//! Folder walk snapshots for the unprivileged NTFS change journal.
//!
//! The saved tree stays separate from the MFT snapshot, with the journal
//! position its walk started at, so a later scan can tell what changed.

use std::fs::{File, OpenOptions};
use std::hash::{Hash as _, Hasher as _};
use std::os::windows::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use rustc_hash::FxHasher;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows_sys::Win32::System::Ioctl::FSCTL_QUERY_USN_JOURNAL;

use super::{ScanOptions, WalkContext};
use crate::tree::{Metric, Node, NodeKind};
use crate::windows;

#[path = "walk_cache/store.rs"]
mod store;

#[derive(Clone, Copy)]
struct Journal {
    id: u64,
    first: u64,
    next: u64,
}

impl Journal {
    const fn covers(self, id: u64, cursor: u64) -> bool {
        self.id == id && self.first <= cursor && cursor <= self.next
    }
}

pub(super) struct Checkpoint {
    root: PathBuf,
    file: PathBuf,
    handle: File,
    volume: u64,
    root_id: u64,
    journal: Journal,
    created: u64,
    options: u64,
}

impl Checkpoint {
    pub(super) fn open(root: &Path, context: &WalkContext) -> Option<Self> {
        let options = &context.options;
        let cache = options.cache.as_ref()?;
        if options.follow_links
            || !options.one_filesystem
            || options.max_depth.is_some()
            || context.known.is_some()
        {
            return None;
        }
        let volume = windows::walk_volume(root)?;
        let volume_root = windows::volume_root(root)?;
        if !windows::file_table_readable(&volume_root) {
            return None;
        }
        let (device, root_id) = windows::identity(root)?;
        if device != volume {
            return None;
        }
        let handle = OpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
            .open(volume_root)
            .ok()?;
        let journal = query(&handle)?;
        let options = options_key(options);
        let mut hash = FxHasher::default();
        root.hash(&mut hash);
        options.hash(&mut hash);
        Some(Self {
            root: root.to_path_buf(),
            file: cache.join(format!("walk-{:016x}.bin", hash.finish())),
            handle,
            volume,
            root_id,
            journal,
            created: now(),
            options,
        })
    }

    pub(super) fn save(self, tree: Node, context: &WalkContext) -> Node {
        if context.cancelled() || !cacheable(&tree, self.volume, 0) {
            trace("cold unavailable: cancelled or unsupported tree entry");
            return tree;
        }
        let Some(after) = query(&self.handle) else {
            trace("cold unavailable: journal query failed");
            return tree;
        };
        if !after.covers(self.journal.id, self.journal.next) {
            trace("cold unavailable: journal wrapped during walk");
            return tree;
        }
        let Some(root) = self.root.to_str() else {
            return tree;
        };
        let state = store::State {
            root: root.to_owned(),
            volume: self.volume,
            root_id: self.root_id,
            journal: self.journal.id,
            next: self.journal.next,
            created: self.created,
            options: self.options,
            open: Vec::new(),
            tree,
        };
        let result = store::save(&self.file, &state);
        trace(&format!("cold save={result:?}"));
        state.tree
    }
}

const fn options_key(options: &ScanOptions) -> u64 {
    (options.apparent_size as u64)
        | ((options.include_hidden as u64) << 1)
        | ((options.dedup_hardlinks as u64) << 2)
        | ((matches!(options.metric, Metric::Files) as u64) << 3)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn query(handle: &File) -> Option<Journal> {
    let mut output = [0; 80];
    let len =
        windows::control(handle, FSCTL_QUERY_USN_JOURNAL, &[], &mut output)
            .ok()?;
    let data = output.get(..len)?;
    let journal = Journal {
        id: number(data, 0)?,
        first: number(data, 8)?.max(number(data, 24)?),
        next: number(data, 16)?,
    };
    (journal.first <= journal.next).then_some(journal)
}

fn number(bytes: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(at..at + 8)?.try_into().ok()?))
}

fn trace(message: &str) {
    if std::env::var_os("DISKTREE_WALK_TRACE").is_some() {
        eprintln!("walk-cache {message}");
    }
}

fn cacheable(node: &Node, volume: u64, depth: usize) -> bool {
    if depth > 512 {
        trace("cold unavailable: tree exceeds cache depth limit");
        return false;
    }
    if (node.is_dir() || node.kind == NodeKind::File)
        && node
            .inode
            .is_none_or(|(device, id)| device != volume || id == 0)
    {
        if std::env::var_os("DISKTREE_WALK_TRACE").is_some() {
            eprintln!(
                "walk-cache unsupported identity {:?} {:?} {:?} volume={volume}",
                node.name, node.kind, node.inode
            );
        }
        return false;
    }
    node.children
        .iter()
        .all(|child| cacheable(child, volume, depth + 1))
}
