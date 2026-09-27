//! Folder snapshots checked against the unprivileged NTFS change journal.
//!
//! The saved tree stays separate from the MFT snapshot. A scan reuses it
//! when the journal names nothing in it since the walk that made it began.

use std::fs::{File, OpenOptions};
use std::hash::{Hash as _, Hasher as _};
use std::os::windows::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use rustc_hash::{FxHashSet, FxHasher};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows_sys::Win32::System::Ioctl::{
    FSCTL_QUERY_USN_JOURNAL, FSCTL_READ_UNPRIVILEGED_USN_JOURNAL,
};

use super::{ScanOptions, WalkContext};
use crate::tree::{Metric, Node, NodeKind};
use crate::windows;

#[path = "walk_cache/store.rs"]
mod store;

const MAX_AGE: u64 = 24 * 60 * 60;
const MAX_CHANGES: usize = 100_000;
const MAX_JOURNAL_BYTES: usize = 64 << 20;

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

    pub(super) fn resume(&self, context: &WalkContext) -> Option<Node> {
        let started = Instant::now();
        let state = store::load(&self.file)?;
        if state.root != self.root.to_str()?
            || state.volume != self.volume
            || state.root_id != self.root_id
            || state.options != self.options
            || !state.tree.is_dir()
            || state.tree.inode != Some((self.volume, self.root_id))
            || !covered(&state, self.journal, self.created)
        {
            return None;
        }
        let changes = changes(&self.handle, self.journal, state.next)?;
        if !untouched(&state.tree, &changes) || context.cancelled() {
            return None;
        }
        trace(&format!("warm total_ms={}", started.elapsed().as_millis()));
        Some(state.tree)
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

const fn covered(state: &store::State, journal: Journal, now: u64) -> bool {
    journal.covers(state.journal, state.next)
        && now >= state.created
        && now - state.created <= MAX_AGE
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

struct Changes {
    files: FxHashSet<u64>,
    parents: FxHashSet<u64>,
}

fn changes(handle: &File, journal: Journal, from: u64) -> Option<Changes> {
    if from < journal.first || from > journal.next {
        return None;
    }
    let mut changes = Changes {
        files: FxHashSet::default(),
        parents: FxHashSet::default(),
    };
    let mut buffer = vec![0; 1 << 20];
    let mut cursor = from;
    let mut bytes = 0;
    while cursor < journal.next {
        let mut input = [0_u8; 40];
        input[..8].copy_from_slice(&cursor.to_le_bytes());
        input[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        input[32..40].copy_from_slice(&journal.id.to_le_bytes());
        let len = windows::control(
            handle,
            FSCTL_READ_UNPRIVILEGED_USN_JOURNAL,
            &input,
            &mut buffer,
        )
        .ok()?;
        bytes += len;
        if bytes > MAX_JOURNAL_BYTES {
            return None;
        }
        let data = buffer.get(..len)?;
        let next = number(data, 0)?;
        if next <= cursor {
            return None;
        }
        parse_changes(data.get(8..)?, cursor, next, &mut changes)?;
        cursor = next;
    }
    let after = query(handle)?;
    if after.id != journal.id || after.first > from || after.next < cursor {
        return None;
    }
    Some(changes)
}

fn parse_changes(
    mut bytes: &[u8],
    from: u64,
    next: u64,
    changes: &mut Changes,
) -> Option<()> {
    let mut last = None;
    while !bytes.is_empty() {
        let length =
            u32::from_le_bytes(bytes.get(..4)?.try_into().ok()?) as usize;
        let version = u16::from_le_bytes(bytes.get(4..6)?.try_into().ok()?);
        if length < 60 || !length.is_multiple_of(8) || version != 2 {
            return None;
        }
        let record = bytes.get(..length)?;
        let usn = number(record, 24)?;
        if usn < from || usn >= next || last.is_some_and(|last| usn <= last) {
            return None;
        }
        last = Some(usn);
        let id = number(record, 8)?;
        let parent = number(record, 16)?;
        changes.files.insert(id);
        changes.parents.insert(parent);
        if changes.files.len() > MAX_CHANGES
            || changes.parents.len() > MAX_CHANGES
        {
            return None;
        }
        bytes = bytes.get(length..)?;
    }
    Some(())
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

/// Whether the journal names nothing in `node`: no folder it lists and no
/// file in it changed, and no listing below it failed.
fn untouched(node: &Node, changes: &Changes) -> bool {
    !node.read_error
        && node.inode.is_none_or(|(_, id)| {
            !changes.files.contains(&id) && !changes.parents.contains(&id)
        })
        && node.children.iter().all(|child| untouched(child, changes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_coverage_refuses_gaps_replacement_and_old_snapshots() {
        let mut state = store::State {
            root: "fixture".into(),
            volume: 1,
            root_id: 2,
            journal: 3,
            next: 100,
            created: 1_000,
            options: 0,
            open: Vec::new(),
            tree: Node::directory("fixture"),
        };
        let journal = Journal {
            id: 3,
            first: 100,
            next: 200,
        };
        assert!(covered(&state, journal, 1_000 + MAX_AGE));
        assert!(!covered(&state, journal, 1_001 + MAX_AGE));
        assert!(!covered(&state, journal, 999));
        assert!(!covered(
            &state,
            Journal {
                first: 101,
                ..journal
            },
            1_001
        ));
        assert!(!covered(&state, Journal { id: 4, ..journal }, 1_001));
        state.next = 201;
        assert!(!covered(&state, journal, 1_001));
    }

    #[test]
    fn journal_records_keep_full_references_and_refuse_a_stalled_cursor() {
        let mut record = [0_u8; 64];
        record[..4].copy_from_slice(&64_u32.to_le_bytes());
        record[4..6].copy_from_slice(&2_u16.to_le_bytes());
        let id = (0x11_u64 << 48) | 0x2a;
        record[8..16].copy_from_slice(&id.to_le_bytes());
        record[16..24].copy_from_slice(&13_u64.to_le_bytes());
        record[24..32].copy_from_slice(&100_u64.to_le_bytes());
        let mut result = Changes {
            files: FxHashSet::default(),
            parents: FxHashSet::default(),
        };
        assert!(parse_changes(&record, 100, 164, &mut result).is_some());
        assert!(result.files.contains(&id));
        assert!(result.parents.contains(&13));
        assert!(parse_changes(&record, 101, 164, &mut result).is_none());
        assert!(parse_changes(&record, 100, 100, &mut result).is_none());
        assert!(parse_changes(&record[..63], 100, 164, &mut result).is_none());
        record[4..6].copy_from_slice(&3_u16.to_le_bytes());
        assert!(parse_changes(&record, 100, 164, &mut result).is_none());
    }
}
