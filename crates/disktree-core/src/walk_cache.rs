//! Folder snapshots validated with the unprivileged NTFS change journal.
//!
//! The saved tree stays separate from the MFT snapshot. A warm scan lists
//! changed parents and every cached alias of a changed file, then settles
//! only those ancestor chains. Keeping the original checkpoint avoids a
//! large cache rewrite on each launch.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::fs::{File, OpenOptions};
use std::hash::{Hash as _, Hasher as _};
use std::os::windows::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use rustc_hash::{FxHashMap, FxHashSet, FxHasher};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_FLAG_BACKUP_SEMANTICS, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE,
};
use windows_sys::Win32::System::Ioctl::{
    FSCTL_QUERY_USN_JOURNAL, FSCTL_READ_UNPRIVILEGED_USN_JOURNAL,
    USN_REASON_CLOSE,
};

use super::{Classified, ScanOptions, WalkContext};
use crate::tree::{Metric, Node, NodeKind, settle_directory, settle_leaf};
use crate::windows;

#[path = "walk_cache/store.rs"]
mod store;

const MAX_AGE: u64 = 24 * 60 * 60;
const MAX_CHANGES: usize = 100_000;
const MAX_DIRECTORIES: usize = 10_000;
const MAX_JOURNAL_BYTES: usize = 64 << 20;

// ponytail: this bounds the blind spot without opening millions of files.
// A writer predating the retained journal can still be missed when its
// cached size is below this set; close or the 24-hour full walk repairs it.
const LARGEST_FILES: usize = 1024;
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
            file: windows::cache_path(
                cache,
                &format!("walk-{:016x}.bin", hash.finish()),
            ),
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
        let mut state = store::load(&self.file)?;
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
        let loaded = started.elapsed();
        let changes = changes(&self.handle, self.journal, state.next)?;
        let mut changed: FxHashSet<u64> =
            changes.files.keys().copied().collect();
        changed.extend(state.open.iter().copied());
        let open = state
            .open
            .iter()
            .copied()
            .filter(|id| changes.files.get(id).is_none_or(|closed| !closed))
            .chain(
                changes
                    .files
                    .iter()
                    .filter_map(|(&id, &closed)| (!closed).then_some(id)),
            )
            .collect();
        if changed.len() > MAX_CHANGES {
            return None;
        }
        let mut update = Update {
            context,
            changed,
            parents: changes.parents,
            refreshed: FxHashSet::default(),
            touched: FxHashSet::default(),
            listed: 0,
        };
        let mut chains = FxHashSet::default();
        let mut pending = FxHashSet::default();
        loop {
            chains.clear();
            pending.clear();
            update.mark(&state.tree, &mut pending, &mut chains)?;
            if pending.is_empty() {
                break;
            }
            if update.refreshed.len() + pending.len() > MAX_DIRECTORIES {
                return None;
            }
            update.refresh(
                &mut state.tree,
                &self.root,
                &pending,
                &chains,
                0,
            )?;
            if context.cancelled() || update.touched.len() > MAX_CHANGES {
                return None;
            }
        }
        let mut seen = FxHashSet::default();
        update.settle(&mut state.tree, &mut seen);
        let (current, current_changed) =
            update.refresh_current(&mut state.tree, &self.root, open)?;
        if !update.refreshed.is_empty() || current_changed {
            // Classification can depend on sibling names and the dominant
            // top-level child. Reuse that policy rather than approximate it.
            crate::classify::classify(&mut state.tree);
        }
        let after = query(&self.handle)?;
        if !covered(&state, after, now()) || after.next < self.journal.next {
            return None;
        }
        if context.cancelled() {
            return None;
        }
        if std::env::var_os("DISKTREE_WALK_TRACE").is_some() {
            eprintln!(
                "walk-cache warm load_ms={} total_ms={} relisted={} refreshed_files={} current_files={}",
                loaded.as_millis(),
                started.elapsed().as_millis(),
                update.refreshed.len(),
                update.touched.len(),
                current,
            );
        }
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
        // Only the walk's starting cursor must remain covered; expiry of
        // older history does not lose a change made during this walk. Seed
        // known writers from the history retained now, not an expired start.
        let Some(changes) = changes(&self.handle, after, after.first) else {
            trace("cold unavailable: retained journal unreadable or too large");
            return tree;
        };
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
            open: changes
                .files
                .into_iter()
                .filter_map(|(id, closed)| (!closed).then_some(id))
                .collect(),
            tree,
        };
        let result = store::save(&self.file, &state);
        if std::env::var_os("DISKTREE_WALK_TRACE").is_some() {
            eprintln!(
                "walk-cache cold save={result:?} open={}",
                state.open.len()
            );
        }
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
    files: FxHashMap<u64, bool>,
    parents: FxHashSet<u64>,
}

fn changes(handle: &File, journal: Journal, from: u64) -> Option<Changes> {
    if from < journal.first || from > journal.next {
        return None;
    }
    let mut changes = Changes {
        files: FxHashMap::default(),
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
        let reason = u32::from_le_bytes(record.get(40..44)?.try_into().ok()?);
        changes.files.insert(id, reason & USN_REASON_CLOSE != 0);
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

struct CurrentFile {
    bytes: u64,
    modified: i64,
    charged: bool,
}

fn largest_files(node: &Node, largest: &mut BinaryHeap<Reverse<(u64, u64)>>) {
    if node.kind == NodeKind::File
        && let Some((_, id)) = node.inode
    {
        let candidate = Reverse((node.bytes, id));
        if largest.len() < LARGEST_FILES {
            largest.push(candidate);
        } else if let Some(mut smallest) = largest.peek_mut()
            && candidate < *smallest
        {
            *smallest = candidate;
        }
    }
    for child in &node.children {
        largest_files(child, largest);
    }
}

fn mark_current(
    node: &Node,
    current: &FxHashMap<u64, Option<CurrentFile>>,
    chains: &mut FxHashSet<u64>,
) -> Option<bool> {
    if !node.is_dir() {
        return Some(
            node.kind == NodeKind::File
                && node.inode.is_some_and(|(_, id)| current.contains_key(&id)),
        );
    }
    let mut needed = false;
    for child in &node.children {
        needed |= mark_current(child, current, chains)?;
    }
    if needed {
        chains.insert(node.inode?.1);
    }
    Some(needed)
}

struct Update<'a> {
    context: &'a WalkContext,
    changed: FxHashSet<u64>,
    parents: FxHashSet<u64>,
    refreshed: FxHashSet<u64>,
    touched: FxHashSet<u64>,
    listed: usize,
}

impl Update<'_> {
    fn mark(
        &self,
        node: &Node,
        pending: &mut FxHashSet<u64>,
        chains: &mut FxHashSet<u64>,
    ) -> Option<bool> {
        let (_, id) = node.inode?;
        let mut dirty = !self.refreshed.contains(&id)
            && (node.read_error
                || self.parents.contains(&id)
                || self.changed.contains(&id));
        let mut below = false;
        for child in &node.children {
            if child.is_dir() {
                below |= self.mark(child, pending, chains)?;
            } else if !self.refreshed.contains(&id)
                && child.inode.is_some_and(|(_, file)| {
                    self.changed.contains(&file) || self.touched.contains(&file)
                })
            {
                dirty = true;
            }
        }
        if dirty {
            pending.insert(id);
        }
        if dirty || below {
            chains.insert(id);
        }
        Some(dirty || below)
    }

    fn refresh(
        &mut self,
        node: &mut Node,
        path: &Path,
        pending: &FxHashSet<u64>,
        chains: &FxHashSet<u64>,
        depth: usize,
    ) -> Option<()> {
        let key = node.inode?;
        if !chains.contains(&key.1) {
            return Some(());
        }
        if pending.contains(&key.1) && !self.refreshed.contains(&key.1) {
            self.relist(node, path, depth)?;
        }
        for child in &mut node.children {
            if child.is_dir()
                && child.inode.is_some_and(|(_, id)| chains.contains(&id))
            {
                let path = self.child_path(path, child)?;
                self.refresh(child, &path, pending, chains, depth + 1)?;
            }
        }
        Some(())
    }

    fn relist(
        &mut self,
        node: &mut Node,
        path: &Path,
        depth: usize,
    ) -> Option<()> {
        if depth > 512
            || self.context.cancelled()
            || self.refreshed.len() >= MAX_DIRECTORIES
        {
            return None;
        }
        let key = node.inode?;
        self.refreshed.insert(key.1);
        let mut old = FxHashMap::default();
        for child in std::mem::take(&mut node.children) {
            if child.is_dir() {
                old.insert(child.inode, child);
            } else if let Some((_, id)) = child.inode {
                self.touched.insert(id);
            }
        }
        node.read_error = false;
        match super::list(path, self.context.volume.get().copied()) {
            Ok(entries) => {
                if entries.identity()? != key {
                    return None;
                }
                for entry in entries {
                    self.listed += 1;
                    if self.listed > MAX_CHANGES || self.context.cancelled() {
                        return None;
                    }
                    let mut entry = entry.ok()?;
                    match self.context.classify(path, &mut entry) {
                        Classified::Subdirectory { path, name, inode } => {
                            let child =
                                if let Some(mut child) = old.remove(&inode) {
                                    child.name = name;
                                    child
                                } else {
                                    let mut child = Node::directory(name);
                                    child.inode = inode;
                                    // New trees share cancellation, policy and limits
                                    // with this refresh, rather than start another scan.
                                    self.relist(&mut child, &path, depth + 1)?;
                                    child
                                };
                            node.children.push(child);
                        }
                        Classified::Entry(child) => {
                            if let Some((_, id)) = child.inode {
                                self.touched.insert(id);
                            }
                            node.children.push(child);
                        }
                        Classified::Skipped => {}
                        Classified::Unreadable => node.read_error = true,
                    }
                }
            }
            Err(error) => {
                node.read_error = true;
                self.context.progress.record_error(path, &error);
            }
        }
        // Removing the charged name must refresh every remaining alias.
        for removed in old.values() {
            self.touch_removed(removed)?;
        }
        Some(())
    }

    fn child_path(&self, parent: &Path, child: &Node) -> Option<PathBuf> {
        if !child.name.contains('\u{fffd}') {
            return Some(parent.join(&*child.name));
        }
        // Display names lose unpaired UTF-16 surrogates. Recover the native
        // name by identity only when a changed chain must enter that folder.
        super::list(parent, self.context.volume.get().copied())
            .ok()?
            .filter_map(Result::ok)
            .find(|entry| entry.identity() == child.inode)
            .map(|entry| entry.path(parent))
    }

    fn touch_removed(&mut self, node: &Node) -> Option<()> {
        if node.is_dir() {
            for child in &node.children {
                self.touch_removed(child)?;
            }
        } else if let Some((_, id)) = node.inode {
            self.touched.insert(id);
            if self.touched.len() > MAX_CHANGES {
                return None;
            }
        }
        Some(())
    }

    fn refresh_current(
        &self,
        tree: &mut Node,
        root: &Path,
        open: FxHashSet<u64>,
    ) -> Option<(usize, bool)> {
        let mut largest = BinaryHeap::with_capacity(LARGEST_FILES);
        largest_files(tree, &mut largest);
        let mut current: FxHashMap<u64, Option<CurrentFile>> = open
            .into_iter()
            .chain(largest.into_iter().map(|Reverse((_, id))| id))
            .map(|id| (id, None))
            .collect();
        let mut chains = FxHashSet::default();
        mark_current(tree, &current, &mut chains)?;
        let changed =
            self.measure_current(tree, root, &mut current, &chains)?;
        Some((
            current.values().filter(|value| value.is_some()).count(),
            changed,
        ))
    }

    fn measure_current(
        &self,
        node: &mut Node,
        path: &Path,
        current: &mut FxHashMap<u64, Option<CurrentFile>>,
        chains: &FxHashSet<u64>,
    ) -> Option<bool> {
        if !chains.contains(&node.inode?.1) {
            return Some(false);
        }

        let mut changed = false;
        for child in &mut node.children {
            if self.context.cancelled() {
                return None;
            }
            if child.is_dir() {
                if child.inode.is_some_and(|(_, id)| chains.contains(&id)) {
                    let path = self.child_path(path, child)?;
                    changed |=
                        self.measure_current(child, &path, current, chains)?;
                }
            } else if child.kind == NodeKind::File
                && let Some(key) = child.inode
                && let Some(value) = current.get_mut(&key.1)
            {
                if value.is_none() {
                    let native = self.child_path(path, child)?;
                    let (bytes, modified) = windows::current_file(
                        &native,
                        key,
                        self.context.options.apparent_size,
                    )
                    .or_else(|| {
                        // A file may refuse opens while its parent still
                        // reports the same facts a full walk would read.
                        super::list(path, self.context.volume.get().copied())
                            .ok()?
                            .filter_map(Result::ok)
                            .find(|entry| entry.identity() == Some(key))
                            .map(|entry| {
                                (
                                    if self.context.options.apparent_size {
                                        entry.apparent()
                                    } else {
                                        entry.allocated()
                                    },
                                    entry.modified(),
                                )
                            })
                    })?;
                    *value = Some(CurrentFile {
                        bytes,
                        modified,
                        charged: false,
                    });
                }
                let value = value.as_mut()?;
                let bytes =
                    if self.context.options.dedup_hardlinks && value.charged {
                        0
                    } else {
                        value.bytes
                    };
                value.charged = true;
                changed |= child.own_bytes != bytes
                    || child.modified != value.modified;
                child.own_bytes = bytes;
                child.modified = value.modified;
                settle_leaf(child, None);
            }
        }
        if changed {
            settle_directory(node, self.context.options.metric);
        }
        Some(changed)
    }

    fn settle(&self, node: &mut Node, seen: &mut FxHashSet<u64>) -> bool {
        let mut dirty = node
            .inode
            .is_some_and(|(_, id)| self.refreshed.contains(&id));
        for child in &mut node.children {
            if child.is_dir() {
                dirty |= self.settle(child, seen);
            } else if let Some((_, id)) = child.inode
                && self.touched.contains(&id)
            {
                if self.context.options.dedup_hardlinks && !seen.insert(id) {
                    child.own_bytes = 0;
                }
                settle_leaf(child, None);
            }
        }
        if dirty {
            settle_directory(node, self.context.options.metric);
        }
        dirty
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_refresh_selects_the_largest_files_without_directories() {
        let mut root = Node::directory("root");
        root.inode = Some((1, 9_999));
        for size in 1..=2_048 {
            let mut node = Node::entry(format!("{size}"), NodeKind::File, size);
            node.inode = Some((1, size));
            root.children.push(node);
        }
        crate::tree::aggregate(&mut root, Metric::Bytes);
        let mut largest = BinaryHeap::new();
        largest_files(&root, &mut largest);
        let mut sizes: Vec<_> =
            largest.into_iter().map(|Reverse((size, _))| size).collect();
        sizes.sort_unstable();
        assert_eq!(sizes.len(), 1_024);
        assert_eq!(sizes.first(), Some(&1_025));
        assert_eq!(sizes.last(), Some(&2_048));
    }

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
        record[40..44].copy_from_slice(&USN_REASON_CLOSE.to_le_bytes());
        let mut result = Changes {
            files: FxHashMap::default(),
            parents: FxHashSet::default(),
        };
        assert!(parse_changes(&record, 100, 164, &mut result).is_some());
        assert_eq!(result.files.get(&id), Some(&true));
        assert!(result.parents.contains(&13));
        assert!(parse_changes(&record, 101, 164, &mut result).is_none());
        assert!(parse_changes(&record, 100, 100, &mut result).is_none());
        assert!(parse_changes(&record[..63], 100, 164, &mut result).is_none());
        record[4..6].copy_from_slice(&3_u16.to_le_bytes());
        assert!(parse_changes(&record, 100, 164, &mut result).is_none());
    }
}
