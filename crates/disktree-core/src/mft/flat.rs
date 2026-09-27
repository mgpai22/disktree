//! The finished tree as flat arrays: what a read of the file table shows,
//! totalled, ordered and classified, in a form that is cheap to keep on
//! disk, to change in place and to turn into [`Node`]s.
//!
//! Every directory is a [`Dir`] and its entries a run of [`Item`]s, in the
//! order the tree shows them; names sit in one arena. The next scan loads
//! it, replaces the entries of the files the change journal names, totals
//! and orders again only the directories that hold a change and those
//! above them, and decides kinds again only where a change can reach: a
//! journal of a few thousand changes costs thousands of steps, not the
//! millions a tree built from the table again would.
//!
//! A kept tree holds only what it shows, so a directory that comes into
//! view with entries it never held (a cloud folder made local, a folder
//! moved in from a hidden one) cannot be brought up to date from it: the
//! table is read whole instead. One made since the tree was is fine, as
//! every entry it has was made or moved in since too, and the journal
//! names each.

use std::sync::atomic::{AtomicBool, Ordering};

use rayon::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_REPARSE_POINT,
};

use super::{
    EVICTED, Entry, FIRST_USER_RECORD, Info, MOST_LEVELS, NAME_SURROGATE, ROOT,
    Stop, Table,
};
use crate::classify::{
    Category, GIT_STORE, Reclaim, category_of_name, directory_kind,
    top_level_kind,
};
use crate::scan::{ScanOptions, ScanProgress};
use crate::tree::{Metric, Node, NodeKind};

/// No directory: the root's parent, and a directory dropped from the tree.
pub(super) const NONE: u32 = u32::MAX;

/// What an [`Item`] is.
pub(super) const FILE: u8 = 0;
pub(super) const LINK: u8 = 1;
pub(super) const DIRECTORY: u8 = 2;

/// A kind not decided yet: every directory of a tree just built, and one
/// a change brought in.
const UNSET: u8 = u8::MAX;

/// A directory's [`Category`] and [`Reclaim`], by number: see [`code`].
type Kind = (u8, u8);

/// A directory of the tree.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Dir {
    /// Its file record, and the sequence number its entries' references
    /// to it carry.
    pub record: u32,
    pub sequence: u16,
    /// Its entries: `items[first..first + len]`, in the order shown.
    pub first: u32,
    pub len: u32,
    /// The directory holding it; [`NONE`] for the root and for one
    /// dropped from the tree, whose `record` is [`NONE`] too.
    pub parent: u32,
    pub category: u8,
    pub reclaim: u8,
    /// Totals as its node has them.
    pub bytes: u64,
    pub files: u64,
    pub dirs: u64,
    pub modified: i64,
}

impl Dir {
    const fn new(record: u32, sequence: u16) -> Self {
        Self {
            record,
            sequence,
            first: 0,
            len: 0,
            parent: NONE,
            category: UNSET,
            reclaim: UNSET,
            bytes: 0,
            files: 0,
            dirs: 1,
            modified: 0,
        }
    }

    const fn is_live(&self) -> bool {
        self.record != NONE
    }

    /// Add an entry's totals: see [`Flat::totals`].
    fn add(&mut self, (bytes, files, dirs, modified): (u64, u64, u64, i64)) {
        // Saturating: a corrupt volume's file table can claim any size.
        self.bytes = self.bytes.saturating_add(bytes);
        self.files = self.files.saturating_add(files);
        self.dirs = self.dirs.saturating_add(dirs);
        self.modified = self.modified.max(modified);
    }

    /// What this directory weighs in its parent's order.
    const fn key(&self, metric: Metric) -> u64 {
        match metric {
            Metric::Bytes => self.bytes,
            Metric::Files => self.files,
        }
    }
}

/// One entry of a directory.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Item {
    /// Its file record, and the record's sequence number.
    pub record: u32,
    pub sequence: u16,
    /// Its name: `len` bytes at `at` in the arena.
    pub at: u32,
    pub len: u16,
    pub kind: u8,
    /// The file has more than one name: its node carries its identity,
    /// and with hardlinks counted once only one of its names weighs.
    pub shared: bool,
    /// A file's size as charged; a directory's index among the dirs.
    pub value: u64,
    /// A file's last write, in Unix seconds.
    pub modified: i64,
}

impl Item {
    /// What a file or link weighs in its parent's order.
    fn key(&self, metric: Metric) -> u64 {
        match metric {
            Metric::Bytes => self.value,
            Metric::Files => u64::from(self.kind == FILE),
        }
    }

    /// A file's or link's totals as [`Dir::add`] takes them.
    fn totals(&self) -> (u64, u64, u64, i64) {
        (self.value, u64::from(self.kind == FILE), 0, self.modified)
    }
}

/// The tree: `dirs[0]` is the root.
#[derive(Debug, Default)]
pub(super) struct Flat {
    pub dirs: Vec<Dir>,
    pub items: Vec<Item>,
    /// Names, as UTF-8.
    pub text: Vec<u8>,
}

/// A file record as NTFS holds it now.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) struct Fresh {
    pub info: Info,
    /// Every name: `(parent, parent's sequence number, name)`.
    pub names: Vec<(u32, u16, String)>,
}

/// Whether a scan with `options` leaves the name out, as the walk does.
fn hidden(options: &ScanOptions, name: &str, info: &Info) -> bool {
    !options.include_hidden
        && (name.starts_with('.')
            || info.attributes & FILE_ATTRIBUTE_HIDDEN != 0)
}

/// Links, junctions and mounted folders: shown as links, not followed.
const fn is_link(info: &Info) -> bool {
    info.attributes & FILE_ATTRIBUTE_REPARSE_POINT != 0
        && info.reparse_tag & NAME_SURROGATE != 0
}

fn code(category: Category, reclaim: Option<Reclaim>) -> Kind {
    let category = Category::LEGEND
        .iter()
        .position(|&known| known == category)
        .unwrap_or(Category::LEGEND.len());
    let reclaim = reclaim
        .and_then(|reclaim| Reclaim::ALL.iter().position(|&r| r == reclaim))
        .map_or(0, |index| index + 1);
    (category as u8, reclaim as u8)
}

fn decode((category, reclaim): Kind) -> (Category, Option<Reclaim>) {
    let category = Category::LEGEND
        .get(usize::from(category))
        .copied()
        .unwrap_or(Category::Other);
    let reclaim = reclaim
        .checked_sub(1)
        .and_then(|index| Reclaim::ALL.get(usize::from(index)).copied());
    (category, reclaim)
}

/// Largest first, then by name: `tree::settle_directory`'s order.
fn order(
    (left_key, left_name): (u64, &[u8]),
    (right_key, right_name): (u64, &[u8]),
) -> std::cmp::Ordering {
    right_key
        .cmp(&left_key)
        .then_with(|| left_name.cmp(right_name))
}

fn name_of<'a>(text: &'a [u8], item: &Item) -> &'a [u8] {
    text.get(item.at as usize..)
        .and_then(|rest| rest.get(..usize::from(item.len)))
        .unwrap_or_default()
}

/// Put `name` in the arena as `item`'s.
fn name_into(
    text: &mut Vec<u8>,
    item: &mut Item,
    name: &str,
) -> Result<(), Stop> {
    item.at = u32::try_from(text.len()).map_err(|_| Stop)?;
    item.len = u16::try_from(name.len()).map_err(|_| Stop)?;
    text.extend_from_slice(name.as_bytes());
    Ok(())
}

impl Flat {
    fn run(&self, dir: Dir) -> &[Item] {
        self.items
            .get(dir.first as usize..)
            .and_then(|rest| rest.get(..dir.len as usize))
            .unwrap_or_default()
    }

    fn name(&self, item: &Item) -> &str {
        std::str::from_utf8(name_of(&self.text, item)).unwrap_or_default()
    }

    fn dir(&self, index: u64) -> Option<Dir> {
        self.dirs.get(usize::try_from(index).ok()?).copied()
    }

    /// An entry's totals as [`Dir::add`] takes them.
    fn totals(&self, item: &Item) -> (u64, u64, u64, i64) {
        if item.kind != DIRECTORY {
            return item.totals();
        }
        self.dir(item.value).map_or((0, 0, 0, 0), |dir| {
            (dir.bytes, dir.files, dir.dirs, dir.modified)
        })
    }

    fn has(&self, run: &[Item], wanted: &str) -> bool {
        run.iter()
            .any(|item| name_of(&self.text, item) == wanted.as_bytes())
    }

    /// See `classify::is_git_store`.
    fn is_git_store(&self, index: u64) -> bool {
        self.dir(index).is_some_and(|dir| {
            let run = self.run(dir);
            GIT_STORE.iter().all(|wanted| self.has(run, wanted))
        })
    }

    /// See `classify::dominant_child_category`.
    fn dominant(&self, index: u64) -> Option<Category> {
        let mut dir = self.dir(index)?;
        for _ in 0..3 {
            let run = self.run(dir);
            let mut subdirectories =
                run.iter().filter(|item| item.kind == DIRECTORY);
            if let Some(category) = subdirectories.clone().find_map(|item| {
                category_of_name(self.name(item)).or_else(|| {
                    self.is_git_store(item.value).then_some(Category::Git)
                })
            }) {
                return Some(category);
            }
            dir = self.dir(subdirectories.next()?.value)?;
        }
        None
    }

    /// The tree as nodes, the root named `name`.
    pub(super) fn tree(
        &self,
        name: Box<str>,
        progress: &ScanProgress,
    ) -> Result<Node, Stop> {
        let stopped = AtomicBool::new(false);
        let root = self.node(0, name, 0, progress, &stopped);
        if stopped.load(Ordering::Relaxed) || progress.is_cancelled() {
            return Err(Stop);
        }
        Ok(root)
    }

    /// Directory `index` as a node, and all beneath it. A cancel, or a
    /// tree deeper than [`MOST_LEVELS`], sets `stopped` and cuts it short.
    fn node(
        &self,
        index: u64,
        name: Box<str>,
        depth: usize,
        progress: &ScanProgress,
        stopped: &AtomicBool,
    ) -> Node {
        let mut node = Node::directory(name);
        let dir = match self.dir(index) {
            Some(dir)
                if depth < MOST_LEVELS
                    && !progress.is_cancelled()
                    && !stopped.load(Ordering::Relaxed) =>
            {
                dir
            }
            _ => {
                stopped.store(true, Ordering::Relaxed);
                return node;
            }
        };
        let (category, reclaim) = decode((dir.category, dir.reclaim));
        let child = |item: &Item| {
            let name = self.name(item);
            if item.kind == DIRECTORY {
                let name = name.into();
                return self.node(
                    item.value,
                    name,
                    depth + 1,
                    progress,
                    stopped,
                );
            }
            // A file beneath the root is what its name says; deeper, it
            // is what holds it: see `classify::classify`.
            let (category, reclaim) = if depth == 0 {
                top_level_kind(name, false, || false, || None, |_| false)
            } else {
                (category, reclaim)
            };
            let kind = if item.kind == LINK {
                NodeKind::Symlink
            } else {
                NodeKind::File
            };
            let files = u64::from(kind == NodeKind::File);
            Node {
                name: name.into(),
                kind,
                bytes: item.value,
                own_bytes: item.value,
                files,
                own_files: files,
                dirs: 0,
                inode: item.shared.then_some((0, u64::from(item.record))),
                read_error: false,
                modified: item.modified,
                category,
                reclaim,
                children: Vec::new(),
            }
        };
        let run = self.run(dir);
        node.children.reserve_exact(run.len());
        node.children.extend(run.iter().map(child));
        for child in node.children.iter().filter(|child| !child.is_dir()) {
            node.own_bytes = node.own_bytes.saturating_add(child.bytes);
            node.own_files = node.own_files.saturating_add(child.files);
        }
        Node {
            bytes: dir.bytes,
            files: dir.files,
            dirs: dir.dirs,
            modified: dir.modified,
            category,
            reclaim,
            ..node
        }
    }

    /// Decide what directories are, as `classify::classify` would: every
    /// one in a tree just built, whose kinds are all unset; afterwards
    /// only where a change can reach. That is a directory `touched` marks
    /// (its entries changed, or some beneath it did), whose entries' kinds
    /// may follow their new siblings, and every directory whose kind came
    /// out other than before, whose entries inherit it. Beneath any other,
    /// nothing the kinds depend on changed. The root's entries are always
    /// decided again: one takes the kind of its largest child, and sizes
    /// anywhere beneath can change which that is.
    pub(super) fn classify(&mut self, touched: &[bool]) {
        let Some(&root) = self.dirs.first() else {
            return;
        };
        let run = self.run(root);
        let mut kinds: Vec<(u64, Kind)> = run
            .par_iter()
            .filter(|item| item.kind == DIRECTORY)
            .flat_map_iter(|item| {
                let (category, reclaim) = top_level_kind(
                    self.name(item),
                    true,
                    || self.is_git_store(item.value),
                    || self.dominant(item.value),
                    |wanted| self.has(run, wanted),
                );
                let mut kinds = Vec::new();
                self.kinds(
                    item.value,
                    code(category, reclaim),
                    touched,
                    1,
                    &mut kinds,
                );
                kinds
            })
            .collect();
        kinds.push((0, code(Category::Other, None)));
        for (index, (category, reclaim)) in kinds {
            if let Some(dir) = usize::try_from(index)
                .ok()
                .and_then(|index| self.dirs.get_mut(index))
            {
                dir.category = category;
                dir.reclaim = reclaim;
            }
        }
    }

    /// Directory `index` is of `kind` now: note it in `out` if that is new,
    /// and go on beneath it where [`Flat::classify`] says to.
    fn kinds(
        &self,
        index: u64,
        kind: Kind,
        touched: &[bool],
        depth: usize,
        out: &mut Vec<(u64, Kind)>,
    ) {
        let Some(dir) = self.dir(index) else {
            return;
        };
        let changed = (dir.category, dir.reclaim) != kind;
        if changed {
            out.push((index, kind));
        }
        let here = usize::try_from(index)
            .ok()
            .and_then(|index| touched.get(index))
            .copied()
            .unwrap_or(false);
        if !changed && !here || depth >= MOST_LEVELS {
            return;
        }
        let (category, reclaim) = decode(kind);
        let run = self.run(dir);
        let child = |item: &Item, out: &mut Vec<(u64, Kind)>| {
            if item.kind != DIRECTORY {
                return;
            }
            let (category, reclaim) = directory_kind(
                self.name(item),
                || self.is_git_store(item.value),
                |wanted| self.has(run, wanted),
                category,
                reclaim,
            );
            self.kinds(
                item.value,
                code(category, reclaim),
                touched,
                depth + 1,
                out,
            );
        };
        for item in run {
            child(item, out);
        }
    }

    /// Bring the tree up to date: `numbers` are the records that changed,
    /// sorted, and `fresh` what those still in use hold now. `created`
    /// tells a record made since the tree was. Totals and order come up to
    /// date too; kinds are left to [`Flat::classify`], given what this
    /// returns: the directories whose entries changed and every one above
    /// them. `None` when the tree cannot be brought up to date from what
    /// it holds: a directory came into view whose entries it never held,
    /// a directory has two names, or the changes do not make a tree.
    pub(super) fn patch(
        &mut self,
        numbers: &[u32],
        fresh: &FxHashMap<u32, Fresh>,
        created: impl Fn(u32) -> bool,
        options: &ScanOptions,
    ) -> Option<Vec<bool>> {
        // The root and the file system's own records are never entries.
        let numbers: Vec<u32> = numbers
            .iter()
            .copied()
            .filter(|&number| number >= FIRST_USER_RECORD)
            .collect();
        let changed = Bits::of(&numbers);
        let parents: FxHashSet<u32> = numbers
            .iter()
            .filter_map(|number| fresh.get(number))
            .flat_map(|fresh| fresh.names.iter().map(|&(parent, ..)| parent))
            .collect();

        // The directory each changed record, and each parent a name
        // names, was.
        let found: Vec<(u32, u32)> = self
            .dirs
            .par_iter()
            .enumerate()
            .filter(|(_, dir)| {
                dir.is_live()
                    && (changed.has(dir.record)
                        || parents.contains(&dir.record))
            })
            .map(|(index, dir)| (dir.record, index as u32))
            .collect();
        let mut dir_of = FxHashMap::default();
        for (record, index) in found {
            if dir_of.insert(record, index).is_some() {
                return None;
            }
        }

        // The entries changed records had, by where they are.
        let old: Vec<(u32, u32)> = self
            .dirs
            .par_iter()
            .enumerate()
            .filter(|(_, dir)| dir.is_live())
            .flat_map_iter(|(index, dir)| {
                let first = dir.first;
                self.run(*dir)
                    .iter()
                    .enumerate()
                    .filter(|(_, item)| changed.has(item.record))
                    .map(move |(at, _)| (index as u32, first + at as u32))
            })
            .collect();
        let mut dirty: FxHashSet<u32> =
            old.iter().map(|&(dir, _)| dir).collect();
        let removed: FxHashSet<u32> = old.iter().map(|&(_, at)| at).collect();

        // A changed record that is a shown directory now keeps its place
        // in `dirs` if it had one at the same sequence number, and gets a
        // new one if it was made since the tree was.
        let mut placed: FxHashMap<u32, u32> = FxHashMap::default();
        let mut unknown = FxHashSet::default();
        for &number in &numbers {
            let Some(Fresh { info, .. }) = fresh.get(&number) else {
                continue;
            };
            if !info.in_use
                || !info.directory
                || is_link(info)
                || info.attributes & EVICTED != 0
            {
                continue;
            }
            match dir_of.get(&number) {
                Some(&index)
                    if self.dirs[index as usize].sequence == info.sequence =>
                {
                    placed.insert(number, index);
                }
                _ if created(number) => {
                    let index = u32::try_from(self.dirs.len()).ok()?;
                    self.dirs.push(Dir::new(number, info.sequence));
                    placed.insert(number, index);
                    dirty.insert(index);
                }
                _ => {
                    unknown.insert(number);
                }
            }
        }

        // The entries changed records have now, as the build makes them.
        let mut added: FxHashMap<u32, Vec<Item>> = FxHashMap::default();
        let mut attached = FxHashSet::default();
        for &number in &numbers {
            let Some(Fresh { info, names }) = fresh.get(&number) else {
                continue;
            };
            let directory = info.directory && !is_link(info);
            if !info.in_use || directory && info.attributes & EVICTED != 0 {
                continue;
            }
            let mut charged = false;
            for (parent, parent_sequence, name) in names {
                if *parent == number || hidden(options, name, info) {
                    continue;
                }
                let holder = if changed.has(*parent) {
                    placed.get(parent)
                } else {
                    dir_of.get(parent)
                };
                let Some(&holder) = holder else {
                    continue;
                };
                if self.dirs[holder as usize].sequence != *parent_sequence {
                    continue;
                }
                let mut item = if directory {
                    let Some(&child) = placed.get(&number) else {
                        if unknown.contains(&number) {
                            return None;
                        }
                        continue;
                    };
                    if !attached.insert(child) {
                        return None;
                    }
                    self.dirs[child as usize].parent = holder;
                    Item {
                        record: number,
                        sequence: info.sequence,
                        kind: DIRECTORY,
                        value: u64::from(child),
                        ..Item::default()
                    }
                } else {
                    let mut size = if options.apparent_size {
                        info.apparent
                    } else {
                        info.allocated
                    };
                    let shared = info.names > 1;
                    // One of a hardlinked file's names weighs, as the
                    // build charges the first it meets.
                    if options.dedup_hardlinks && shared && size > 0 {
                        if charged {
                            size = 0;
                        }
                        charged = true;
                    }
                    Item {
                        record: number,
                        sequence: info.sequence,
                        kind: if is_link(info) { LINK } else { FILE },
                        shared,
                        value: size,
                        modified: info.modified,
                        ..Item::default()
                    }
                };
                name_into(&mut self.text, &mut item, name).ok()?;
                added.entry(holder).or_default().push(item);
                dirty.insert(holder);
            }
        }

        // A changed record's directory with no place now went, or left the
        // view, with everything that stayed beneath it.
        let gone: Vec<u32> = dir_of
            .iter()
            .filter(|&(&record, index)| {
                changed.has(record) && !attached.contains(index)
            })
            .map(|(_, &index)| index)
            .chain(
                placed
                    .values()
                    .copied()
                    .filter(|index| !attached.contains(index)),
            )
            .collect();
        for index in gone {
            self.drop_beneath(index, &removed);
        }

        // Each changed directory's entries again, as a run of their own
        // after the others: what it kept, then what it gained.
        let mut dirty: Vec<u32> = dirty
            .into_iter()
            .filter(|&index| {
                self.dirs.get(index as usize).is_some_and(Dir::is_live)
            })
            .collect();
        dirty.sort_unstable();
        for &index in &dirty {
            let dir = self.dirs[index as usize];
            let first = u32::try_from(self.items.len()).ok()?;
            for at in dir.first..dir.first.saturating_add(dir.len) {
                if !removed.contains(&at)
                    && let Some(&item) = self.items.get(at as usize)
                {
                    self.items.push(item);
                }
            }
            self.items.extend(added.remove(&index).unwrap_or_default());
            let len = u32::try_from(self.items.len()).ok()? - first;
            let dir = &mut self.dirs[index as usize];
            dir.first = first;
            dir.len = len;
        }

        // Every directory given a place must hang from the root.
        for &index in &attached {
            let mut at = index;
            let mut steps = 0;
            while at != 0 {
                let dir = self.dirs.get(at as usize)?;
                if !dir.is_live() || steps > MOST_LEVELS {
                    return None;
                }
                at = dir.parent;
                steps += 1;
            }
        }

        // Totals and order again for each changed directory and those
        // above it, deepest first, so each totals children already done.
        let mut touched = vec![false; self.dirs.len()];
        let mut chain = Vec::new();
        for &index in &dirty {
            let mut at = index;
            while let Some(flag) = touched.get_mut(at as usize)
                && !*flag
            {
                *flag = true;
                chain.push(at);
                at = self.dirs[at as usize].parent;
            }
        }
        let depth = |mut at: u32| {
            let mut depth = 0;
            while let Some(dir) = self.dirs.get(at as usize)
                && depth <= MOST_LEVELS
            {
                at = dir.parent;
                depth += 1;
            }
            depth
        };
        let mut chain: Vec<(usize, u32)> = chain
            .into_iter()
            .map(|index| (depth(index), index))
            .collect();
        chain.sort_unstable_by(|left, right| right.cmp(left));
        for (_, index) in chain {
            self.settle(index, options.metric);
        }
        Some(touched)
    }

    /// Drop directory `index` and everything beneath it that stayed
    /// there: an entry in `removed` has another place now, or none.
    fn drop_beneath(&mut self, index: u32, removed: &FxHashSet<u32>) {
        let mut stack = vec![index];
        while let Some(index) = stack.pop() {
            let Some(dir) = self.dirs.get_mut(index as usize) else {
                continue;
            };
            if !dir.is_live() {
                continue;
            }
            let (first, len) = (dir.first, dir.len);
            *dir = Dir {
                record: NONE,
                parent: NONE,
                len: 0,
                ..*dir
            };
            for at in first..first.saturating_add(len) {
                if let Some(item) = self.items.get(at as usize)
                    && item.kind == DIRECTORY
                    && !removed.contains(&at)
                    && let Ok(child) = u32::try_from(item.value)
                {
                    stack.push(child);
                }
            }
        }
    }

    /// Total directory `index` from its entries, and order them.
    fn settle(&mut self, index: u32, metric: Metric) {
        let Some(&dir) = self.dirs.get(index as usize) else {
            return;
        };
        let mut total = Dir {
            bytes: 0,
            files: 0,
            dirs: 1,
            modified: 0,
            ..dir
        };
        for item in self.run(dir) {
            total.add(self.totals(item));
        }
        self.dirs[index as usize] = total;
        let Self { dirs, items, text } = self;
        let (dirs, text): (&[Dir], &[u8]) = (dirs, text);
        let start = dir.first as usize;
        let Some(run) = items.get_mut(start..start + dir.len as usize) else {
            return;
        };
        let key = |item: &Item| {
            if item.kind == DIRECTORY {
                dirs.get(item.value as usize)
                    .map_or(0, |dir| dir.key(metric))
            } else {
                item.key(metric)
            }
        };
        // Stable, which takes a run still nearly in order, as most are
        // after a few changes, in close to one pass.
        run.sort_by(|left, right| {
            order(
                (key(left), name_of(text, left)),
                (key(right), name_of(text, right)),
            )
        });
    }

    /// `(record, sequence, size)` of the `count` largest files among the
    /// tree's entries.
    pub(super) fn largest(&self, count: usize) -> Vec<(u32, u16, u64)> {
        let mut files: Vec<(u64, u32, u16)> = self
            .items
            .par_iter()
            .filter(|item| item.kind != DIRECTORY)
            .map(|item| (item.value, item.record, item.sequence))
            .collect();
        if files.len() > count {
            files.select_nth_unstable_by(count, |left, right| right.cmp(left));
            files.truncate(count);
        }
        let mut largest: Vec<(u32, u16, u64)> = files
            .into_iter()
            .map(|(size, record, sequence)| (record, sequence, size))
            .collect();
        // A file with more names that each weigh is one file.
        largest.sort_unstable();
        largest.dedup_by_key(|&mut (record, ..)| record);
        largest
    }

    /// Whether this is a tree: every run and name in bounds, every
    /// directory named once, by an entry of the directory it says holds
    /// it, and the root by none. A kept tree is a file another program can
    /// write, and must not become a tree that never ends.
    pub(super) fn is_valid(&self) -> bool {
        let named: Vec<AtomicBool> =
            std::iter::repeat_with(|| AtomicBool::new(false))
                .take(self.dirs.len())
                .collect();
        let in_bounds = |item: &Item| {
            self.text
                .get(item.at as usize..)
                .and_then(|rest| rest.get(..usize::from(item.len)))
                .is_some()
        };
        self.dirs
            .first()
            .is_some_and(|root| root.is_live() && root.parent == NONE)
            && self.dirs.par_iter().enumerate().all(|(index, dir)| {
                if !dir.is_live() {
                    return dir.len == 0;
                }
                let Some(run) = self
                    .items
                    .get(dir.first as usize..)
                    .and_then(|rest| rest.get(..dir.len as usize))
                else {
                    return false;
                };
                run.iter().all(|item| {
                    in_bounds(item)
                        && match item.kind {
                            FILE | LINK => true,
                            DIRECTORY => usize::try_from(item.value)
                                .ok()
                                .filter(|&child| child != 0)
                                .is_some_and(|child| {
                                    self.dirs.get(child).is_some_and(|sub| {
                                        sub.is_live()
                                            && sub.parent as usize == index
                                    }) && !named[child]
                                        .swap(true, Ordering::Relaxed)
                                }),
                            _ => false,
                        }
                })
            })
    }
}

/// Record numbers, a bit each: tested for every entry of the tree.
struct Bits(Vec<u64>);

impl Bits {
    fn of(numbers: &[u32]) -> Self {
        let top = numbers.iter().max().map_or(0, |&top| top as usize + 1);
        let mut bits = vec![0_u64; top.div_ceil(64)];
        for &number in numbers {
            bits[number as usize / 64] |= 1 << (number % 64);
        }
        Self(bits)
    }

    fn has(&self, number: u32) -> bool {
        self.0
            .get(number as usize / 64)
            .is_some_and(|word| word & (1 << (number % 64)) != 0)
    }
}

/// What one of a directory's entries becomes.
pub(super) enum Built {
    File(Item),
    /// A directory: its record and sequence number.
    Directory(u32, u16),
}

fn sort(run: &mut [(u64, Item)], text: &[u8]) {
    // Unstable: see `tree::settle_directory`.
    run.sort_unstable_by(|(left_key, left), (right_key, right)| {
        order(
            (*left_key, name_of(text, left)),
            (*right_key, name_of(text, right)),
        )
    });
}

impl Table<'_> {
    /// The tree beneath the root, totalled and ordered.
    pub(super) fn build(&self) -> Result<Flat, Stop> {
        let sequence = self
            .infos
            .get(ROOT as usize)
            .map_or(0, |info| info.sequence);
        // Sized for every name the table holds: grown by doubling, the
        // lists are copied and faulted in over and over.
        let mut flat = Flat {
            dirs: Vec::with_capacity(
                self.infos.par_iter().filter(|info| info.directory).count(),
            ),
            items: Vec::with_capacity(self.names.len()),
            text: Vec::with_capacity(self.texts.iter().map(String::len).sum()),
        };
        self.fill(ROOT, sequence, 0, &mut flat, &mut Vec::new())?;
        Ok(flat)
    }

    pub(super) fn descend(&self, depth: usize) -> bool {
        self.options.max_depth.is_none_or(|max| depth < max)
    }

    /// What `entry`, in a directory at `sequence`, becomes; `None` for one
    /// the walk would not list. Mirrors what the walk keeps: see
    /// `WalkContext::classify`.
    pub(super) fn entry(
        &self,
        entry: &Entry,
        sequence: u16,
        descend: bool,
    ) -> Result<Option<Built>, Stop> {
        // A root directory holds hundreds of thousands of files; a check
        // per entry lets a cancel stop within one.
        if self.progress.is_cancelled() {
            return Err(Stop);
        }
        // An entry naming a parent whose record has since been reused, or
        // itself: the root is its own parent.
        if entry.parent_sequence != sequence
            || entry.child == entry.parent
            || entry.child < FIRST_USER_RECORD
        {
            return Ok(None);
        }
        let Some(info) = self.infos.get(entry.child as usize) else {
            return Ok(None);
        };
        if !info.in_use || hidden(self.options, self.name(entry), info) {
            return Ok(None);
        }
        let link = is_link(info);
        if info.directory && !link {
            if info.attributes & EVICTED != 0 || !descend {
                return Ok(None);
            }
            return Ok(Some(Built::Directory(entry.child, info.sequence)));
        }
        let mut size = if self.options.apparent_size {
            info.apparent
        } else {
            info.allocated
        };
        let shared = info.names > 1;
        // Every name of a file has the file's size, so one that weighs
        // nothing need not be remembered to be charged once.
        if size > 0
            && shared
            && let Some(seen) = &self.seen
            && !seen.insert((0, u64::from(entry.child)))
        {
            size = 0;
        }
        Ok(Some(Built::File(Item {
            record: entry.child,
            sequence: info.sequence,
            kind: if link { LINK } else { FILE },
            shared,
            value: size,
            modified: info.modified,
            ..Item::default()
        })))
    }

    /// Directory `number` and everything beneath it into `flat`; returns
    /// its place in `flat.dirs`. Entries wait in `scratch` while their
    /// directory's subdirectories are built, then go to `flat.items` in
    /// order: one list for every directory, not one each.
    fn fill(
        &self,
        number: u32,
        sequence: u16,
        depth: usize,
        flat: &mut Flat,
        scratch: &mut Vec<(u64, Item)>,
    ) -> Result<u32, Stop> {
        if depth >= MOST_LEVELS || self.progress.is_cancelled() {
            return Err(Stop);
        }
        let index = u32::try_from(flat.dirs.len()).map_err(|_| Stop)?;
        flat.dirs.push(Dir::new(number, sequence));
        let descend = self.descend(depth);
        let metric = self.options.metric;
        let start = scratch.len();
        for entry in self.entries(number) {
            let Some(built) = self.entry(entry, sequence, descend)? else {
                continue;
            };
            let (mut item, key) = match built {
                Built::File(item) => (item, item.key(metric)),
                Built::Directory(child, child_sequence) => {
                    let at = self.fill(
                        child,
                        child_sequence,
                        depth + 1,
                        flat,
                        scratch,
                    )?;
                    let sub = &mut flat.dirs[at as usize];
                    sub.parent = index;
                    let item = Item {
                        record: child,
                        sequence: child_sequence,
                        kind: DIRECTORY,
                        value: u64::from(at),
                        ..Item::default()
                    };
                    (item, sub.key(metric))
                }
            };
            name_into(&mut flat.text, &mut item, self.name(entry))?;
            scratch.push((key, item));
        }
        let mut dir = Dir::new(number, sequence);
        for (_, item) in &scratch[start..] {
            dir.add(flat.totals(item));
        }
        sort(&mut scratch[start..], &flat.text);
        dir.first = u32::try_from(flat.items.len()).map_err(|_| Stop)?;
        dir.len = u32::try_from(scratch.len() - start).map_err(|_| Stop)?;
        flat.dirs[index as usize] = dir;
        flat.items
            .extend(scratch.drain(start..).map(|(_, item)| item));
        Ok(index)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;
    use crate::classify::{Category, Reclaim};
    use crate::tree::Seen;

    /// A volume: what each record in use holds, the root's (5, at
    /// sequence 5) aside.
    type Volume = BTreeMap<u32, Fresh>;

    fn dir(sequence: u16, (parent, at): (u32, u16), name: &str) -> Fresh {
        Fresh {
            info: Info {
                in_use: true,
                directory: true,
                sequence,
                names: 1,
                ..Info::default()
            },
            names: vec![(parent, at, name.to_owned())],
        }
    }

    fn file(sequence: u16, names: &[(u32, u16, &str)], size: u64) -> Fresh {
        Fresh {
            info: Info {
                in_use: true,
                sequence,
                names: names.len() as u8,
                apparent: size,
                allocated: size.next_multiple_of(4096),
                modified: size.cast_signed() % 1000,
                ..Info::default()
            },
            names: names
                .iter()
                .map(|&(parent, at, name)| (parent, at, name.to_owned()))
                .collect(),
        }
    }

    fn table<'a>(
        volume: &Volume,
        options: &'a ScanOptions,
        progress: &'a ScanProgress,
    ) -> Table<'a> {
        let top = volume.keys().max().map_or(0, |&top| top as usize) + 1;
        let mut infos = vec![Info::default(); top.max(ROOT as usize + 1)];
        infos[ROOT as usize] = Info {
            in_use: true,
            directory: true,
            sequence: 5,
            ..Info::default()
        };
        let mut text = String::new();
        let mut names = Vec::new();
        for (&child, fresh) in volume {
            infos[child as usize] = fresh.info;
            for (parent, parent_sequence, name) in &fresh.names {
                names.push(Entry {
                    parent: *parent,
                    parent_sequence: *parent_sequence,
                    child,
                    chunk: 0,
                    at: text.len() as u32,
                    len: name.len() as u16,
                });
                text.push_str(name);
            }
        }
        names.sort_by_key(|entry| entry.parent);
        let starts = super::super::starts(&names, infos.len());
        Table {
            infos,
            names,
            texts: vec![text],
            starts,
            options,
            progress,
            seen: options.dedup_hardlinks.then(Seen::new),
        }
    }

    /// The tree a whole read of `volume` makes.
    fn built(volume: &Volume, options: &ScanOptions) -> Flat {
        let progress = ScanProgress::default();
        let table = table(volume, options, &progress);
        let Ok(mut flat) = table.build() else {
            panic!("the table makes a tree");
        };
        flat.classify(&[]);
        assert!(flat.is_valid());
        flat
    }

    /// `flat`, the tree of `before`, brought up to `after` the way a
    /// resumed scan does: the journal names what differs, and records made
    /// since, new or reused, are what it saw created.
    fn patch(
        flat: &mut Flat,
        before: &Volume,
        after: &Volume,
        options: &ScanOptions,
    ) -> Option<()> {
        let numbers: Vec<u32> = before
            .keys()
            .chain(after.keys())
            .copied()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .filter(|number| before.get(number) != after.get(number))
            .collect();
        let fresh: FxHashMap<u32, Fresh> = numbers
            .iter()
            .filter_map(|&number| Some((number, after.get(&number)?.clone())))
            .collect();
        let created = |number: u32| {
            after.get(&number).is_some_and(|now| {
                before
                    .get(&number)
                    .is_none_or(|was| was.info.sequence != now.info.sequence)
            })
        };
        let touched = flat.patch(&numbers, &fresh, created, options)?;
        flat.classify(&touched);
        Some(())
    }

    /// Every node as a line, in order: its path and all it says. Checks
    /// on the way that the kinds are what `classify` makes of the tree.
    fn lines(flat: &Flat) -> Vec<String> {
        let progress = ScanProgress::default();
        let Ok(root) = flat.tree("C:".into(), &progress) else {
            panic!("the tree turns into nodes");
        };
        let mut again = root.clone();
        crate::classify::classify(&mut again);
        let mut out = Vec::new();
        describe(&root, "", &mut out);
        let mut expected = Vec::new();
        describe(&again, "", &mut expected);
        assert_eq!(out, expected, "kinds as `classify` decides them");
        out
    }

    fn describe(node: &Node, path: &str, out: &mut Vec<String>) {
        out.push(format!(
            "{path} {:?} {} {} {} {} {} {:?} {} {:?} {:?}",
            node.kind,
            node.bytes,
            node.own_bytes,
            node.files,
            node.own_files,
            node.dirs,
            node.inode,
            node.modified,
            node.category,
            node.reclaim
        ));
        for child in &node.children {
            describe(child, &format!("{path}/{}", child.name), out);
        }
    }

    fn exact() -> ScanOptions {
        // Which name of a hardlinked file weighs is whichever the build
        // meets first: compared exactly, each weighs.
        ScanOptions {
            dedup_hardlinks: false,
            ..ScanOptions::default()
        }
    }

    #[test]
    fn patching_the_changed_files_gives_what_a_whole_read_would() {
        let root = (ROOT, 5);
        let mut before = Volume::new();
        for (number, fresh) in [
            (20, dir(1, root, "src")),
            (21, dir(1, (20, 1), "rust-thing")),
            (22, dir(1, (21, 1), "target")),
            (23, file(1, &[(22, 1, "out.bin")], 5000)),
            (24, dir(1, root, "repo")),
            (25, dir(1, (24, 1), "objects")),
            (26, dir(1, (24, 1), "refs")),
            (27, dir(1, root, "mystery")),
            (60, dir(1, (27, 1), "src")),
            (61, file(1, &[(60, 1, "small")], 100)),
            (30, dir(1, (27, 1), ".cache")),
            (31, file(1, &[(30, 1, "blob")], 5000)),
            (40, file(1, &[(5, 5, "notes.txt")], 300)),
            (
                41,
                file(1, &[(20, 1, "linked.bin"), (27, 1, "linked.bin")], 7000),
            ),
            (42, file(1, &[(20, 1, "gone.txt")], 10)),
            (43, dir(1, (20, 1), "old")),
            (44, file(1, &[(43, 1, "x")], 20)),
            (45, dir(1, (24, 1), "moving")),
            (46, file(1, &[(45, 1, "m")], 999)),
        ] {
            before.insert(number, fresh);
        }
        let mut after = before.clone();
        // A file grows past its folder's neighbours; a manifest makes
        // `target` build output; `HEAD` makes `repo` a git store; `src`
        // outgrows `.cache`, so `mystery` is code now.
        after.insert(23, file(1, &[(22, 1, "out.bin")], 50_000));
        after.insert(50, file(1, &[(21, 1, "Cargo.toml")], 1));
        after.insert(51, file(1, &[(24, 1, "HEAD")], 1));
        after.insert(61, file(1, &[(60, 1, "small")], 90_000));
        // Gone, renamed, moved with what it holds, one name fewer.
        after.remove(&43);
        after.remove(&44);
        after.insert(40, file(1, &[(5, 5, "notes.md")], 300));
        after.insert(45, dir(1, (20, 1), "moving"));
        after.insert(41, file(1, &[(20, 1, "linked.bin")], 7000));
        // Made since: a folder with a file, and a record reused.
        after.insert(52, dir(1, (20, 1), "fresh"));
        after.insert(53, file(1, &[(52, 1, "f")], 64));
        after.insert(42, dir(2, root, "reborn"));
        after.insert(54, file(1, &[(42, 2, "inside")], 4097));

        for options in [
            exact(),
            ScanOptions {
                metric: Metric::Files,
                apparent_size: true,
                ..exact()
            },
        ] {
            let mut flat = built(&before, &options);
            patch(&mut flat, &before, &after, &options).expect("patched");
            let expected = built(&after, &options);
            assert_eq!(lines(&flat), lines(&expected));
            assert!(flat.is_valid());
        }
        let tree = |flat: &Flat| {
            flat.tree("C:".into(), &ScanProgress::default())
                .unwrap_or_else(|_| panic!("a tree"))
        };
        let expected = tree(&built(&after, &exact()));
        let named = |node: &Node, path: &[&str]| {
            let mut node = node.clone();
            for part in path {
                node = node.child_named(part).expect("there").clone();
            }
            node
        };
        assert_eq!(
            named(&expected, &["src", "rust-thing", "target", "out.bin"])
                .reclaim,
            Some(Reclaim::BuildOutput)
        );
        assert_eq!(named(&expected, &["repo", "refs"]).category, Category::Git);
        assert_eq!(named(&expected, &["mystery"]).category, Category::Code);
    }

    #[test]
    fn hardlinks_counted_once_stay_counted_once_through_a_patch() {
        let root = (ROOT, 5);
        let before: Volume = [
            (20, dir(1, root, "a")),
            (21, dir(1, root, "b")),
            (30, file(1, &[(20, 1, "x"), (21, 1, "x")], 8192)),
            (31, file(1, &[(20, 1, "y")], 4096)),
        ]
        .into_iter()
        .collect();
        let mut after = before.clone();
        after.insert(31, file(1, &[(20, 1, "y"), (21, 1, "y")], 4096));
        after.insert(30, file(1, &[(20, 1, "x"), (21, 1, "x")], 16384));
        let options = ScanOptions::default();
        let mut flat = built(&before, &options);
        patch(&mut flat, &before, &after, &options).expect("patched");
        let root = flat.tree("C:".into(), &ScanProgress::default());
        let root = root.unwrap_or_else(|_| panic!("a tree"));
        assert_eq!((root.bytes, root.files), (16384 + 4096, 4));
    }

    #[test]
    fn a_folder_coming_into_view_with_unknown_entries_needs_a_whole_read() {
        let root = (ROOT, 5);
        let options = ScanOptions {
            include_hidden: false,
            ..exact()
        };
        for attributes in [EVICTED, FILE_ATTRIBUTE_HIDDEN] {
            let mut away = dir(1, root, "cloud");
            away.info.attributes = attributes;
            let before: Volume = [
                (20, away),
                (21, file(1, &[(20, 1, "held")], 100)),
                (22, dir(1, (20, 1), "inner")),
                (23, file(1, &[(22, 1, "deep")], 100)),
            ]
            .into_iter()
            .collect();
            // Made local, or shown: its entries were never in the tree.
            let mut shown = before.clone();
            shown.insert(20, dir(1, root, "cloud"));
            let mut flat = built(&before, &options);
            assert!(patch(&mut flat, &before, &shown, &options).is_none());
            // Nor were those of a folder moved out of it.
            let mut moved = before.clone();
            moved.insert(22, dir(1, root, "inner"));
            let mut flat = built(&before, &options);
            assert!(patch(&mut flat, &before, &moved, &options).is_none());
            // One made since holds only what the journal names.
            let mut made = shown.clone();
            made.insert(20, dir(2, root, "cloud"));
            made.remove(&21);
            made.remove(&22);
            made.remove(&23);
            made.insert(24, file(1, &[(20, 2, "new")], 5));
            let mut flat = built(&before, &options);
            patch(&mut flat, &before, &made, &options).expect("patched");
            assert_eq!(lines(&flat), lines(&built(&made, &options)));
        }
    }

    /// A small xorshift: the same volumes on every run.
    struct Random(u64);

    impl Random {
        fn below(&mut self, count: usize) -> usize {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 % count.max(1) as u64) as usize
        }
    }

    /// Names the kinds depend on, and some that mean nothing.
    const NAMES: [&str; 20] = [
        "a",
        "b",
        "src",
        "target",
        "Cargo.toml",
        "objects",
        "refs",
        "HEAD",
        ".cache",
        "node_modules",
        "package.json",
        "logs",
        "Application Support",
        ".microsandbox",
        "snapshots",
        "layers",
        "x.bin",
        "y.txt",
        "Downloads",
        ".git",
    ];

    /// Directories of `volume`: `(record, sequence)`, the root first.
    fn directories(volume: &Volume) -> Vec<(u32, u16)> {
        std::iter::once((ROOT, 5))
            .chain(
                volume
                    .iter()
                    .filter(|(_, fresh)| fresh.info.directory)
                    .map(|(&number, fresh)| (number, fresh.info.sequence)),
            )
            .collect()
    }

    /// Whether `number` is `within` or beneath it.
    fn beneath(volume: &Volume, mut number: u32, within: u32) -> bool {
        for _ in 0..64 {
            if number == within {
                return true;
            }
            match volume.get(&number) {
                Some(fresh) if fresh.info.directory => {
                    number = fresh.names[0].0;
                }
                _ => return false,
            }
        }
        true
    }

    /// A name `parent` does not hold yet.
    fn free_name(
        volume: &Volume,
        parent: u32,
        random: &mut Random,
    ) -> Option<String> {
        let taken = |name: &str| {
            volume.values().any(|fresh| {
                fresh
                    .names
                    .iter()
                    .any(|(p, _, n)| *p == parent && n == name)
            })
        };
        let name = NAMES[random.below(NAMES.len())];
        (!taken(name)).then(|| name.to_owned())
    }

    /// One change as a volume sees them: a file resized, something
    /// renamed, moved, deleted or made, a name linked or unlinked, a
    /// record reused.
    fn change(volume: &mut Volume, random: &mut Random, next: &mut u32) {
        let numbers: Vec<u32> = volume.keys().copied().collect();
        let dirs = directories(volume);
        let pick = numbers.get(random.below(numbers.len())).copied();
        let (parent, parent_sequence) = dirs[random.below(dirs.len())];
        let Some(name) = free_name(volume, parent, random) else {
            return;
        };
        let size = [0, 1, 4096, 5000, 70_000, 1 << 30][random.below(6)];
        match (random.below(9), pick) {
            (0, Some(number)) if !volume[&number].info.directory => {
                let fresh = volume.get_mut(&number).expect("there");
                fresh.info.apparent = size;
                fresh.info.allocated = size.next_multiple_of(4096);
            }
            (1 | 2, Some(number)) if !beneath(volume, parent, number) => {
                let fresh = volume.get_mut(&number).expect("there");
                fresh.names[0] = (parent, parent_sequence, name);
            }
            (3, Some(number)) => {
                // A folder goes with everything in it; a file with another
                // name elsewhere keeps that one.
                let gone: BTreeSet<u32> = volume
                    .iter()
                    .filter(|(_, fresh)| fresh.info.directory)
                    .map(|(&other, _)| other)
                    .filter(|&other| beneath(volume, other, number))
                    .chain([number])
                    .collect();
                volume.retain(|other, fresh| {
                    if gone.contains(other) {
                        return false;
                    }
                    fresh.names.retain(|(parent, ..)| !gone.contains(parent));
                    fresh.info.names = fresh.names.len() as u8;
                    !fresh.names.is_empty()
                });
            }
            (4, _) => {
                volume.insert(
                    *next,
                    file(1, &[(parent, parent_sequence, &name)], size),
                );
                *next += 1;
            }
            (5, _) => {
                volume.insert(*next, dir(1, (parent, parent_sequence), &name));
                *next += 1;
            }
            (6, Some(number)) if !volume[&number].info.directory => {
                let fresh = volume.get_mut(&number).expect("there");
                fresh.names.push((parent, parent_sequence, name));
                fresh.info.names += 1;
            }
            (7, Some(number)) if volume[&number].names.len() > 1 => {
                let fresh = volume.get_mut(&number).expect("there");
                fresh.names.pop();
                fresh.info.names -= 1;
            }
            (8, Some(number)) if !volume[&number].info.directory => {
                let sequence = volume[&number].info.sequence + 1;
                let fresh = if random.below(2) == 0 {
                    dir(sequence, (parent, parent_sequence), &name)
                } else {
                    file(sequence, &[(parent, parent_sequence, &name)], size)
                };
                volume.insert(number, fresh);
            }
            _ => {}
        }
    }

    #[test]
    fn a_chain_of_patched_changes_keeps_what_a_whole_read_would_make() {
        for (seed, options) in [
            (0x2545_F491_4F6C_DD1D, exact()),
            (
                0x9E37_79B9_7F4A_7C15,
                ScanOptions {
                    metric: Metric::Files,
                    ..exact()
                },
            ),
        ] {
            let mut random = Random(seed);
            let mut volume = Volume::new();
            let mut next = 20;
            for _ in 0..40 {
                change(&mut volume, &mut random, &mut next);
            }
            let mut flat = built(&volume, &options);
            for round in 0..300 {
                let before = volume.clone();
                for _ in 0..=random.below(4) {
                    change(&mut volume, &mut random, &mut next);
                }
                patch(&mut flat, &before, &volume, &options)
                    .unwrap_or_else(|| panic!("round {round} patched"));
                assert_eq!(
                    lines(&flat),
                    lines(&built(&volume, &options)),
                    "round {round}"
                );
                assert!(flat.is_valid());
            }
        }
    }
}
