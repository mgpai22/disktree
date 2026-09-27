//! The tree as flat arrays: what a read of the file table shows,
//! totalled, ordered and classified, in a form that is cheap to keep and
//! to turn into [`Node`]s.
//!
//! Every directory is a [`Dir`] and its entries a run of [`Item`]s, in the
//! order the tree shows them; names sit in one arena.

use std::sync::atomic::{AtomicBool, Ordering};

use rayon::prelude::*;
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

/// No directory: the root's parent.
pub(super) const NONE: u32 = u32::MAX;

/// What an [`Item`] is.
pub(super) const FILE: u8 = 0;
pub(super) const LINK: u8 = 1;
pub(super) const DIRECTORY: u8 = 2;

/// A kind not decided yet: every directory of a tree just built.
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
    /// The directory holding it; [`NONE`] for the root.
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

    /// Decide what directories are, as `classify::classify` would, in a
    /// tree whose kinds are all unset. The root's entries are decided
    /// first: one takes the kind of its largest child.
    pub(super) fn classify(&mut self) {
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
                self.kinds(item.value, code(category, reclaim), 1, &mut kinds);
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
    /// and go on beneath it if so.
    fn kinds(
        &self,
        index: u64,
        kind: Kind,
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
        if !changed || depth >= MOST_LEVELS {
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
            self.kinds(item.value, code(category, reclaim), depth + 1, out);
        };
        for item in run {
            child(item, out);
        }
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
