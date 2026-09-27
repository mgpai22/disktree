//! What each entry of the file table becomes in the tree a scan hands
//! over, as the walk would list it: a directory to descend into, or a file
//! or link with its size as charged.

use windows_sys::Win32::Storage::FileSystem::{
    FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_REPARSE_POINT,
};

use super::{
    EVICTED, Entry, FIRST_USER_RECORD, Info, NAME_SURROGATE, Stop, Table,
};
use crate::scan::ScanOptions;
use crate::tree::{Node, NodeKind};

/// What an [`Item`] is.
pub(super) const FILE: u8 = 0;
pub(super) const LINK: u8 = 1;

/// A file or link, as the tree shows it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct Item {
    /// Its file record.
    pub record: u32,
    pub kind: u8,
    /// The file has more than one name: its node carries its identity,
    /// and with hardlinks counted once only one of its names weighs.
    pub shared: bool,
    /// Its size as charged.
    pub value: u64,
    /// Its last write, in Unix seconds.
    pub modified: i64,
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

/// What one of a directory's entries becomes.
pub(super) enum Built {
    File(Item),
    /// A directory: its record and sequence number.
    Directory(u32, u16),
}

impl Table<'_> {
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
            kind: if link { LINK } else { FILE },
            shared,
            value: size,
            modified: info.modified,
        })))
    }
}

/// A file's or link's node, settled.
pub(super) fn leaf(item: &Item, name: &str) -> Node {
    let kind = if item.kind == LINK {
        NodeKind::Symlink
    } else {
        NodeKind::File
    };
    let mut node = Node::entry(name, kind, item.value);
    node.modified = item.modified;
    node.inode = item.shared.then_some((0, u64::from(item.record)));
    node
}
