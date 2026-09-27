//! A finished walk of one volume kept on disk: a header, the root path, the
//! files last seen open, then every node depth first. A leaf keeps only its
//! own size, its count following from its kind; a directory keeps its
//! totals, so nothing is summed again on load. Identities keep only the
//! file number, their device being the state's volume.

use std::fs::File;
use std::hash::Hasher as _;
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rayon::prelude::*;
use rustc_hash::FxHasher;

use crate::classify::{Category, Reclaim};
use crate::tree::{Node, NodeKind};

/// Bumped for layout or scan-policy changes, including incomplete listings.
/// Older snapshots must not hide an error the newer walk would retry.
const MAGIC: [u8; 8] = *b"dtwalk\x00\x03";

/// Largest file kept or read, header included.
const MOST_BYTES: usize = 1 << 30;
const MOST_NODES: u64 = 10_000_000;
/// Deepest node below the root.
const MOST_DEPTH: usize = 512;

/// Magic, checksum of everything after it, then volume, root id, journal,
/// next, created, options, and the counts of open files, root bytes and
/// nodes.
const HEADER: usize = 8 * 11;
const NODE_COUNT_AT: usize = 80;

/// Tag bits above the kind's two: flags.
const READ_ERROR: u8 = 1 << 2;
/// A file number follows; its device is the state's volume.
const INODE: u8 = 1 << 3;

/// What the next scan starts from.
#[derive(Debug)]
pub(super) struct State {
    pub root: String,
    pub volume: u64,
    pub root_id: u64,
    pub journal: u64,
    pub next: u64,
    /// Unix seconds.
    pub created: u64,
    pub options: u64,
    pub open: Vec<u64>,
    pub tree: Node,
}

/// Write `state` to `path`, whole or not at all: a failed or interrupted
/// save leaves whatever was there before.
pub(super) fn save(path: &Path, state: &State) -> io::Result<()> {
    replace(path, &encode(state)?)
}

fn encode(state: &State) -> io::Result<Vec<u8>> {
    if state.root.contains('\0') {
        return Err(invalid("root path holds a NUL"));
    }
    let hint =
        usize::try_from(state.tree.files.saturating_add(state.tree.dirs))
            .unwrap_or(usize::MAX)
            .saturating_mul(24)
            .min(MOST_BYTES);
    let mut out = Vec::with_capacity(hint);
    out.extend_from_slice(&MAGIC);
    for value in [
        0,
        state.volume,
        state.root_id,
        state.journal,
        state.next,
        state.created,
        state.options,
        state.open.len() as u64,
        state.root.len() as u64,
        0,
    ] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out.extend_from_slice(state.root.as_bytes());
    for number in &state.open {
        out.extend_from_slice(&number.to_le_bytes());
    }
    let mut writer = Writer {
        out,
        nodes: 0,
        volume: state.volume,
    };
    writer.node(&state.tree, 0)?;
    let Writer { mut out, nodes, .. } = writer;
    if out.len() > MOST_BYTES {
        return Err(too_large());
    }
    out[NODE_COUNT_AT..HEADER].copy_from_slice(&nodes.to_le_bytes());
    let sum = checksum(&out[16..]);
    out[8..16].copy_from_slice(&sum.to_le_bytes());
    Ok(out)
}

/// Nodes appended depth first to one buffer.
struct Writer {
    out: Vec<u8>,
    nodes: u64,
    /// The device every kept identity must be on; only the file number is
    /// written.
    volume: u64,
}

impl Writer {
    fn node(&mut self, node: &Node, depth: usize) -> io::Result<()> {
        self.nodes += 1;
        if self.nodes > MOST_NODES || self.out.len() > MOST_BYTES {
            return Err(too_large());
        }
        if !name_fits(&node.name, depth) {
            return Err(invalid("a name cannot be kept"));
        }
        let dir = node.is_dir();
        if !dir
            && (!node.children.is_empty()
                || node.bytes != node.own_bytes
                || node.files != u64::from(node.kind == NodeKind::File)
                || node.own_files != node.files
                || node.dirs != 0)
        {
            return Err(invalid("a leaf is not settled"));
        }
        if !node.children.is_empty() && depth >= MOST_DEPTH {
            return Err(too_large());
        }
        let inode = match node.inode {
            Some((device, inode)) if device == self.volume => Some(inode),
            Some(_) => return Err(invalid("an identity of another volume")),
            None => None,
        };
        let tag = kind_code(node.kind)
            | if node.read_error { READ_ERROR } else { 0 }
            | if inode.is_some() { INODE } else { 0 };
        self.out.push(tag);
        self.out.push(
            category_code(node.category)
                | (node.reclaim.map_or(0, reclaim_code) << 4),
        );
        self.varint(node.name.len() as u64);
        self.out.extend_from_slice(node.name.as_bytes());
        let modified = node.modified;
        self.varint(((modified << 1) ^ (modified >> 63)).cast_unsigned());
        if let Some(inode) = inode {
            self.varint(inode);
        }
        if dir {
            self.varint(node.bytes);
            self.varint(node.own_bytes);
            self.varint(node.files);
            self.varint(node.own_files);
            self.varint(node.dirs);
        } else {
            self.varint(node.own_bytes);
        }
        if dir {
            self.varint(node.children.len() as u64);
            for child in &node.children {
                self.node(child, depth + 1)?;
            }
        }
        Ok(())
    }

    fn varint(&mut self, mut value: u64) {
        while value >= 0x80 {
            self.out.push(value as u8 | 0x80);
            value >>= 7;
        }
        self.out.push(value as u8);
    }
}

/// A name below the root is one path component, with no `:` that Windows
/// could take for a drive or a stream; the root's is whatever the scan
/// called it, a drive or a path.
fn name_fits(name: &str, depth: usize) -> bool {
    if depth == 0 {
        return !name.contains('\0');
    }
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.bytes().any(|byte| {
            byte == 0 || byte == b':' || std::path::is_separator(byte as char)
        })
}

const fn kind_code(kind: NodeKind) -> u8 {
    match kind {
        NodeKind::Directory => 0,
        NodeKind::File => 1,
        NodeKind::Symlink => 2,
        NodeKind::Other => 3,
    }
}

const fn category_code(category: Category) -> u8 {
    match category {
        Category::Code => 0,
        Category::AgentScratch => 1,
        Category::Toolchain => 2,
        Category::Synced => 3,
        Category::Git => 4,
        Category::Media => 5,
        Category::Documents => 6,
        Category::Cache => 7,
        Category::Other => 8,
    }
}

/// `0` is kept for no reason at all.
const fn reclaim_code(reclaim: Reclaim) -> u8 {
    match reclaim {
        Reclaim::Regenerable => 1,
        Reclaim::SyncHistory => 2,
        Reclaim::PackageStore => 3,
        Reclaim::BuildOutput => 4,
        Reclaim::Reinstallable => 5,
        Reclaim::SandboxLayers => 6,
        Reclaim::Snapshots => 7,
        Reclaim::Trash => 8,
        Reclaim::Temporary => 9,
    }
}

/// A check a torn or damaged file fails: each megabyte hashed on a thread
/// of its own, then the hashes in order.
fn checksum(bytes: &[u8]) -> u64 {
    let parts: Vec<u64> = bytes
        .par_chunks(1 << 20)
        .map(|chunk| {
            let mut hasher = FxHasher::default();
            hasher.write(chunk);
            hasher.finish()
        })
        .collect();
    let mut hasher = FxHasher::default();
    hasher.write_usize(bytes.len());
    for part in parts {
        hasher.write_u64(part);
    }
    hasher.finish()
}

/// Written whole under a name of this process's own, then renamed over
/// `path`: a reader sees the old file or the new one, never half of one.
/// Not synced: a crash that loses the new bytes fails the checksum, and
/// the next scan walks again.
fn replace(path: &Path, bytes: &[u8]) -> io::Result<()> {
    static SAVES: AtomicU64 = AtomicU64::new(0);
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let mut partial = path.as_os_str().to_owned();
    partial.push(format!(
        ".{}-{}.partial",
        std::process::id(),
        SAVES.fetch_add(1, Ordering::Relaxed)
    ));
    let partial = PathBuf::from(partial);
    let written = File::create(&partial)
        .and_then(|mut out| out.write_all(bytes))
        .and_then(|()| std::fs::rename(&partial, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&partial);
    }
    written
}

fn invalid(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason)
}

fn too_large() -> io::Error {
    io::Error::other("too large to keep")
}

#[cfg(test)]
mod tests {
    use super::*;

    const VOLUME: u64 = 0xDEAD_BEEF;

    fn state(tree: Node) -> State {
        State {
            root: "C:\\Users\\me".to_owned(),
            volume: VOLUME,
            root_id: 5,
            journal: u64::MAX,
            next: 1 << 40,
            created: 1_790_000_000,
            options: 0b101,
            open: vec![1, u64::MAX, 3],
            tree,
        }
    }

    #[test]
    fn only_settled_leaves_of_the_volume_are_kept() {
        let breaks: [fn(&mut Node); 5] = [
            |file| file.inode = Some((1, 9)),
            |file| file.bytes += 1,
            |file| file.files = 0,
            |file| file.dirs = 1,
            |file| file.children.push(Node::entry("g", NodeKind::File, 1)),
        ];
        for (index, bad) in breaks.into_iter().enumerate() {
            let mut file = Node::entry("f", NodeKind::File, 1);
            file.inode = Some((VOLUME, 9));
            let mut root = Node::directory("r");
            root.children.push(file);
            assert!(encode(&state(root.clone())).is_ok());
            bad(&mut root.children[0]);
            assert!(encode(&state(root)).is_err(), "case {index}");
        }
    }
}
