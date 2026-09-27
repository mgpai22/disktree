//! A finished walk of one volume kept on disk: a header, the root path, the
//! files last seen open, then every node depth first. A leaf keeps only its
//! own size, its count following from its kind; a directory keeps its
//! totals, so nothing is summed again on load. Identities keep only the
//! file number, their device being the state's volume.
//! Anything that does not check out (another format, a torn or
//! damaged file, a count or name that cannot be) loads as nothing, and the
//! caller walks again.

use std::hash::Hasher as _;
use std::io::{self, Read as _, Write as _};
use std::path::Path;

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

/// Fewest bytes a node takes: tag, classes, a one-byte name and its
/// length, modified and own bytes.
const LEAST_RECORD: usize = 6;

/// Tag bits: the kind, then flags. Anything above `KNOWN` is damage.
const KIND: u8 = 0b11;
const READ_ERROR: u8 = 1 << 2;
/// A file number follows; its device is the state's volume.
const INODE: u8 = 1 << 3;
const KNOWN: u8 = KIND | READ_ERROR | INODE;

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

/// The state kept in `path`, if it is whole and of this format.
pub(super) fn load(path: &Path) -> Option<State> {
    let mut file = crate::windows::cache_read(path)?;
    let len = usize::try_from(file.metadata().ok()?.len()).ok()?;
    if len > MOST_BYTES {
        return None;
    }
    let mut bytes = Vec::with_capacity(len);
    (&mut file)
        .take(MOST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    decode(&bytes)
}

/// Write `state` to `path`, whole or not at all: a failed or interrupted
/// save leaves whatever was there before. Not synced: a crash that loses
/// the new bytes fails the checksum, and the next scan walks again.
pub(super) fn save(path: &Path, state: &State) -> io::Result<()> {
    let bytes = encode(state)?;
    crate::windows::cache_write(path, |out| out.write_all(&bytes))
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

fn decode(bytes: &[u8]) -> Option<State> {
    if bytes.len() < HEADER || bytes.len() > MOST_BYTES || bytes[..8] != MAGIC {
        return None;
    }
    let mut reader = Reader {
        bytes,
        at: 8,
        nodes_left: 0,
        volume: 0,
    };
    if reader.u64()? != checksum(&bytes[16..]) {
        return None;
    }
    let volume = reader.u64()?;
    let root_id = reader.u64()?;
    let journal = reader.u64()?;
    let next = reader.u64()?;
    let created = reader.u64()?;
    let options = reader.u64()?;
    let open = usize::try_from(reader.u64()?).ok()?;
    let root = usize::try_from(reader.u64()?).ok()?;
    let nodes = reader.u64()?;
    if nodes == 0 || nodes > MOST_NODES {
        return None;
    }
    let root = std::str::from_utf8(reader.take(root)?).ok()?;
    if root.contains('\0') {
        return None;
    }
    let open = reader
        .take(open.checked_mul(8)?)?
        .chunks_exact(8)
        .map(|word| u64::from_le_bytes(word.try_into().unwrap_or_default()))
        .collect();
    reader.nodes_left = nodes;
    reader.volume = volume;
    let tree = reader.node(0)?;
    if reader.nodes_left != 0 || reader.at != bytes.len() {
        return None;
    }
    Some(State {
        root: root.to_owned(),
        volume,
        root_id,
        journal,
        next,
        created,
        options,
        open,
        tree,
    })
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

/// A cursor over a loaded file; every read fails past its end.
struct Reader<'a> {
    bytes: &'a [u8],
    at: usize,
    /// Nodes the header promises and the tree has not yet used.
    nodes_left: u64,
    /// Every kept identity's device.
    volume: u64,
}

impl<'a> Reader<'a> {
    fn take(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.at.checked_add(len)?;
        let bytes = self.bytes.get(self.at..end)?;
        self.at = end;
        Some(bytes)
    }

    fn byte(&mut self) -> Option<u8> {
        let byte = *self.bytes.get(self.at)?;
        self.at += 1;
        Some(byte)
    }

    fn u64(&mut self) -> Option<u64> {
        Some(u64::from_le_bytes(self.take(8)?.try_into().ok()?))
    }

    fn varint(&mut self) -> Option<u64> {
        let mut value = 0;
        for shift in (0_u32..64).step_by(7) {
            let byte = self.byte()?;
            let part = u64::from(byte & 0x7F);
            if shift == 63 && part > 1 {
                return None;
            }
            value |= part << shift;
            if byte & 0x80 == 0 {
                return Some(value);
            }
        }
        None
    }

    fn node(&mut self, depth: usize) -> Option<Node> {
        self.nodes_left = self.nodes_left.checked_sub(1)?;
        let tag = self.byte()?;
        if tag & !KNOWN != 0 {
            return None;
        }
        let kind = kind_from(tag & KIND);
        let classes = self.byte()?;
        let category = category_from(classes & 0x0F)?;
        let reclaim = match classes >> 4 {
            0 => None,
            code => Some(reclaim_from(code)?),
        };
        let len = usize::try_from(self.varint()?).ok()?;
        let name = std::str::from_utf8(self.take(len)?).ok()?;
        if !name_fits(name, depth) {
            return None;
        }
        let modified = self.varint()?;
        let modified = (modified >> 1).cast_signed()
            ^ (modified & 1).cast_signed().wrapping_neg();
        let inode = if tag & INODE == 0 {
            None
        } else {
            Some((self.volume, self.varint()?))
        };
        let (bytes, own_bytes, files, own_files, dirs) = if kind.is_dir() {
            (
                self.varint()?,
                self.varint()?,
                self.varint()?,
                self.varint()?,
                self.varint()?,
            )
        } else {
            let own_bytes = self.varint()?;
            let files = u64::from(kind == NodeKind::File);
            (own_bytes, own_bytes, files, files, 0)
        };
        let children = if kind.is_dir() {
            let count = usize::try_from(self.varint()?).ok()?;
            // Bounded before anything is allocated: a count no remaining
            // node or byte could fill is damage.
            if (count > 0 && depth >= MOST_DEPTH)
                || count as u64 > self.nodes_left
                || count > (self.bytes.len() - self.at) / LEAST_RECORD
            {
                return None;
            }
            let mut children = Vec::with_capacity(count);
            for _ in 0..count {
                children.push(self.node(depth + 1)?);
            }
            children
        } else {
            Vec::new()
        };
        Some(Node {
            name: name.into(),
            kind,
            bytes,
            own_bytes,
            files,
            own_files,
            dirs,
            inode,
            read_error: tag & READ_ERROR != 0,
            modified,
            category,
            reclaim,
            children,
        })
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

const fn kind_from(code: u8) -> NodeKind {
    match code {
        0 => NodeKind::Directory,
        1 => NodeKind::File,
        2 => NodeKind::Symlink,
        _ => NodeKind::Other,
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

const fn category_from(code: u8) -> Option<Category> {
    Some(match code {
        0 => Category::Code,
        1 => Category::AgentScratch,
        2 => Category::Toolchain,
        3 => Category::Synced,
        4 => Category::Git,
        5 => Category::Media,
        6 => Category::Documents,
        7 => Category::Cache,
        8 => Category::Other,
        _ => return None,
    })
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

const fn reclaim_from(code: u8) -> Option<Reclaim> {
    Some(match code {
        1 => Reclaim::Regenerable,
        2 => Reclaim::SyncHistory,
        3 => Reclaim::PackageStore,
        4 => Reclaim::BuildOutput,
        5 => Reclaim::Reinstallable,
        6 => Reclaim::SandboxLayers,
        7 => Reclaim::Snapshots,
        8 => Reclaim::Trash,
        9 => Reclaim::Temporary,
        _ => return None,
    })
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

fn invalid(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, reason)
}

fn too_large() -> io::Error {
    io::Error::other("too large to keep")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn leaf(name: &str, kind: NodeKind, bytes: u64) -> Node {
        Node::entry(name, kind, bytes)
    }

    const VOLUME: u64 = 0xDEAD_BEEF;

    /// A finished tree of one volume with every kind, flag and class.
    fn sample() -> Node {
        let mut file = leaf("a.txt", NodeKind::File, 1234);
        file.inode = Some((VOLUME, 0xFFFF_0000_0000_1234));
        file.modified = -5;
        file.category = Category::Documents;
        // A second name of a file already charged: no weight of its own.
        let mut link = leaf("hard", NodeKind::File, 0);
        link.inode = Some((VOLUME, 0xFFFF_0000_0000_1234));
        let mut odd = leaf("ödd ✓", NodeKind::File, 10);
        odd.modified = 17;
        let mut sub = Node::directory("src");
        sub.read_error = true;
        sub.inode = Some((VOLUME, 42));
        sub.category = Category::Code;
        sub.reclaim = Some(Reclaim::Temporary);
        sub.modified = i64::MAX;
        sub.children = vec![
            leaf("link", NodeKind::Symlink, 0),
            leaf("fifo", NodeKind::Other, 0),
            Node::directory("empty"),
        ];
        let mut root = Node::directory("C:\\");
        root.reclaim = Some(Reclaim::Regenerable);
        root.modified = i64::MIN;
        root.children = vec![sub, file, link, odd];
        crate::tree::aggregate(&mut root, crate::tree::Metric::Bytes);
        root
    }

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

    fn reseal(bytes: &mut [u8]) {
        let sum = checksum(&bytes[16..]);
        bytes[8..16].copy_from_slice(&sum.to_le_bytes());
    }

    fn body_at(bytes: &[u8]) -> usize {
        let word = |at: usize| {
            u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap()) as usize
        };
        HEADER + word(72) + word(64) * 8
    }

    #[test]
    fn a_saved_state_loads_as_it_was() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("walk").join("walk-C.bin");
        let kept = state(sample());
        save(&path, &kept).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(format!("{loaded:?}"), format!("{kept:?}"));
    }

    #[test]
    fn a_save_replaces_the_last_and_leaves_nothing_beside_it() {
        let temp = tempfile::tempdir().unwrap();
        // A directory the save makes: an elevated one refuses any other.
        let dir = temp.path().join("walk");
        let path = dir.join("walk.bin");
        save(&path, &state(Node::directory("old"))).unwrap();
        save(&path, &state(sample())).unwrap();
        assert_eq!(&*load(&path).unwrap().tree.name, "C:\\");
        let names: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, ["walk.bin"]);
    }

    #[test]
    fn a_missing_file_loads_as_nothing() {
        let dir = tempfile::tempdir().unwrap();
        assert!(load(&dir.path().join("none.bin")).is_none());
    }

    #[test]
    fn any_damaged_byte_or_torn_end_is_refused() {
        let bytes = encode(&state(sample())).unwrap();
        assert!(decode(&bytes).is_some());
        for at in 0..bytes.len() {
            let mut damaged = bytes.clone();
            damaged[at] ^= 0x10;
            assert!(decode(&damaged).is_none(), "byte {at}");
        }
        for len in 0..bytes.len() {
            assert!(decode(&bytes[..len]).is_none(), "length {len}");
        }
    }

    #[test]
    fn a_checksummed_file_with_trailing_bytes_is_refused() {
        let mut bytes = encode(&state(sample())).unwrap();
        bytes.push(0);
        reseal(&mut bytes);
        assert!(decode(&bytes).is_none());
    }

    #[test]
    fn unknown_flags_and_classes_are_refused_even_when_checksummed() {
        let bytes = encode(&state(sample())).unwrap();
        let root = body_at(&bytes);
        for (at, value) in [
            (root, 0x10),              // an unknown tag bit
            (root + 1, 9),             // no such category
            (root + 1, (10 << 4) | 8), // no such reason
        ] {
            let mut forged = bytes.clone();
            forged[at] = value;
            reseal(&mut forged);
            assert!(decode(&forged).is_none(), "{at}: {value:#x}");
        }
    }

    #[test]
    fn counts_that_do_not_add_up_are_refused() {
        let bytes = encode(&state(Node::directory("r"))).unwrap();
        // The root's child count is its last byte.
        let mut forged = bytes.clone();
        *forged.last_mut().unwrap() = 1;
        reseal(&mut forged);
        assert!(decode(&forged).is_none());
        for nodes in [0, 2, MOST_NODES + 1] {
            let mut forged = bytes.clone();
            forged[NODE_COUNT_AT..HEADER]
                .copy_from_slice(&u64::to_le_bytes(nodes));
            reseal(&mut forged);
            assert!(decode(&forged).is_none(), "{nodes} nodes");
        }
        let mut forged = bytes;
        forged[64..72].copy_from_slice(&u64::MAX.to_le_bytes());
        reseal(&mut forged);
        assert!(decode(&forged).is_none());
    }

    #[test]
    fn names_that_are_not_one_component_are_neither_kept_nor_loaded() {
        let mut root = Node::directory("r");
        root.children.push(leaf("ab", NodeKind::File, 1));
        let bytes = encode(&state(root.clone())).unwrap();
        let at = bytes.windows(2).rposition(|pair| pair == b"ab").unwrap();
        for bad in ["..", "a/", "a\0", "C:", "a:"] {
            let mut forged = bytes.clone();
            forged[at..at + 2].copy_from_slice(bad.as_bytes());
            reseal(&mut forged);
            assert!(decode(&forged).is_none(), "{bad:?}");
            root.children[0].name = bad.into();
            assert!(encode(&state(root.clone())).is_err(), "{bad:?}");
        }
        let mut forged = bytes;
        forged[at] = 0xFF;
        reseal(&mut forged);
        assert!(decode(&forged).is_none(), "not UTF-8");
        for name in ["", "."] {
            root.children[0].name = name.into();
            assert!(encode(&state(root.clone())).is_err(), "{name:?}");
        }
    }

    #[test]
    fn depth_is_bounded_on_both_sides() {
        fn chain(depth: usize) -> Node {
            let mut node = Node::directory("d");
            for _ in 0..depth {
                let mut parent = Node::directory("d");
                parent.children.push(node);
                node = parent;
            }
            node
        }
        let deepest = encode(&state(chain(MOST_DEPTH))).unwrap();
        assert_eq!(decode(&deepest).unwrap().tree.depth() as usize, MOST_DEPTH);
        assert!(encode(&state(chain(MOST_DEPTH + 1))).is_err());
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
            let mut file = leaf("f", NodeKind::File, 1);
            file.inode = Some((VOLUME, 9));
            let mut root = Node::directory("r");
            root.children.push(file);
            assert!(encode(&state(root.clone())).is_ok());
            bad(&mut root.children[0]);
            assert!(encode(&state(root)).is_err(), "case {index}");
        }
    }
}
