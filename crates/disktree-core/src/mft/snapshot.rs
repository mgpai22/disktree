//! Keeping a scan's finished tree for the next one: the flat tree a whole
//! read made, written to a file in the scan's cache directory, with where
//! the volume's change journal stood when the read began. The next scan
//! starts from it: the journal names every file changed since, and only
//! those records are read again, from NTFS itself rather than the disk,
//! so they are as current as the file system is; `flat.rs` takes them
//! into the tree.
//!
//! Anything that does not line up gives up and reads the whole table: no
//! journal, another journal (it was deleted and made again), a kept tree
//! of another format, volume, record size or scan options, or one that
//! fails its checksum or is not a tree, a journal that has since dropped
//! the changes wanted, or changes the kept tree cannot take in.

use std::fs::File;
use std::io::{self, Read as _, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::thread::JoinHandle;

use rayon::prelude::*;
use rustc_hash::{FxHashMap, FxHashSet};
use windows_sys::Win32::System::Ioctl::{
    FSCTL_GET_NTFS_FILE_RECORD, FSCTL_QUERY_USN_JOURNAL, FSCTL_READ_USN_JOURNAL,
};

use super::flat::{Dir, Flat, Fresh, Item, NONE};
use super::{
    ATTRIBUTE_LIST, Entry, Geometry, Info, Parsed, REFERENCE, ReadExact as _,
    attributes, open_volume, parse_fixed, u16_at, u32_at, u64_at,
};
use crate::scan::ScanOptions;
use crate::tree::Metric;
use crate::windows::control;

/// Bumped whenever what a kept tree holds changes, so one kept by an
/// older build is read again rather than trusted.
const MAGIC: [u8; 8] = *b"dttree\x00\x02";

/// Bytes of the journal read per call.
const JOURNAL_BUFFER: usize = 1 << 20;

/// The volume's change journal: which one, and the numbers (`USN`s) of its
/// first and next entries.
#[derive(Clone, Copy)]
pub(super) struct Journal {
    id: u64,
    first: u64,
    next: u64,
}

/// Where the next scan picks up the journal.
pub(super) struct Checkpoint {
    journal: u64,
    next: u64,
}

impl Checkpoint {
    /// Before a whole read that `journal` is at.
    pub(super) const fn before(journal: Journal) -> Self {
        Self {
            journal: journal.id,
            next: journal.next,
        }
    }
}

/// The file kept for `letter` in `dir`.
pub(super) fn file(dir: &Path, letter: char) -> PathBuf {
    dir.join(format!("mft-{letter}.bin"))
}

pub(super) fn query(volume: &File) -> Option<Journal> {
    let mut out = [0_u8; 64];
    let len = control(volume, FSCTL_QUERY_USN_JOURNAL, &[], &mut out).ok()?;
    let out = out.get(..len)?;
    Some(Journal {
        id: u64_at(out, 0)?,
        first: u64_at(out, 8)?,
        next: u64_at(out, 16)?,
    })
}

/// Every file the journal names from `from` on, and where it ended.
/// `None` when the journal cannot be read from there: it has dropped those
/// entries, or holds a kind this does not know.
fn changes(
    volume: &File,
    journal: Journal,
    from: u64,
) -> Option<(FxHashSet<u32>, u64)> {
    let mut files = FxHashSet::default();
    let mut buffer = vec![0_u8; JOURNAL_BUFFER];
    let mut at_usn = from;
    loop {
        // READ_USN_JOURNAL_DATA_V0: start, reasons, only on close, timeout,
        // bytes to wait for, journal id.
        let mut input = [0_u8; 40];
        input[0..8].copy_from_slice(&at_usn.to_le_bytes());
        input[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
        input[32..40].copy_from_slice(&journal.id.to_le_bytes());
        let len = control(volume, FSCTL_READ_USN_JOURNAL, &input, &mut buffer)
            .ok()?;
        let out = buffer.get(..len)?;
        let next = u64_at(out, 0)?;
        let mut at = 8;
        while at < out.len() {
            let length = u32_at(out, at)? as usize;
            // Version 2 records, which a version 0 request gets on NTFS:
            // 64-bit file references at 8.
            if length < 60 || u16_at(out, at + 4)? != 2 {
                return None;
            }
            let record = out.get(at..at + length)?;
            let number = u32::try_from(u64_at(record, 8)? & REFERENCE).ok()?;
            files.insert(number);
            at += length;
        }
        if out.len() <= 8 || next <= at_usn {
            return Some((files, next));
        }
        at_usn = next;
    }
}

/// The last scan's tree brought up to date; `None` when a whole read is
/// needed instead.
pub(super) fn resume(
    path: &str,
    volume: &File,
    geometry: &Geometry,
    journal: Journal,
    file: &Path,
    options: &ScanOptions,
) -> Option<Flat> {
    let (mut flat, checkpoint) = load(file, geometry, journal, key(options))?;
    let (files, _) = changes(volume, journal, checkpoint.next)?;
    let mut numbers: Vec<u32> = files.into_iter().collect();
    numbers.sort_unstable();
    let fresh = fresh(&read_again(path, geometry, &numbers)?);
    let touched = flat.patch(&numbers, &fresh, options)?;
    flat.classify(&touched);
    Some(flat)
}

/// What re-reading `numbers` found: per list, the base records' facts and
/// the rest parsed, the list's place its chunk number.
type Lists = Vec<(Vec<(u32, Info)>, Parsed)>;

/// Every record of `numbers` as NTFS holds it now.
fn read_again(
    path: &str,
    geometry: &Geometry,
    numbers: &[u32],
) -> Option<Lists> {
    let volume = open_volume(path).ok()?;
    let mut out = Parsed::default();
    let mut bases = Vec::with_capacity(numbers.len());
    let mut buffer = Vec::new();
    for &number in numbers {
        if let Some(info) =
            reparse(&volume, geometry, number, 0, &mut buffer, &mut out).ok()?
        {
            bases.push((number, info));
        }
    }
    Some(vec![(bases, out)])
}
/// What each record re-read holds.
fn fresh(lists: &Lists) -> FxHashMap<u32, Fresh> {
    let mut fresh: FxHashMap<u32, Fresh> = lists
        .iter()
        .flat_map(|(bases, _)| bases)
        .map(|&(number, info)| {
            (
                number,
                Fresh {
                    info,
                    names: Vec::new(),
                },
            )
        })
        .collect();
    let text = |out: &Parsed, entry: &Entry| {
        let at = entry.at as usize;
        out.text
            .get(at..at + usize::from(entry.len))
            .unwrap_or_default()
            .to_owned()
    };
    for (_, out) in lists {
        for entry in &out.names {
            if let Some(record) = fresh.get_mut(&entry.child) {
                let name = text(out, entry);
                record
                    .names
                    .push((entry.parent, entry.parent_sequence, name));
            }
        }
    }
    fresh
}

/// Parse file `number` as NTFS holds it now into `out`: its base record's
/// facts, or `None` when the record is free or is itself another file's
/// extension, which its base file carries.
fn reparse(
    volume: &File,
    geometry: &Geometry,
    number: u32,
    chunk: u32,
    buffer: &mut Vec<u8>,
    out: &mut Parsed,
) -> io::Result<Option<Info>> {
    let Some(base) = fetch(volume, geometry, number, buffer)? else {
        return Ok(None);
    };
    if u64_at(&base, 0x20).unwrap_or(0) & REFERENCE != 0 {
        return Ok(None);
    }
    let mut info = Info::default();
    parse_fixed(&base, number, chunk, out, &mut info);
    if !info.in_use {
        return Ok(None);
    }
    // A file spread over extension records is for a whole read.
    if attributes(&base).any(|attribute| attribute.kind == ATTRIBUTE_LIST) {
        return Err(io::Error::other("an attribute list"));
    }
    Ok(Some(info))
}

/// Record `number` as NTFS holds it now, which the disk may not yet;
/// `None` when it is not in use. NTFS hands it over with its update
/// sequence already undone.
fn fetch(
    volume: &File,
    geometry: &Geometry,
    number: u32,
    buffer: &mut Vec<u8>,
) -> io::Result<Option<Vec<u8>>> {
    // NTFS_FILE_RECORD_OUTPUT_BUFFER: reference, length, record.
    const AT: usize = 12;
    buffer.resize(AT + geometry.record, 0);
    let input = u64::from(number).to_le_bytes();
    let len = control(volume, FSCTL_GET_NTFS_FILE_RECORD, &input, buffer)?;
    let out = buffer.get(..len).unwrap_or_default();
    // A free record gives the nearest in-use one below it instead.
    let (Some(reference), Some(length)) = (u64_at(out, 0), u32_at(out, 8))
    else {
        return Err(io::Error::other("short file record"));
    };
    if reference & REFERENCE != u64::from(number) {
        return Ok(None);
    }
    match out.get(AT..AT + length as usize) {
        Some(record) if record.len() == geometry.record => {
            Ok(Some(record.to_vec()))
        }
        _ => Err(io::Error::other("unexpected file record length")),
    }
}

/// A kept tree being written, which a scan waits for before it reads one.
static SAVING: Mutex<Option<JoinHandle<()>>> = Mutex::new(None);

/// Wait until the last scan's tree is on disk.
pub fn wait_for_saved() {
    let saving = crate::scan::lock(&SAVING).take();
    if let Some(saving) = saving {
        let _ = saving.join();
    }
}

/// Write the tree `make` makes for the next scan, on a thread of its own,
/// then free it: making it and writing it are work the caller need not
/// wait out, and hundreds of megabytes to free.
pub(super) fn save_later(
    file: PathBuf,
    geometry: &Geometry,
    options: &ScanOptions,
    checkpoint: Checkpoint,
    make: impl FnOnce() -> Option<Flat> + Send + 'static,
) {
    let serial = geometry.serial;
    let record = geometry.record;
    let key = key(options);
    let spawned = std::thread::Builder::new().spawn(move || {
        if let Some(tree) = make() {
            let _ = save(&file, serial, record, key, &tree, &checkpoint);
        }
    });
    if let Ok(handle) = spawned {
        *crate::scan::lock(&SAVING) = Some(handle);
    }
}

/// The options a kept tree was made with, which a scan resuming from it
/// must share: each changes what the tree holds, or its order.
fn key(options: &ScanOptions) -> u64 {
    u64::from(options.apparent_size)
        | u64::from(options.include_hidden) << 1
        | u64::from(options.dedup_hardlinks) << 2
        | u64::from(options.metric == Metric::Files) << 3
}

/// Header: magic, serial, record size, journal, next, the options, and
/// the counts of directories, entries and name bytes, then the checksum of
/// all that follows.
const HEADER: usize = 8 * 10;
const DIR: usize = 52;
const ITEM: usize = 30;

/// Bytes per write, and per stretch of the checksum. Two writes of a
/// hundred megabytes and more took a table 427 ms to write; in pieces of a
/// megabyte one took 163-190 ms (`ArenaFable`'s measurement).
const PIECE: usize = 1 << 20;

/// The parts of the file, as the checksum tells them apart.
const DIRS: u64 = 1;
const ITEMS: u64 = 2;
const TEXT: u64 = 3;

fn encode_dir(dir: &Dir, out: &mut [u8]) {
    out[0..4].copy_from_slice(&dir.record.to_le_bytes());
    out[4..6].copy_from_slice(&dir.sequence.to_le_bytes());
    out[6..10].copy_from_slice(&dir.first.to_le_bytes());
    out[10..14].copy_from_slice(&dir.len.to_le_bytes());
    out[14..18].copy_from_slice(&dir.parent.to_le_bytes());
    out[18] = dir.category;
    out[19] = dir.reclaim;
    out[20..28].copy_from_slice(&dir.bytes.to_le_bytes());
    out[28..36].copy_from_slice(&dir.files.to_le_bytes());
    out[36..44].copy_from_slice(&dir.dirs.to_le_bytes());
    out[44..52].copy_from_slice(&dir.modified.to_le_bytes());
}

fn decode_dir(bytes: &[u8]) -> Dir {
    Dir {
        record: u32_at(bytes, 0).unwrap_or(NONE),
        sequence: u16_at(bytes, 4).unwrap_or(0),
        first: u32_at(bytes, 6).unwrap_or(0),
        len: u32_at(bytes, 10).unwrap_or(0),
        parent: u32_at(bytes, 14).unwrap_or(NONE),
        category: bytes.get(18).copied().unwrap_or(0),
        reclaim: bytes.get(19).copied().unwrap_or(0),
        bytes: u64_at(bytes, 20).unwrap_or(0),
        files: u64_at(bytes, 28).unwrap_or(0),
        dirs: u64_at(bytes, 36).unwrap_or(0),
        modified: u64_at(bytes, 44).unwrap_or(0).cast_signed(),
    }
}

fn encode_item(item: &Item, out: &mut [u8]) {
    out[0..4].copy_from_slice(&item.record.to_le_bytes());
    out[4..6].copy_from_slice(&item.sequence.to_le_bytes());
    out[6..10].copy_from_slice(&item.at.to_le_bytes());
    out[10..12].copy_from_slice(&item.len.to_le_bytes());
    out[12] = item.kind;
    out[13] = u8::from(item.shared);
    out[14..22].copy_from_slice(&item.value.to_le_bytes());
    out[22..30].copy_from_slice(&item.modified.to_le_bytes());
}

fn decode_item(bytes: &[u8]) -> Item {
    Item {
        record: u32_at(bytes, 0).unwrap_or(0),
        sequence: u16_at(bytes, 4).unwrap_or(0),
        at: u32_at(bytes, 6).unwrap_or(0),
        len: u16_at(bytes, 10).unwrap_or(0),
        // Not a kind: a tree that holds it is refused.
        kind: bytes.get(12).copied().unwrap_or(u8::MAX),
        shared: bytes.get(13).is_some_and(|&shared| shared != 0),
        value: u64_at(bytes, 14).unwrap_or(0),
        modified: u64_at(bytes, 22).unwrap_or(0).cast_signed(),
    }
}

fn save(
    file: &Path,
    serial: u64,
    record: usize,
    key: u64,
    tree: &Flat,
    checkpoint: &Checkpoint,
) -> io::Result<()> {
    if let Some(dir) = file.parent() {
        std::fs::create_dir_all(dir)?;
    }
    // Written whole under another name, then renamed over the old one: a
    // scan stopped halfway leaves the last good tree.
    let partial = file.with_extension("partial");
    let mut out = File::create(&partial)?;
    // Its whole length first: grown a piece at a time, the file cost the
    // file system an extension per megabyte.
    let length = HEADER
        + tree.dirs.len() * DIR
        + tree.items.len() * ITEM
        + tree.text.len();
    out.set_len(length as u64)?;
    // The header goes in last, once the checksum is known.
    out.write_all(&[0; HEADER])?;
    let mut piece = Vec::with_capacity(PIECE);
    let mut sum =
        write_region(&mut out, &tree.dirs, DIR, DIRS, encode_dir, &mut piece)?;
    sum ^= write_region(
        &mut out,
        &tree.items,
        ITEM,
        ITEMS,
        encode_item,
        &mut piece,
    )?;
    for (index, part) in tree.text.chunks(PIECE).enumerate() {
        sum ^= checksum(TEXT, index, part);
        out.write_all(part)?;
    }
    let mut header = Vec::with_capacity(HEADER);
    header.extend_from_slice(&MAGIC);
    for value in [
        serial,
        record as u64,
        checkpoint.journal,
        checkpoint.next,
        key,
        tree.dirs.len() as u64,
        tree.items.len() as u64,
        tree.text.len() as u64,
        sum,
    ] {
        header.extend_from_slice(&value.to_le_bytes());
    }
    out.seek(SeekFrom::Start(0))?;
    out.write_all(&header)?;
    drop(out);
    std::fs::rename(&partial, file)
}

/// Write `records`, `size` bytes each, a piece at a time through `piece`;
/// returns their checksum.
fn write_region<T: Sync>(
    out: &mut File,
    records: &[T],
    size: usize,
    region: u64,
    encode: impl Fn(&T, &mut [u8]) + Sync,
    piece: &mut Vec<u8>,
) -> io::Result<u64> {
    let mut sum = 0;
    for (index, records) in records.chunks(PIECE / size).enumerate() {
        piece.resize(records.len() * size, 0);
        piece
            .par_chunks_exact_mut(size)
            .zip(records.par_iter())
            .for_each(|(out, record)| encode(record, out));
        sum ^= checksum(region, index, piece);
        out.write_all(piece)?;
    }
    Ok(sum)
}

/// The tree kept in `file`, if it is of this volume and these options and
/// `journal` still reaches back to where it left off.
fn load(
    file: &Path,
    geometry: &Geometry,
    journal: Journal,
    key: u64,
) -> Option<(Flat, Checkpoint)> {
    let kept = open(file, geometry, journal, key)?;
    let flat = body(file, &kept)?;
    Some((flat, kept.checkpoint))
}

/// A kept tree's header, read and checked before its body.
struct Kept {
    dirs: usize,
    items: usize,
    text: usize,
    /// The checksum the whole file must have.
    sum: u64,
    checkpoint: Checkpoint,
}

/// The header of the tree kept in `file`: see [`load`].
fn open(
    file: &Path,
    geometry: &Geometry,
    journal: Journal,
    key: u64,
) -> Option<Kept> {
    let mut input = File::open(file).ok()?;
    let mut header = [0_u8; HEADER];
    input.read_exact(&mut header).ok()?;
    if header[..8] != MAGIC {
        return None;
    }
    let value = |index: usize| u64_at(&header, 8 * (index + 1));
    let count = |index: usize| usize::try_from(value(index)?).ok();
    if value(0)? != geometry.serial
        || value(1)? != geometry.record as u64
        || value(4)? != key
    {
        return None;
    }
    let next = value(3)?;
    if value(2)? != journal.id || next < journal.first || next > journal.next {
        return None;
    }
    let (dirs, items, text) = (count(5)?, count(6)?, count(7)?);
    // Sizes checked against the file before anything is allocated for
    // them: a corrupt count must not ask for terabytes.
    let length = dirs
        .checked_mul(DIR)?
        .checked_add(items.checked_mul(ITEM)?)?
        .checked_add(text)?
        .checked_add(HEADER)?;
    if length != usize::try_from(input.metadata().ok()?.len()).ok()?
        || [dirs, items, text]
            .iter()
            .any(|&count| count > u32::MAX as usize)
    {
        return None;
    }
    Some(Kept {
        dirs,
        items,
        text,
        sum: value(8)?,
        checkpoint: Checkpoint {
            journal: journal.id,
            next,
        },
    })
}

/// The tree itself, if it matches its checksum and is a tree.
fn body(file: &Path, kept: &Kept) -> Option<Flat> {
    let mut at = HEADER;
    // Room to grow: a patch appends, and growing a list of millions past
    // its capacity copies it whole.
    let (dirs, mut found) = read_region(
        file,
        at,
        kept.dirs,
        DIR,
        DIRS,
        kept.dirs / 32,
        decode_dir,
    )?;
    at += kept.dirs * DIR;
    let (items, sum) = read_region(
        file,
        at,
        kept.items,
        ITEM,
        ITEMS,
        kept.items / 32,
        decode_item,
    )?;
    found ^= sum;
    at += kept.items * ITEM;
    let mut text = Vec::with_capacity(kept.text + kept.text / 32);
    text.resize(kept.text, 0);
    found ^= text
        .par_chunks_mut(PIECE)
        .enumerate()
        .map(|(index, piece)| {
            let offset = (at + index * PIECE) as u64;
            File::open(file).ok()?.seek_read_exact(piece, offset).ok()?;
            Some(checksum(TEXT, index, piece))
        })
        .collect::<Option<Vec<u64>>>()?
        .into_iter()
        .fold(0, |sum, piece| sum ^ piece);
    let flat = Flat { dirs, items, text };
    (found == kept.sum && flat.is_valid()).then_some(flat)
}

/// `count` records of `size` bytes at `offset` in `file`, read a piece at
/// a time on every thread, through a handle of each thread's own, and
/// decoded as they come: no copy of the file's bytes is kept. With their
/// checksum.
fn read_region<T: Clone + Default + Send + Sync>(
    file: &Path,
    offset: usize,
    count: usize,
    size: usize,
    region: u64,
    spare: usize,
    decode: impl Fn(&[u8]) -> T + Sync + Send,
) -> Option<(Vec<T>, u64)> {
    let per = PIECE / size;
    let mut records = Vec::with_capacity(count + spare);
    records.par_extend(rayon::iter::repeat_n(T::default(), count));
    let sums = records
        .par_chunks_mut(per)
        .enumerate()
        .map_init(
            || (File::open(file).ok(), Vec::new()),
            |(input, bytes), (index, records)| {
                bytes.resize(records.len() * size, 0);
                let offset = (offset + index * per * size) as u64;
                input.as_ref()?.seek_read_exact(bytes, offset).ok()?;
                for (record, raw) in
                    records.iter_mut().zip(bytes.chunks_exact(size))
                {
                    *record = decode(raw);
                }
                Some(checksum(region, index, bytes))
            },
        )
        .collect::<Option<Vec<u64>>>()?;
    Some((records, sums.into_iter().fold(0, |sum, piece| sum ^ piece)))
}

/// A check a torn or damaged piece of the file fails. Four lanes of
/// 64-bit words, so the multiplies overlap: a quarter of the time one
/// chain of them took.
fn checksum(region: u64, index: usize, bytes: &[u8]) -> u64 {
    const MIX: u64 = 0x9E37_79B9_7F4A_7C15;
    let seed = (region << 48) ^ index as u64;
    let mut lanes =
        [seed, seed ^ 1, seed ^ 2, seed ^ 3].map(|lane| lane.wrapping_mul(MIX));
    let mut blocks = bytes.chunks_exact(32);
    for block in &mut blocks {
        for (lane, word) in lanes.iter_mut().zip(block.chunks_exact(8)) {
            let word = u64::from_le_bytes(word.try_into().unwrap_or_default());
            *lane = (lane.rotate_left(23) ^ word).wrapping_mul(MIX);
        }
    }
    let mut sum = lanes.iter().fold(bytes.len() as u64, |sum, &lane| {
        (sum.rotate_left(17) ^ lane).wrapping_mul(MIX)
    });
    for &byte in blocks.remainder() {
        sum = (sum.rotate_left(8) ^ u64::from(byte)).wrapping_mul(MIX);
    }
    sum
}

#[cfg(test)]
mod tests {
    use super::super::flat::{DIRECTORY, FILE};
    use super::*;

    const JOURNAL: Journal = Journal {
        id: 0xABCD,
        first: 1000,
        next: 200_000,
    };

    fn geometry(serial: u64) -> Geometry {
        Geometry {
            cluster: 4096,
            record: 1024,
            mft_offset: 0,
            volume: 1 << 30,
            serial,
        }
    }

    /// The root holding `sub` and `résumé.txt`, a file with two names, and
    /// `sub` holding `file.txt`.
    fn tree() -> Flat {
        let dir = |record, first, len, parent, bytes| Dir {
            record,
            sequence: 1,
            first,
            len,
            parent,
            category: 8,
            reclaim: 0,
            bytes,
            files: len.into(),
            dirs: 1,
            modified: 9,
        };
        let item = |record, at, len, kind, value| Item {
            record,
            sequence: 3,
            at,
            len,
            kind,
            shared: record == 30,
            value,
            modified: 7,
        };
        Flat {
            dirs: vec![dir(5, 0, 2, NONE, 12_288), dir(20, 2, 1, 0, 4096)],
            items: vec![
                item(30, 3, 12, FILE, 8192),
                item(20, 0, 3, DIRECTORY, 1),
                item(31, 15, 8, FILE, 4096),
            ],
            text: "subr\u{e9}sum\u{e9}.txtfile.txt".as_bytes().to_vec(),
        }
    }

    #[test]
    fn a_kept_tree_reads_back_as_written_and_a_damaged_one_not_at_all() {
        let options = ScanOptions::default();
        let checkpoint = Checkpoint {
            journal: 0xABCD,
            next: 123_456,
        };
        let dir = tempfile::TempDir::new().expect("tempdir");
        let file = file(dir.path(), 'C');
        let key = key(&options);
        let saved = tree();
        assert!(saved.is_valid());
        save(&file, 7, 1024, key, &saved, &checkpoint).expect("saved");

        let (loaded, kept) =
            load(&file, &geometry(7), JOURNAL, key).expect("loads");
        assert_eq!(
            (&loaded.dirs, &loaded.items, &loaded.text),
            (&saved.dirs, &saved.items, &saved.text)
        );
        assert_eq!((kept.journal, kept.next), (0xABCD, 123_456));

        // Another volume's, a table of another record size, or a scan
        // with other options is not this one's.
        assert!(load(&file, &geometry(8), JOURNAL, key).is_none());
        let other = Geometry {
            record: 4096,
            ..geometry(7)
        };
        assert!(load(&file, &other, JOURNAL, key).is_none());
        let apparent = ScanOptions {
            apparent_size: true,
            ..ScanOptions::default()
        };
        assert!(
            load(&file, &geometry(7), JOURNAL, super::key(&apparent)).is_none()
        );
        // Nor is one the journal no longer reaches back to, or another
        // journal's.
        let wrapped = Journal {
            first: 200_000,
            ..JOURNAL
        };
        assert!(load(&file, &geometry(7), wrapped, key).is_none());
        let remade = Journal { id: 1, ..JOURNAL };
        assert!(load(&file, &geometry(7), remade, key).is_none());

        // A damaged byte fails the checksum; a short file its length.
        let bytes = std::fs::read(&file).expect("read");
        let mut damaged = bytes.clone();
        let middle = damaged.len() / 2 + HEADER / 2;
        damaged[middle] ^= 0x10;
        std::fs::write(&file, &damaged).expect("write");
        assert!(load(&file, &geometry(7), JOURNAL, key).is_none());
        std::fs::write(&file, &bytes[..bytes.len() - 1]).expect("write");
        assert!(load(&file, &geometry(7), JOURNAL, key).is_none());

        // Nor is one that is not a tree: a folder named twice would be
        // built twice, each time for every level such names repeat.
        let mut twice = tree();
        twice.items[0] = twice.items[1];
        assert!(!twice.is_valid());
        save(&file, 7, 1024, key, &twice, &checkpoint).expect("saved");
        assert!(load(&file, &geometry(7), JOURNAL, key).is_none());
        let mut elsewhere = tree();
        elsewhere.dirs[1].parent = 1;
        assert!(!elsewhere.is_valid());
    }
}
