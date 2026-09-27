//! Keeping a scan's finished tree for the next one: the flat tree a whole
//! read made, written to a file in the scan's cache directory, with where
//! the volume's change journal stood when the read began.

use std::fs::File;
use std::io::{self, Seek as _, SeekFrom, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::thread::JoinHandle;

use rayon::prelude::*;
use windows_sys::Win32::System::Ioctl::FSCTL_QUERY_USN_JOURNAL;

use super::flat::{Dir, Flat, Item};
use super::{Geometry, u64_at};
use crate::scan::ScanOptions;
use crate::tree::Metric;
use crate::windows::control;

/// Bumped whenever what a kept tree holds changes, so one kept by an
/// older build is read again rather than trusted.
const MAGIC: [u8; 8] = *b"dttree\x00\x02";

/// The volume's change journal: which one, and the number (`USN`) of its
/// next entry.
#[derive(Clone, Copy)]
pub(super) struct Journal {
    id: u64,
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
        next: u64_at(out, 16)?,
    })
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
