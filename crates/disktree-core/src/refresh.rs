//! Reading one folder of a tree again, in place: what an action on that
//! folder changed, without walking the whole root.

use std::io;
use std::path::Path;
use std::sync::Arc;

use super::{ScanOptions, ScanProgress, WalkContext, scan_blocking};
use crate::classify::classify_where;
use crate::tree::{IDENTIFIED, NONE, Tree, name_in};

/// Re-walk `folder`, which lies beneath `root_path` (the path `tree` was
/// scanned from), with the walk's rules, and return `tree` with that
/// folder's subtree replaced and every ancestor's totals updated.
///
/// Only the folder is walked: never from the file table, and nothing kept
/// on disk is resumed or saved. A folder gone from disk leaves its parent.
/// Errors for `root_path` itself (scan it whole instead), a path outside
/// it, and one the tree holds no folder at.
///
/// Hardlinks count once within the folder only: a file with another name
/// outside it is charged there too, until a whole scan.
pub fn refresh_folder(
    tree: &Tree,
    root_path: &Path,
    folder: &Path,
    options: &ScanOptions,
) -> io::Result<Tree> {
    let relative = folder.strip_prefix(root_path).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "{} is not beneath {}",
                folder.display(),
                root_path.display()
            ),
        )
    })?;
    let chain = chain(tree, relative).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::NotFound,
            format!("{} is no folder of the tree", folder.display()),
        )
    })?;
    let (&target, ancestors) = chain.split_last().unwrap_or((&0, &[]));
    if ancestors.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the scanned root is refreshed by scanning it whole",
        ));
    }

    let mut options = options.clone();
    // The walk starts at the folder, so a depth limit counts from there.
    options.max_depth = options
        .max_depth
        .map(|most| most.saturating_sub(ancestors.len()));
    let mut context =
        WalkContext::new(None, options, Arc::new(ScanProgress::default()));
    context.plain = true;
    let metric = context.options.metric;
    let walked = scan_blocking(folder, &Arc::new(context));

    let mut out = tree.clone();
    let fresh_from = out.dirs.len();
    match walked {
        Ok(fresh) => splice(&mut out, target, Arc::unwrap_or_clone(fresh)),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            remove(&mut out, ancestors[ancestors.len() - 1], target);
        }
        Err(error) => return Err(error),
    }
    for &index in ancestors.iter().rev() {
        out.settle(index, metric);
    }
    let mut touched = vec![false; out.dirs.len()];
    for &index in &chain {
        touched[index as usize] = true;
    }
    touched[fresh_from..].fill(true);
    classify_where(&mut out, Some(&touched));
    Ok(out)
}

/// The directories from the root down to the one at `relative`, by
/// index; `None` where a name is no directory of the tree.
fn chain(tree: &Tree, relative: &Path) -> Option<Vec<u32>> {
    let mut chain = vec![0_u32];
    for component in relative.components() {
        let name = component.as_os_str().to_string_lossy();
        let dir = tree.dirs.get(*chain.last()? as usize)?;
        let text = &tree.segs.get(dir.seg as usize)?.text;
        let item = tree
            .run(dir)
            .iter()
            .find(|item| item.is_dir() && name_in(text, item) == name)?;
        chain.push(u32::try_from(item.value).ok()?);
    }
    Some(chain)
}

/// Drop every directory beneath `top` from the tree, `top` too when
/// `with_top`. Their runs stay where they are, unreached.
///
/// ponytail: what a refresh drops stays in memory until the next whole
/// scan; compact the tree if repeated refreshes ever weigh.
fn drop_beneath(tree: &mut Tree, top: u32, with_top: bool) {
    let mut stack = vec![top];
    while let Some(index) = stack.pop() {
        let Some(&dir) = tree.dirs.get(index as usize) else {
            continue;
        };
        if index != top || with_top {
            // Dropped already: a loop, which no tree has, ends here.
            if dir.parent == NONE {
                continue;
            }
            tree.dirs[index as usize].parent = NONE;
        }
        stack.extend(
            tree.run(&dir)
                .iter()
                .filter(|item| item.is_dir())
                .map(|item| item.value as u32),
        );
    }
}

/// Put the walked `fresh` tree in place of directory `target`: its root
/// takes `target`'s index, its other directories and segments go after
/// the tree's own, and its devices are numbered as the tree numbers them.
fn splice(tree: &mut Tree, target: u32, fresh: Tree) {
    drop_beneath(tree, target, false);
    let base = tree.dirs.len() as u32;
    let segs = tree.segs.len() as u32;
    let place = |index: u64| {
        if index == 0 {
            target
        } else {
            base + index as u32 - 1
        }
    };
    let volumes: Vec<Option<u16>> = fresh
        .volumes
        .iter()
        .map(|&device| tree.intern(device))
        .collect();
    let renumber = |volume: &mut u16, flags: &mut u8| {
        if *flags & IDENTIFIED == 0 {
            return;
        }
        match volumes.get(usize::from(*volume)).copied().flatten() {
            Some(number) => *volume = number,
            None => *flags &= !IDENTIFIED,
        }
    };
    for mut seg in fresh.segs {
        for item in &mut seg.items {
            if item.is_dir() {
                item.value = u64::from(place(item.value));
            } else {
                renumber(&mut item.volume, &mut item.flags);
            }
        }
        tree.segs.push(seg);
    }
    let parent = tree.dirs[target as usize].parent;
    for (index, mut dir) in fresh.dirs.into_iter().enumerate() {
        dir.seg += segs;
        renumber(&mut dir.volume, &mut dir.flags);
        if index == 0 {
            dir.parent = parent;
            tree.dirs[target as usize] = dir;
        } else {
            dir.parent = if dir.parent == NONE {
                NONE
            } else {
                place(u64::from(dir.parent))
            };
            tree.dirs.push(dir);
        }
    }
}

/// Take directory `target`, gone from disk, out of `parent`'s entries.
fn remove(tree: &mut Tree, parent: u32, target: u32) {
    drop_beneath(tree, target, true);
    let dir = tree.dirs[parent as usize];
    let start = dir.first as usize;
    let Some(run) = tree
        .segs
        .get_mut(dir.seg as usize)
        .and_then(|seg| seg.items.get_mut(start..start + dir.len as usize))
    else {
        return;
    };
    if let Some(at) = run
        .iter()
        .position(|item| item.is_dir() && item.value == u64::from(target))
    {
        // The run closes up; the slot left at its end is never read.
        run.copy_within(at + 1.., at);
        tree.dirs[parent as usize].len -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::Node;
    use std::fs;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn options() -> ScanOptions {
        ScanOptions {
            apparent_size: true,
            ..ScanOptions::default()
        }
    }

    fn write(root: &Path, relative: &str, bytes: usize) {
        let path = root.join(relative);
        fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        fs::write(&path, vec![b'x'; bytes]).expect("write");
    }

    fn scanned(root: &Path) -> Tree {
        Arc::unwrap_or_clone(super::super::scan(root, options()).expect("scan"))
    }

    fn at<'a>(tree: &'a Tree, path: &[&str]) -> Node<'a> {
        path.iter().fold(tree.root(), |node, name| {
            node.child_named(name).expect("child")
        })
    }

    /// Every node's path, size, files and folders, in the order shown.
    fn lines(node: Node<'_>, path: &str, out: &mut Vec<String>) {
        out.push(format!(
            "{path} {} {} {}",
            node.bytes(),
            node.files(),
            node.dirs()
        ));
        for child in node.children() {
            lines(child, &format!("{path}/{}", child.name()), out);
        }
    }

    fn describe(tree: &Tree) -> Vec<String> {
        let mut out = Vec::new();
        lines(tree.root(), "", &mut out);
        out
    }

    fn setup() -> (TempDir, PathBuf, Tree) {
        let temp = TempDir::new().expect("tempdir");
        let root = temp.path().to_path_buf();
        write(&root, "a/b/one.bin", 1000);
        write(&root, "a/b/two.bin", 2000);
        write(&root, "a/b/deep/three.bin", 300);
        write(&root, "a/side.bin", 50);
        write(&root, "c/other.bin", 4000);
        let tree = scanned(&root);
        (temp, root, tree)
    }

    #[test]
    fn a_refreshed_folder_matches_a_whole_scan() {
        let (_temp, root, tree) = setup();
        write(&root, "a/b/one.bin", 5000);
        fs::remove_file(root.join("a/b/two.bin")).expect("rm");
        write(&root, "a/b/new/four.bin", 700);
        fs::remove_dir_all(root.join("a/b/deep")).expect("rm");

        let refreshed =
            refresh_folder(&tree, &root, &root.join("a/b"), &options())
                .expect("refresh");
        assert_eq!(describe(&refreshed), describe(&scanned(&root)));
        let a = at(&refreshed, &["a"]);
        assert_eq!(a.bytes(), 5000 + 700 + 50);
        assert_eq!(refreshed.root().bytes(), 5000 + 700 + 50 + 4000);
    }

    #[test]
    fn what_lies_outside_the_folder_is_not_read_again() {
        let (_temp, root, tree) = setup();
        write(&root, "c/other.bin", 10);
        write(&root, "a/side.bin", 10);
        write(&root, "a/b/one.bin", 1);

        let refreshed =
            refresh_folder(&tree, &root, &root.join("a/b"), &options())
                .expect("refresh");
        let other = at(&refreshed, &["c", "other.bin"]);
        assert_eq!(other.bytes(), 4000);
        assert_eq!(at(&refreshed, &["a", "side.bin"]).bytes(), 50);
        assert_eq!(at(&refreshed, &["a", "b", "one.bin"]).bytes(), 1);
        assert_eq!(refreshed.root().bytes(), 4000 + 50 + 1 + 2000 + 300);
    }

    #[test]
    fn a_folder_gone_from_disk_leaves_the_tree() {
        let (_temp, root, tree) = setup();
        fs::remove_dir_all(root.join("a/b")).expect("rm");

        let refreshed =
            refresh_folder(&tree, &root, &root.join("a/b"), &options())
                .expect("refresh");
        assert!(at(&refreshed, &["a"]).child_named("b").is_none());
        assert_eq!(describe(&refreshed), describe(&scanned(&root)));
    }

    #[test]
    fn the_root_and_paths_outside_it_are_refused() {
        let (temp, root, tree) = setup();
        let outside = temp.path().parent().expect("parent").to_path_buf();
        assert!(refresh_folder(&tree, &root, &outside, &options()).is_err());
        assert!(refresh_folder(&tree, &root, &root, &options()).is_err());
        let file = root.join("a/side.bin");
        assert!(refresh_folder(&tree, &root, &file, &options()).is_err());
    }
}
