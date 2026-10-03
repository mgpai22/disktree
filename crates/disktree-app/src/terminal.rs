//! "Open terminal here": the platform's own terminal, started in a folder.

use std::io;
use std::path::Path;
use std::process::{Child, Command};

/// Start a terminal whose working directory is `dir`. An elevated disktree
/// starts an elevated terminal, which is what someone cleaning a disk as
/// administrator wants next.
pub fn open(dir: &Path) -> io::Result<()> {
    let child = spawn(dir)?;
    // Nothing waits on the terminal, but on Unix an exited child stays a
    // zombie until someone does; a thread that only waits costs nothing.
    std::thread::spawn(move || wait(child));
    Ok(())
}

fn wait(mut child: Child) {
    let _ = child.wait();
}

#[cfg(windows)]
fn spawn(dir: &Path) -> io::Result<Child> {
    use std::os::windows::process::CommandExt as _;

    /// `CREATE_NEW_CONSOLE`: `cmd` would otherwise share disktree's console,
    /// which a windowed program started from Explorer does not have.
    const NEW_CONSOLE: u32 = 0x10;

    if on_path("wt.exe") {
        return Command::new("wt.exe").arg("-d").arg(dir).spawn();
    }
    // `current_dir` rather than `cd /d <dir>`: no quoting of the path for
    // cmd's own parser to get wrong.
    Command::new("cmd.exe")
        .arg("/K")
        .current_dir(dir)
        .creation_flags(NEW_CONSOLE)
        .spawn()
}

/// Whether `program` is in a `PATH` directory. Windows Terminal is an app
/// execution alias, a reparse point that following would fail on, so the
/// entry is looked at without following it.
#[cfg(windows)]
fn on_path(program: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path)
            .any(|dir| std::fs::symlink_metadata(dir.join(program)).is_ok())
    })
}

#[cfg(target_os = "macos")]
fn spawn(dir: &Path) -> io::Result<Child> {
    Command::new("open")
        .args(["-a", "Terminal"])
        .arg(dir)
        .spawn()
}

#[cfg(all(unix, not(target_os = "macos")))]
fn spawn(dir: &Path) -> io::Result<Child> {
    let terminal = std::env::var_os("TERMINAL")
        .filter(|terminal| !terminal.is_empty())
        .unwrap_or_else(|| "x-terminal-emulator".into());
    Command::new(terminal).current_dir(dir).spawn()
}
