//! Watching a folder that something outside disktree may still be
//! changing: a shell verb that carries on after its menu closes (a copy, an
//! unpack), or a terminal opened there.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use notify::{RecommendedWatcher, RecursiveMode, Watcher as _};

/// How long the folder must be quiet before it is read again: a copy or an
/// unpack writes in bursts, and reading mid-burst only means reading again.
const QUIET: Duration = Duration::from_secs(2);

/// When a watch gives up: a terminal can stay open all day, and a watch
/// nobody remembers starting should not keep reading the disk.
const LIMIT: Duration = Duration::from_mins(10);

/// One folder under watch. Dropping it stops the watch.
pub struct Watch {
    pub folder: PathBuf,
    started: Instant,
    /// When the folder last changed, if it has not been read since.
    changed: Arc<Mutex<Option<Instant>>>,
    _watcher: RecommendedWatcher,
}

/// What a watch wants done now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tick {
    Wait,
    Refresh,
    Expired,
}

impl Watch {
    /// Watch `folder` and everything beneath it.
    pub fn start(folder: PathBuf) -> notify::Result<Self> {
        let changed = Arc::new(Mutex::new(None));
        let mut watcher = notify::recommended_watcher({
            let changed = Arc::clone(&changed);
            move |event: notify::Result<notify::Event>| {
                // Reading the folder again is itself an access; counting it
                // would refresh forever. An error (a lost event, an
                // overflow) may hide a change, so it counts as one.
                if !matches!(&event, Ok(event) if event.kind.is_access()) {
                    *changed.lock().unwrap_or_else(PoisonError::into_inner) =
                        Some(Instant::now());
                }
            }
        })?;
        watcher.watch(&folder, RecursiveMode::Recursive)?;
        Ok(Self {
            folder,
            started: Instant::now(),
            changed,
            _watcher: watcher,
        })
    }

    /// What to do at `now`. A refresh it asks for is taken: the change that
    /// called for it is forgotten.
    pub fn tick(&self, now: Instant) -> Tick {
        let mut changed =
            self.changed.lock().unwrap_or_else(PoisonError::into_inner);
        let tick = decide(self.started, *changed, now);
        if tick == Tick::Refresh {
            *changed = None;
        }
        tick
    }
}

/// A change waits out [`QUIET`] before it is read. One that has settled is
/// read even past [`LIMIT`], so the last burst is not lost; a folder that
/// never goes quiet is given up on all the same.
fn decide(started: Instant, changed: Option<Instant>, now: Instant) -> Tick {
    match changed {
        Some(at) if now.saturating_duration_since(at) >= QUIET => Tick::Refresh,
        _ if now.saturating_duration_since(started) >= LIMIT => Tick::Expired,
        _ => Tick::Wait,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_change_is_read_once_the_folder_is_quiet_and_the_watch_ends() {
        let start = Instant::now();
        let at = |seconds| start + Duration::from_secs(seconds);
        assert_eq!(decide(start, None, at(1)), Tick::Wait);
        // A burst still going on waits.
        assert_eq!(decide(start, Some(at(5)), at(6)), Tick::Wait);
        assert_eq!(decide(start, Some(at(5)), at(7)), Tick::Refresh);
        // The last change to settle is still read; one still going is not
        // waited on past the limit.
        assert_eq!(decide(start, Some(at(599)), at(601)), Tick::Refresh);
        assert_eq!(decide(start, Some(at(600)), at(601)), Tick::Expired);
        assert_eq!(decide(start, None, at(600)), Tick::Expired);
    }
}
