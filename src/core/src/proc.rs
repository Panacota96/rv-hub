//! Running another program with a time limit (`describe --json`, `verify-log`), without a console window on
//! Windows and without ever waiting forever: on timeout the child is killed and the result says so.

use std::ffi::OsStr;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};

/// What a finished (or killed) child produced.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Output {
    /// Exit code of the child; None when killed by a signal or by the timeout.
    pub code: Option<i32>,
    /// What was read; after a timeout, what was read by the deadline.
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// The deadline passed before the child exited, or before its stdout/stderr were closed (a descendant still
    /// holding them). The output may then be incomplete.
    pub timed_out: bool,
    pub elapsed_ms: u64,
}

/// Runs `exe args…` with stdin closed, captures stdout/stderr and kills it after `timeout`. The deadline bounds
/// the whole call, the reading of the pipes included: a descendant that keeps them open does not hold it up. On
/// Unix the child gets its own process group, and the whole group is killed on timeout.
/// Err only when it cannot be started.
pub fn run<S: AsRef<OsStr>>(exe: &Path, args: &[S], timeout: Duration) -> std::io::Result<Output> {
    let mut cmd = Command::new(exe);
    cmd.args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0);
    }
    let started = Instant::now();
    let deadline = started + timeout;
    let mut child = cmd.spawn()?;
    // Each reader appends to its buffer as it reads and says on `done` when its pipe is closed.
    let (done_tx, done_rx) = mpsc::channel::<()>();
    let pipe = |r: Option<Box<dyn Read + Send>>| {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let (b, tx) = (buf.clone(), done_tx.clone());
        std::thread::spawn(move || {
            if let Some(mut r) = r {
                let mut chunk = [0u8; 8192];
                loop {
                    match r.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(n) => b
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .extend_from_slice(&chunk[..n]),
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(_) => break,
                    }
                }
            }
            let _ = tx.send(());
        });
        buf
    };
    let out = pipe(
        child
            .stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    let err = pipe(
        child
            .stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn Read + Send>),
    );
    drop(done_tx);
    let mut timed_out = false;
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break Some(s);
        }
        if Instant::now() >= deadline {
            timed_out = true;
            kill(&mut child);
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    // Both pipes closed, within the same deadline (a descendant may still hold them after the child exited).
    let mut closed = 0;
    while closed < 2 && !timed_out {
        let left = deadline.saturating_duration_since(Instant::now());
        match done_rx.recv_timeout(left) {
            Ok(()) => closed += 1,
            Err(_) => {
                timed_out = true;
                kill(&mut child);
            }
        }
    }
    // After a timeout: a short, bounded drain of what was already written (the pipes close once the process
    // group is gone); whatever is still open after it is abandoned.
    if timed_out {
        let grace = Instant::now() + Duration::from_millis(200);
        while closed < 2 {
            let left = grace.saturating_duration_since(Instant::now());
            if done_rx.recv_timeout(left).is_err() {
                break;
            }
            closed += 1;
        }
    }
    let take =
        |b: &Arc<Mutex<Vec<u8>>>| std::mem::take(&mut *b.lock().unwrap_or_else(|e| e.into_inner()));
    Ok(Output {
        code: status.and_then(|s| s.code()),
        stdout: take(&out),
        stderr: take(&err),
        timed_out,
        elapsed_ms: started.elapsed().as_millis() as u64,
    })
}

/// Kills the child; on Unix its whole process group (it was started as the group's leader), so descendants that
/// still hold the pipes go too. Elsewhere only the child (a reaped child is not killed again).
fn kill(child: &mut std::process::Child) {
    #[cfg(unix)]
    if let Ok(pgid) = i32::try_from(child.id()) {
        use nix::sys::signal::{Signal, killpg};
        let _ = killpg(nix::unistd::Pid::from_raw(pgid), Signal::SIGKILL);
    }
    let _ = child.kill();
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn captures_output_and_kills_on_timeout() {
        let o = run(
            Path::new("/bin/sh"),
            &["-c", "echo hi; echo err >&2; exit 3"],
            Duration::from_secs(10),
        )
        .unwrap();
        assert_eq!((o.code, o.timed_out), (Some(3), false));
        assert_eq!(o.stdout, b"hi\n");
        assert_eq!(o.stderr, b"err\n");
        let o = run(
            Path::new("/bin/sh"),
            &["-c", "sleep 5"],
            Duration::from_millis(200),
        )
        .unwrap();
        assert!(o.timed_out && o.code.is_none() && o.elapsed_ms < 4000);
        assert!(
            run(
                Path::new("/nonexistent/exe"),
                &["x"],
                Duration::from_secs(1)
            )
            .is_err()
        );
    }

    /// Review P2: a descendant that keeps stdout/stderr open must not outlive the timeout.
    #[test]
    fn a_descendant_holding_the_pipes_does_not_outlive_the_timeout() {
        let o = run(
            Path::new("/bin/sh"),
            &["-c", "echo early; sleep 2 & exit 0"],
            Duration::from_millis(100),
        )
        .unwrap();
        assert!(o.timed_out, "{o:?}");
        assert!(o.elapsed_ms < 1500, "returned after {} ms", o.elapsed_ms);
        assert_eq!(
            o.stdout, b"early\n",
            "what was read by the deadline is returned"
        );
        // The descendant is killed with the process group: it never gets to write its marker.
        let d = tempfile::tempdir().unwrap();
        let marker = d.path().join("still-running");
        let script = format!("(sleep 1; touch '{}') & exit 0", marker.display());
        let o = run(
            Path::new("/bin/sh"),
            &["-c", script.as_str()],
            Duration::from_millis(100),
        )
        .unwrap();
        assert!(o.timed_out && o.elapsed_ms < 900, "{o:?}");
        std::thread::sleep(Duration::from_millis(1500));
        assert!(!marker.exists(), "the descendant outlived the timeout");
        // Timeout while the child itself still runs: its output so far is returned too.
        let o = run(
            Path::new("/bin/sh"),
            &["-c", "echo partial; sleep 5"],
            Duration::from_millis(300),
        )
        .unwrap();
        assert!(o.timed_out && o.elapsed_ms < 1500, "{o:?}");
        assert_eq!(o.stdout, b"partial\n");
    }
}
