//! Running another program with a time limit (`describe --json`, `verify-log`), without a console window on
//! Windows and without ever waiting forever: on timeout the child is killed and the result says so.

use std::ffi::OsStr;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// What a finished (or killed) child produced.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Output {
    /// Exit code; None when killed by a signal or by the timeout.
    pub code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub timed_out: bool,
    pub elapsed_ms: u64,
}

/// Runs `exe args…` with stdin closed, captures stdout/stderr and kills it after `timeout`.
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
    let started = Instant::now();
    let mut child = cmd.spawn()?;
    let pipe = |r: Option<Box<dyn Read + Send>>| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            if let Some(mut r) = r {
                let _ = r.read_to_end(&mut buf);
            }
            buf
        })
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
    let mut timed_out = false;
    let status = loop {
        if let Some(s) = child.try_wait()? {
            break Some(s);
        }
        if started.elapsed() >= timeout {
            timed_out = true;
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    // After a timeout a grandchild may still hold the pipes open: do not wait for the readers then.
    let (stdout, stderr) = if timed_out {
        (Vec::new(), Vec::new())
    } else {
        (
            out.join().unwrap_or_default(),
            err.join().unwrap_or_default(),
        )
    };
    Ok(Output {
        code: status.and_then(|s| s.code()),
        stdout,
        stderr,
        timed_out,
        elapsed_ms: started.elapsed().as_millis() as u64,
    })
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
}
