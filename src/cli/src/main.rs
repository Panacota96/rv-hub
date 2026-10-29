//! rv-hub command-line interface. All work happens in `rv_hub_core`; this file only
//! parses arguments, renders events (progress bar or JSON Lines) and maps results to exit codes.
//! (Core-engineer stage: the main verb `verify` and the template's commands; `tools`, `case` and `launch`
//! are added by the CLI stage on top of `rv_hub_core::{tools, case_view, suggest, launch}`.)

use clap::{Args, CommandFactory, Parser, Subcommand, ValueEnum};
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use rv_hub_core::trust::{self, DEFAULT_TSA};
use rv_hub_core::{
    CrossCheckMode, Event, HashAlgo, RunConfig, TOOL_NAME, TOOL_VERSION, audit, case, hash, i18n,
    run, verify,
};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

const EXIT_OK: u8 = 0;
const EXIT_ERROR: u8 = 1;
const EXIT_USAGE: u8 = 2;
const EXIT_FINDINGS: u8 = 3;
const EXIT_CANCELLED: u8 = 130;

const ABOUT: &str = "RV Hub, the main app of the Rakvor tools: verify a whole case folder (case log, every run's audit and review logs, optionally the evidence) and cross-check each run with its own tool.";

const LONG_ABOUT: &str = "\
DESCRIPTION:
  rv-hub verify checks a Rakvor case folder as a whole, without changing anything in it:
    1. the case log (case-log.jsonl): hash chain, case.json and the evidence-registry digest;
    2. every run folder runs/<TOOL>/<RUN-ID>: its audit.jsonl chain, its link with the case log
       (case_linked <-> run_started, the audit head recorded at run_finished), its RFC 3161
       timestamp tokens and, when present, its review.jsonl (anchored to run_finished);
    3. with --rehash, every registered evidence file, read again and compared with the registry.
  With --crosscheck auto (default) each run is also verified by the run's own tool
  (<tool> verify-log <run>/logs) when that tool is installed and signed by Rakvor; a different
  verdict is a high-severity finding (TOOL_VERIFY_DISAGREES).
  The verification is itself a run: reports and a hash-chained audit log are written to
  <CASE>/runs/rv-hub/<RUN-ID>/ and the run is recorded in the case log. No evidence input is
  needed: --case-dir is the only required option.";

const VERIFY_AFTER_HELP: &str = "\
EXAMPLES:
  Verify a case folder (logs and links; English reports):
    rv-hub verify --case-dir E:\\CASE-014
  Also re-hash every registered evidence file, Spanish reports, for the examiner Ana Ruiz:
    rv-hub verify --case-dir E:\\CASE-014 --rehash --lang es --actor \"Ana Ruiz\"
  The evidence copies were moved to another drive: look them up there by file name:
    rv-hub verify --case-dir E:\\CASE-014 --rehash --evidence-dir F:\\copies
  Re-hash two items only, without asking the tools, machine-readable progress:
    rv-hub verify --case-dir E:\\CASE-014 -E E0001,E0002 --crosscheck off --progress jsonl
  Cross-check with a tool that is not installed (e.g. a portable copy, any signature):
    rv-hub verify --case-dir E:\\CASE-014 --tool-exe rv-pdfauth=D:\\portable\\rv-pdfauth.exe

EXIT CODES:
  0    Completed; no high-severity finding (the case verifies).
  1    Runtime error (case log locked by another tool, output not writable, ...).
  2    Usage error (unknown option, bad value, not a case folder, --case of another case,
       unknown evidence id, malformed --tool-exe).
  3    Completed with at least one high-severity finding: a broken case log, run log or review
       log, a run missing from the case log, evidence that differs from the registry or cannot
       be found (--rehash), or a tool whose own verify-log disagrees with RV Hub.
  130  Cancelled with Ctrl+C. Partial reports and the cancellation are written to the audit log.

FILES WRITTEN:
  <CASE>/runs/rv-hub/<RUN-ID>/logs/audit.jsonl       Hash-chained log of every check (JSON Lines).
  <CASE>/runs/rv-hub/<RUN-ID>/logs/audit.log         The same actions, human-readable.
  <CASE>/runs/rv-hub/<RUN-ID>/logs/hashes.csv        Hash register of every file verified.
  <CASE>/runs/rv-hub/<RUN-ID>/logs/environment.json  Tool and dependency versions, OS, host, user.
  <CASE>/runs/rv-hub/<RUN-ID>/logs/timestamp-<SEQ>.tsr|.json  RFC 3161 token for the chain head.
  <CASE>/runs/rv-hub/<RUN-ID>/reports/statistics.json|.<LANG>.html|.<LANG>.pdf  Verification report.
  <CASE>/runs/rv-hub/<RUN-ID>/reports/items/<NNNNN>-<ITEM>/technical|summary|custody .json/.html/.pdf
                                                      One folder per item (case log, run, evidence).
  <CASE>/case-log.jsonl                              run_started and run_finished of this run are
                                                      appended (under case-log.lock); nothing else
                                                      in the case is written.
  When the case log itself fails verification it is never extended: logs/ and reports/ go to
  <OUT>/logs/<RUN-ID>/ and <OUT>/reports/<RUN-ID>/ instead (--out).

FORENSIC NOTES:
  - The case folder is read-only for RV Hub: every file is opened for reading; only the hub's own
    run folder and two case-log entries are written, after re-verifying the case log under the lock.
  - The checks use the same verifier code as the tools (hash chain, case log, timestamps, review
    log), and each run's own tool is asked for its verdict: one verifier lineage, checked twice.
  - Verification proves integrity, not content: an intact run log does not make a tool's findings
    correct, and a matching evidence hash does not make the evidence authentic.
  - Signatures of the tools are checked on Windows (Authenticode, chain to the Rakvor root); on
    other systems no tool is Rakvor-signed for the cross-check unless given with --tool-exe.
  - Each audit entry stores the SHA-256 of the previous one; editing, deleting or re-ordering any
    line is detected by `verify-log`. Removing the last lines is detected against the case log.
  - MD5 and SHA-1 are accepted for compatibility with older case files; pair them with SHA-256 or BLAKE3.
  - The chain head is timestamped by an RFC 3161 authority (proves when the log existed). Offline? The run
    finishes with `timestamp_pending`; run `rv-hub timestamp <LOG>` later.
  - With --sign-cert every PDF is signed with the examiner's certificate; the password is never logged.";

#[derive(Parser)]
#[command(name = TOOL_NAME, version = TOOL_VERSION, about = ABOUT, long_about = LONG_ABOUT, max_term_width = 100,
          after_long_help = "Run `rv-hub <COMMAND> --help` for the options, examples and exit codes of each command.")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Verify a whole case folder (case log, every run, optionally the evidence) and cross-check
    /// each run with its own tool.
    #[command(long_about = LONG_ABOUT, after_long_help = VERIFY_AFTER_HELP)]
    Verify(Box<VerifyArgs>),
    /// Verify an audit log (audit.jsonl): edited, deleted or re-ordered entries, and truncation.
    #[command(after_long_help = "\
CHECKS:
  - every entry links to the previous one (hash chain): an edited, deleted or re-ordered entry
    breaks it;
  - every timestamp token (timestamp-<SEQ>.tsr) covers the hash of the entry it names, and every
    timestamp_obtained entry still has its token file;
  - review.jsonl in the same folder (viewing after the run, written by rv-imgauth), when present,
    is an intact chain anchored to the run's run_finished entry (\"review entries: N\");
  - truncation: a chain alone cannot show that entries were removed from its end. The log must
    still contain the entry covered by its RFC 3161 timestamp (covers_seq) and, for a run inside
    a case folder (<CASE>/runs/<TOOL>/<RUN-ID>/logs), end with the audit head that the case log
    recorded at run_finished (only timestamp_obtained may follow). Entries after the last
    anchored one are listed as not provable; with neither record the output says
    \"truncation not detectable without a timestamp or case record\".

EXAMPLES:
  rv-hub verify-log rakvor-out/logs/20261019T101500Z-a1b2c3/audit.jsonl
  rv-hub verify-log rakvor-out/logs/20261019T101500Z-a1b2c3
  rv-hub verify-log E:\\CASE-014\\runs\\rv-hub\\20261019T101500Z-a1b2c3\\logs

EXIT CODES:
  0  The chain is intact and agrees with its timestamps and case record (if any).
  1  The log cannot be read.
  3  The chain is broken (an entry was edited, deleted or re-ordered), a timestamp does not
     match, or the log is shorter than its timestamp or case record says (truncated).")]
    VerifyLog {
        /// Path to audit.jsonl, or to the run's log folder that contains it.
        ///
        /// Example: rakvor-out/logs/20261019T101500Z-a1b2c3
        log: PathBuf,
    },
    /// Check every hash algorithm against known-answer test vectors.
    #[command(after_long_help = "\
EXAMPLES:
  rv-hub self-test

EXIT CODES:
  0  All algorithms give the published answer for the input \"abc\".
  1  At least one algorithm failed: do not use this build for evidence.")]
    SelfTest,
    /// Add an RFC 3161 timestamp to a finished run (e.g. after working offline).
    #[command(after_long_help = "\
EXAMPLES:
  rv-hub timestamp rakvor-out/logs/20261019T101500Z-a1b2c3
  rv-hub timestamp rakvor-out/logs/20261019T101500Z-a1b2c3 --tsa-url https://freetsa.org/tsr

EXIT CODES:
  0  Timestamp obtained and logged.
  1  The TSA could not be reached (nothing changed; try again).
  3  The log is missing or broken: no timestamp is added.")]
    Timestamp {
        /// The run's log folder (or its audit.jsonl).
        ///
        /// Example: rakvor-out/logs/20261019T101500Z-a1b2c3
        log: PathBuf,
        /// RFC 3161 time-stamping authority.
        /// Default: http://timestamp.digicert.com
        /// Example: --tsa-url https://freetsa.org/tsr
        #[arg(long, value_name = "URL", default_value = DEFAULT_TSA, verbatim_doc_comment, hide_default_value = true)]
        tsa_url: String,
        /// Name written in the new audit entry.
        /// Default: the operating-system user name
        /// Example: --actor "Ana Ruiz"
        #[arg(short, long, value_name = "NAME", verbatim_doc_comment)]
        actor: Option<String>,
    },
    /// Verify a whole case folder: case log, evidence registry and every run's audit log.
    #[command(after_long_help = "\
CHECKS:
  - case-log.jsonl is an intact hash chain starting with case_created; case.json is unchanged;
  - evidence/registry.json has the SHA-256 recorded at the last registry change;
  - every run announced in the case log has an intact audit.jsonl (and valid timestamp
    tokens), its case_linked entry points to its run_started entry, and the audit head
    recorded at run_finished is its final entry (only timestamp_obtained may follow);
  - with --rehash: every registered item still reachable at its registered path is read again
    and its digests are compared with the registry (the latest registration of a path).

EXAMPLES:
  rv-hub verify-case E:\\CASE-014
  rv-hub verify-case E:\\CASE-014 --rehash

EXIT CODES:
  0  The case folder is intact (warnings, e.g. a run still in progress or an item not
     reachable for --rehash, are printed).
  1  The folder is not a case folder (no case.json).
  3  At least one check failed: the case was edited, truncated or re-ordered, or (--rehash)
     an evidence file differs from the registry.")]
    VerifyCase {
        /// The case folder (the one that holds case.json).
        ///
        /// Example: E:\CASE-014
        case: PathBuf,
        /// Also re-hash every registered item still reachable and compare it with the registry.
        /// Default: off (only the registry's digest is checked)
        /// Example: --rehash
        #[arg(long, verbatim_doc_comment)]
        rehash: bool,
    },
    /// Print the full help of every command as Markdown (used to generate docs/usage-cli.md).
    #[command(hide = true)]
    DocsCli,
}

#[derive(Clone, Copy, ValueEnum)]
enum ProgressMode {
    /// Progress bar with elapsed time, throughput and ETA on stderr.
    Bar,
    /// One JSON event per line on stdout (for scripts and other tools).
    Jsonl,
    /// No progress output; only the final summary.
    None,
}

#[derive(Clone, Copy, ValueEnum)]
enum CrossCheckArg {
    /// Ask each run's own tool when it is installed and Rakvor-signed (or given with --tool-exe).
    Auto,
    /// Do not run any tool.
    Off,
}

#[derive(Args)]
struct VerifyArgs {
    /// The case folder to verify (the one that holds case.json). Required.
    ///
    /// Default: none. Example: --case-dir E:\CASE-014
    #[arg(long, value_name = "DIR", required = true, verbatim_doc_comment)]
    case_dir: PathBuf,

    /// Also read every registered evidence file again and compare its digests with the registry.
    ///
    /// Default: off (the registry's own digest is still checked). Example: --rehash
    #[arg(long, verbatim_doc_comment)]
    rehash: bool,

    /// Re-hash only these registered evidence ids (implies --rehash), comma-separated or repeated.
    ///
    /// Default: none (every registered item with --rehash). Example: --evidence E0001,E0007
    #[arg(
        short = 'E',
        long = "evidence",
        value_name = "IDS",
        verbatim_doc_comment
    )]
    evidence: Vec<String>,

    /// Folder where registered evidence files are now, when they are not at their registered path
    /// (looked up by file name). Repeat for several. Only used with --rehash.
    ///
    /// Default: none (only the registered paths). Example: --evidence-dir F:\copies
    #[arg(long = "evidence-dir", value_name = "DIR", verbatim_doc_comment)]
    evidence_dirs: Vec<PathBuf>,

    /// Cross-check every run with its own tool (`<tool> verify-log <run>/logs`): auto or off.
    ///
    /// Default: auto. Example: --crosscheck off
    #[arg(
        long,
        value_enum,
        value_name = "MODE",
        default_value = "auto",
        verbatim_doc_comment,
        hide_default_value = true,
        hide_possible_values = true
    )]
    crosscheck: CrossCheckArg,

    /// Executable to use for a tool's cross-check, whatever its signature: NAME=PATH. Repeat for several.
    ///
    /// Default: none (installed, Rakvor-signed tools only).
    /// Example: --tool-exe rv-pdfauth=D:\portable\rv-pdfauth.exe
    #[arg(long = "tool-exe", value_name = "NAME=PATH", verbatim_doc_comment)]
    tool_exe: Vec<String>,

    /// Hash algorithm(s) for the digests of the verified logs and of the hub's own files: one or two of
    /// md5, sha1, sha256, sha512, sha3-256, blake3. Evidence is always compared with the registry's.
    /// Default: sha256. Example: --hash sha256,blake3
    #[arg(
        short = 'H',
        long = "hash",
        value_name = "ALGO",
        value_delimiter = ',',
        default_value = "sha256",
        verbatim_doc_comment,
        hide_default_value = true
    )]
    hashes: Vec<String>,

    /// Folder for logs/ and reports/ only when the case log fails verification (a broken case is
    /// never extended). Otherwise the run goes to <CASE>/runs/rv-hub/<RUN-ID>/.
    /// Default: ./rakvor-out. Example: --out D:\verifications
    #[arg(
        short,
        long,
        value_name = "DIR",
        default_value = "rakvor-out",
        verbatim_doc_comment,
        hide_default_value = true
    )]
    out: PathBuf,

    /// Report language: en, es, fr, or all (one HTML and PDF per language). JSON is language-neutral.
    ///
    /// Default: en. Example: --lang es   or   --lang all
    #[arg(
        short,
        long,
        value_name = "LANG",
        default_value = "en",
        verbatim_doc_comment,
        hide_default_value = true
    )]
    lang: String,

    /// Name of the examiner, written in every audit entry and report.
    ///
    /// Default: the operating-system user name. Example: --actor "Ana Ruiz"
    #[arg(short, long, value_name = "NAME", verbatim_doc_comment)]
    actor: Option<String>,

    /// Expected case id: the run stops (exit 2) when case.json names another case.
    ///
    /// Default: none (any case). Example: --case CASE-2026-014
    #[arg(short, long = "case", value_name = "ID", verbatim_doc_comment)]
    case_id: Option<String>,

    /// How progress is shown: bar, jsonl or none.
    ///
    /// Default: bar (hidden automatically when stderr is not a terminal).
    /// Example: --progress jsonl
    #[arg(
        short,
        long,
        value_enum,
        value_name = "MODE",
        default_value = "bar",
        verbatim_doc_comment,
        hide_default_value = true
    )]
    progress: ProgressMode,

    /// Custody form per item: co (Colombia, Fiscalía style, Spanish) or fr (France, scellés, French).
    /// An English copy is always added. The case's own jurisdiction (case.json) applies when it has one.
    /// Default: co
    /// Example: --jurisdiction fr
    #[arg(short, long, value_name = "CC", default_value = "co", value_parser = ["co", "fr"], verbatim_doc_comment, hide_default_value = true, hide_possible_values = true)]
    jurisdiction: String,

    /// RFC 3161 time-stamping authority for the audit chain head.
    /// Default: http://timestamp.digicert.com
    /// Example: --tsa-url https://freetsa.org/tsr
    #[arg(long, value_name = "URL", default_value = DEFAULT_TSA, verbatim_doc_comment, hide_default_value = true)]
    tsa_url: String,

    /// Do not request a trusted timestamp (offline labs). Also set by RV_NO_TIMESTAMP=1.
    /// Default: off (a timestamp is requested)
    /// Example: --no-timestamp
    #[arg(long, env = "RV_NO_TIMESTAMP", value_parser = clap::builder::FalseyValueParser::new(), verbatim_doc_comment, hide_env = true)]
    no_timestamp: bool,

    /// Examiner's certificate (.p12/.pfx, RSA) used to sign every PDF report. The password is read from
    /// the environment variable named by --sign-pass-env, or asked for interactively.
    /// Default: none (PDFs are not signed)
    /// Example: --sign-cert C:\certs\ana-ruiz.p12
    #[arg(long, value_name = "P12", verbatim_doc_comment)]
    sign_cert: Option<PathBuf>,

    /// Environment variable holding the certificate password.
    /// Default: RV_SIGN_PASSWORD
    /// Example: --sign-pass-env CERT_PASS
    #[arg(
        long,
        value_name = "VAR",
        default_value = "RV_SIGN_PASSWORD",
        verbatim_doc_comment,
        hide_default_value = true
    )]
    sign_pass_env: String,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    ExitCode::from(match cli.command {
        Command::Verify(a) => verify(*a),
        Command::VerifyLog { log } => verify_log(log),
        Command::VerifyCase { case, rehash } => verify_case(case, rehash),
        Command::SelfTest => self_test(),
        Command::Timestamp {
            log,
            tsa_url,
            actor,
        } => timestamp(log, tsa_url, actor),
        Command::DocsCli => {
            print!("{}", docs_cli());
            EXIT_OK
        }
    })
}

fn usage_error(msg: &str) -> u8 {
    eprintln!(
        "error: {}\n\nFor more information, try 'rv-hub verify --help'.",
        msg
    );
    EXIT_USAGE
}

fn verify(a: VerifyArgs) -> u8 {
    let mut algos = Vec::new();
    for h in &a.hashes {
        match HashAlgo::parse(h) {
            Some(x) => algos.push(x),
            None => {
                return usage_error(&format!(
                    "unknown hash algorithm '{}': use md5, sha1, sha256, sha512, sha3-256 or blake3",
                    h
                ));
            }
        }
    }
    if let Err(e) = hash::validate_selection(&algos) {
        return usage_error(&e);
    }
    let langs = match i18n::parse_langs(&a.lang) {
        Ok(l) => l,
        Err(e) => return usage_error(&e),
    };
    let evidence_ids = match case::parse_evidence_ids(&a.evidence) {
        Ok(ids) => ids,
        Err(e) => return usage_error(&e.message),
    };
    let mut tool_overrides = BTreeMap::new();
    for t in &a.tool_exe {
        match t.split_once('=') {
            Some((name, path)) if name.starts_with("rv-") && !path.is_empty() => {
                tool_overrides.insert(name.to_string(), PathBuf::from(path));
            }
            _ => {
                return usage_error(&format!(
                    "--tool-exe {t}: use NAME=PATH, e.g. rv-pdfauth=D:\\rv-pdfauth.exe"
                ));
            }
        }
    }

    let cancel = Arc::new(AtomicBool::new(false));
    let c = cancel.clone();
    let _ = ctrlc::set_handler(move || c.store(true, Ordering::SeqCst));

    let cfg = RunConfig {
        case_dir: a.case_dir.clone(),
        rehash: a.rehash || !evidence_ids.is_empty(),
        evidence_ids,
        evidence_dirs: a.evidence_dirs.clone(),
        crosscheck: match a.crosscheck {
            CrossCheckArg::Auto => CrossCheckMode::Auto,
            CrossCheckArg::Off => CrossCheckMode::Off,
        },
        tool_overrides,
        algorithms: algos,
        out_dir: a.out.clone(),
        langs,
        actor: a.actor.clone().unwrap_or_else(rv_hub_core::env::os_user),
        case_id: a.case_id.clone(),
        frontend: "cli".into(),
        command_line: std::env::args().collect(),
        jurisdiction: a.jurisdiction.clone(),
        tsa_url: if a.no_timestamp {
            None
        } else {
            Some(a.tsa_url.clone())
        },
        sign_password: a
            .sign_cert
            .as_ref()
            .and_then(|_| password(&a.sign_pass_env)),
        sign_cert: a.sign_cert.clone(),
        ..Default::default()
    };
    // Case problems found before anything is written map to their own exit codes.
    if let Err(e) = rv_hub_core::run::preflight(&cfg) {
        return match e.exit_code() {
            EXIT_USAGE => usage_error(&e.message),
            code => {
                eprintln!("error: {}", e.message);
                code
            }
        };
    }

    let bar = match a.progress {
        ProgressMode::Bar => {
            let b = ProgressBar::with_draw_target(Some(0), ProgressDrawTarget::stderr_with_hz(8));
            b.set_style(
                ProgressStyle::with_template("{spinner} [{elapsed_precise}] {wide_bar} {binary_bytes}/{binary_total_bytes} ETA {eta} {msg}")
                    .unwrap_or_else(|_| ProgressStyle::default_bar()),
            );
            Some(b)
        }
        _ => None,
    };
    let jsonl = matches!(a.progress, ProgressMode::Jsonl);
    // A closed stdout (e.g. `| head`) must never abort a verification half-way: stop printing, keep working.
    let mut stdout_open = true;
    let mut sink = |e: &Event| {
        if jsonl && stdout_open {
            let mut out = std::io::stdout().lock();
            stdout_open = writeln!(out, "{}", serde_json::to_string(e).unwrap_or_default())
                .and_then(|_| out.flush())
                .is_ok();
        }
        if let Some(b) = &bar {
            match e {
                Event::RunStarted {
                    total_bytes,
                    total_items,
                    ..
                } => {
                    b.set_length(*total_bytes);
                    b.set_message(format!("0/{} items", total_items));
                }
                Event::Progress {
                    done,
                    total,
                    bytes_done,
                    ..
                } => {
                    b.set_position(*bytes_done);
                    b.set_message(format!("{}/{} items", done, total));
                }
                Event::Error { path, message } => b.println(format!(
                    "warning: {}: {}",
                    path.as_deref().unwrap_or("-"),
                    message
                )),
                Event::Cancelled { .. } => b.println("cancelled: writing partial reports..."),
                Event::Timestamp { status, reason, .. } if status != "ok" => b.println(format!(
                    "warning: timestamp pending ({}); run `rv-hub timestamp` later",
                    reason.as_deref().unwrap_or("-")
                )),
                _ => {}
            }
        }
    };
    let result = run(&cfg, &mut sink, &cancel);
    if let Some(b) = &bar {
        b.finish_and_clear();
    }
    match result {
        Err(e) => {
            eprintln!("error: {}", e.message);
            e.exit_code()
        }
        Ok(s) => {
            if !jsonl {
                let out = format!(
                    "{status}  run {id}\n  items: {items}  bytes: {bytes}  errors: {errors}  elapsed: {elapsed}\n  findings: high {h}, medium {m}, low {l}, info {i}\n  codes: {codes}\n  timestamp: {ts}\n  report: {report}\n  logs:   {logs}",
                    status = if s.cancelled {
                        "CANCELLED"
                    } else if s.high > 0 {
                        "DONE (high-severity findings)"
                    } else {
                        "DONE"
                    },
                    id = s.run_id,
                    items = s.items,
                    bytes = s.bytes,
                    errors = s.errors,
                    elapsed = rv_hub_core::time::human_duration(s.elapsed_ms),
                    h = s.high,
                    m = s.medium,
                    l = s.low,
                    i = s.info,
                    codes = if s.codes.is_empty() {
                        "-".to_string()
                    } else {
                        s.codes.join(", ")
                    },
                    ts = format!(
                        "{} {}",
                        s.timestamp["status"].as_str().unwrap_or("off"),
                        s.timestamp["gen_time"].as_str().unwrap_or("")
                    )
                    .trim(),
                    report = s
                        .report_dir
                        .join(format!("statistics.{}.html", cfg.langs[0]))
                        .display(),
                    logs = s.log_dir.display()
                );
                let _ = writeln!(std::io::stdout(), "{}", out);
                if let Some(c) = &s.case {
                    let t = &c.tally;
                    let _ = writeln!(
                        std::io::stdout(),
                        "  case:   {} {} | runs {} (intact {}, broken {}, not in case log {}) | evidence re-hashed {} (match {}, differ {}, missing {}) | cross-check agree {}, disagree {}, not done {}",
                        c.case_id,
                        if c.linked {
                            "(run recorded in the case log)"
                        } else {
                            "(case log broken: not extended)"
                        },
                        t.runs,
                        t.runs_intact,
                        t.runs_broken,
                        t.runs_not_in_case_log,
                        t.evidence_checked,
                        t.evidence_matched,
                        t.evidence_mismatched,
                        t.evidence_missing,
                        t.crosscheck_agreed,
                        t.crosscheck_disagreed,
                        t.crosscheck_unavailable
                    );
                }
            }
            if s.cancelled {
                EXIT_CANCELLED
            } else if s.high > 0 {
                EXIT_FINDINGS
            } else {
                EXIT_OK
            }
        }
    }
}

fn password(env: &str) -> Option<String> {
    if let Ok(p) = std::env::var(env) {
        return Some(p);
    }
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        // No echo: the password never appears on screen or in a terminal recording.
        return rpassword::prompt_password("Certificate password: ").ok();
    }
    None
}

fn timestamp(log: PathBuf, tsa_url: String, actor: Option<String>) -> u8 {
    let dir = if log.is_file() {
        log.parent().map(|p| p.to_path_buf()).unwrap_or_default()
    } else {
        log
    };
    if !dir.join("audit.jsonl").is_file() {
        eprintln!(
            "error: no audit log at {}: nothing to timestamp",
            dir.join("audit.jsonl").display()
        );
        return EXIT_FINDINGS;
    }
    let mut audit_log =
        match audit::AuditLog::resume(&dir, &actor.unwrap_or_else(rv_hub_core::env::os_user)) {
            Ok(l) => l,
            Err(e) => {
                eprintln!("error: {}", e);
                return EXIT_FINDINGS;
            }
        };
    match trust::timestamp_head(&dir, audit_log.entries(), audit_log.head(), &tsa_url) {
        Ok(ts) => {
            if let Err(e) = audit_log.record("timestamp_obtained", Some(&ts.file), ts.to_json()) {
                eprintln!("error: {}", e);
                return EXIT_ERROR;
            }
            println!(
                "OK  timestamp {} by {} covers entry #{}",
                ts.gen_time, ts.tsa, ts.covers_seq
            );
            EXIT_OK
        }
        Err(e) => {
            eprintln!("error: {}", e);
            EXIT_ERROR
        }
    }
}

fn verify_log(log: PathBuf) -> u8 {
    let path = if log.is_dir() {
        log.join("audit.jsonl")
    } else {
        log
    };
    let v = match verify::verify_log(&path) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("error: {}", e);
            return EXIT_ERROR;
        }
    };
    if v.problems.is_empty() {
        println!(
            "OK  {} entries, chain intact: {}",
            v.entries,
            path.display()
        );
        for t in &v.timestamps {
            println!("    {}", t);
        }
        if let Some(n) = v.review_entries {
            println!("    review entries: {}", n);
        }
        println!("    {}", v.truncation);
    } else {
        println!("BROKEN  {}", path.display());
        for p in &v.problems {
            println!("  - {}", p);
        }
    }
    for w in &v.warnings {
        println!("  warning: {}", w);
    }
    if v.problems.is_empty() {
        EXIT_OK
    } else {
        EXIT_FINDINGS
    }
}

fn verify_case(dir: PathBuf, rehash: bool) -> u8 {
    if !dir.join(case::CASE_FILE).is_file() {
        eprintln!(
            "error: {} is not a case folder (no {})",
            dir.display(),
            case::CASE_FILE
        );
        return EXIT_ERROR;
    }
    let mut v = case::verify_case(&dir);
    let rehashed = rehash.then(|| case::rehash_registry(&dir, &mut v));
    if v.problems.is_empty() {
        println!(
            "OK  case {}: {} case-log entries, {} registered items, {} runs verified: {}",
            v.case_id,
            v.entries,
            v.registry_items,
            v.runs,
            dir.display()
        );
        if let Some(r) = &rehashed {
            println!(
                "    re-hashed {} of {} registered items: {} match the registry",
                r.checked, r.registered, r.matched
            );
        }
        for w in &v.warnings {
            println!("  warning: {}", w);
        }
        EXIT_OK
    } else {
        println!("BROKEN  case {}: {}", v.case_id, dir.display());
        for p in &v.problems {
            println!("  - {}", p);
        }
        if let Some(r) = &rehashed {
            println!(
                "    re-hashed {} of {} registered items: {} match the registry",
                r.checked, r.registered, r.matched
            );
        }
        for w in &v.warnings {
            println!("  warning: {}", w);
        }
        EXIT_FINDINGS
    }
}

fn self_test() -> u8 {
    let failed = hash::self_test();
    for (algo, _) in hash::KNOWN_ANSWERS {
        println!(
            "{:<9} {}",
            algo.name(),
            if failed.contains(&algo) {
                "FAIL"
            } else {
                "PASS"
            }
        );
    }
    if failed.is_empty() {
        EXIT_OK
    } else {
        EXIT_ERROR
    }
}

/// Markdown of every command's long help, so docs/usage-cli.md can never drift from the binary.
fn docs_cli() -> String {
    let mut root = Cli::command().term_width(100);
    root.build();
    let mut out = String::from(
        "# Command-line reference\n\n<!-- Generated by `rv-hub docs-cli`. Do not edit by hand: CI fails if this file differs. -->\n\n",
    );
    out.push_str("```mermaid\nflowchart LR\n  A[rv-hub] --> B[verify]\n  A --> C[verify-log]\n  A --> D[self-test]\n  A --> T[timestamp]\n  A --> V[verify-case]\n  T --> E\n  B --> K[(CASE folder)]\n  B --> E[(runs/rv-hub/RUN-ID)]\n  V --> K\n  C --> E\n```\n\n");
    out.push_str(&format!(
        "## rv-hub\n\n```text\n{}\n```\n\n",
        root.render_long_help().to_string().trim_end()
    ));
    let names: Vec<String> = root
        .get_subcommands()
        .filter(|c| !c.is_hide_set() && c.get_name() != "help")
        .map(|c| c.get_name().to_string())
        .collect();
    for name in names {
        let sub = root.find_subcommand_mut(&name).expect("subcommand");
        let mut sub = sub.clone().bin_name(format!("rv-hub {}", name));
        out.push_str(&format!(
            "## rv-hub {}\n\n```text\n{}\n```\n\n",
            name,
            sub.render_long_help().to_string().trim_end()
        ));
    }
    out
}
