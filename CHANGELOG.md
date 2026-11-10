# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Entries are generated from
[Conventional Commits](https://www.conventionalcommits.org/) by release-please and reviewed by a human.

## [Unreleased]

### Added
- Project scaffolded with rakvor-tool-forge (rust profile) on 2026-10-29.
- Tool discovery (uninstall registry AppIds, `%LOCALAPPDATA%\Programs\Rakvor`, `PATH`, added portable folders),
  `describe --json` (`rakvor.describe/1`) with a built-in table for older tool versions, and the SHA-256 of every
  executable.
- Authenticode signature check on Windows (`WinVerifyTrust`, chain root pinned to the bundled Rakvor root); findings
  `TOOL_SIGNED_RAKVOR`, `TOOL_SIGNED_OTHER_ROOT`, `TOOL_SIGNATURE_INVALID`, `TOOL_UNSIGNED`.
- Launch of a tool's GUI on a case (`--case-dir`), re-hashed and re-checked at launch; untrusted launches need a
  confirmation that is logged first; hub session log (hash-chained) in `%LOCALAPPDATA%\Rakvor\RV Hub\logs\`.
- Read-only case dashboard and next-step suggestions (`rv-hub case`, Case tab).
- Whole-case verification (`rv-hub verify`, Verify tab): case log, every run's audit log, review log, case links,
  timestamp tokens, unannounced runs, unknown logs, optional evidence re-hash (`--rehash`, `--evidence-dir`), and a
  cross-check with each run's own tool (`verify-log`, full verdict; chain-only verdict for rv-pdfauth and rv-imgauth,
  whose `verify-log` lacks the truncation check); reports in en/es/fr.
- CLI commands `tools`, `case`, `launch`, `verify`, `describe`; GUI tabs Tools, Case and Verify.
- Sample case made by the tools, with six tampered variants and their expected findings.
- Timestamp tokens are verified like rv-pdfauth and rv-imgauth do: the TSA's CMS signature (ESS
  signing-certificate, message digest, RSA signature, timeStamping key usage), and with `--tsa-ca` (`verify-log`,
  `verify`) the TSA certificate chain at genTime; without it the output says "chain not checked".

### Fixed
- Timestamp verification (`verify-log`, `verify`, `verify-case`) is driven by the audit log's `timestamp_obtained`
  entries: deleting a token's `timestamp-<SEQ>.json` no longer skips its signature and chain checks (with `--tsa-ca`
  an untrusted TSA passed that way). A recorded token whose `.tsr` or `.json` is missing, or whose metadata disagrees
  with the entry, is a problem (`RUN_LOG_BROKEN` in `verify`); a token file that nothing records is checked too, or
  is a problem when it cannot be.
- The TSA certificate's extended key usage must be critical and contain only `id-kp-timeStamping` (RFC 3161 §2.3),
  as in rv-certcheck.
- `--tsa-ca` path validation enforces `pathLenConstraint` (anchor included, self-issued certificates not counted),
  `keyCertSign` for issuers with keyUsage, directoryName name constraints, and rejects unsupported critical
  extensions on any certificate of the path (policy processing and other name forms are not implemented: such
  chains fail closed). Path building tries every candidate issuer and anchor (cross-signed intermediates, renewed
  anchors, self-issued key-rollover intermediates), at most 8 certificates deep, without loops. Tested against 34
  fixture chains cross-checked with `openssl verify -purpose timestampsign` (`tests/fixtures/tsa-chains`).
- Docs: the `openssl ts -verify` cross-check is labelled a signature/chain check; revocation of the TSA certificate
  is never checked by the tool and must be established from CRL/OCSP evidence covering genTime.
- `rv-hub verify`: every verify-log problem of a run is a `RUN_LOG_BROKEN` finding (it was only a fact when the
  hub's other checks missed it, e.g. a timestamp token and its metadata both deleted while the `timestamp_obtained`
  entry remained), and `RUN_LOG_INTACT` is given only when the verify-log verdict is intact (so a broken case log
  no longer leaves `RUN_LOG_INTACT` on runs whose length it cannot vouch for).
- Cross-check: a discovered tool's CLI is checked again just before it is run, as at launch (Windows lock with
  `FILE_SHARE_READ`, re-hash compared with the discovery SHA-256, signature re-check, re-hash at the path before the
  start). One that changed since discovery (the GUI reuses the Tools tab's inventory) is not run: new finding
  `TOOL_CHANGED_SINCE_DISCOVERY` (medium), recorded in the audit log.
- `describe --json` and `verify-log` time limits cover the reading of the output too: a descendant that keeps the
  pipes open after the program exits no longer delays the hub past the limit (it is reported as a timeout). On Linux
  and macOS the program runs in its own process group, killed as a whole on timeout (new Unix-only dependency
  `nix`, `signal` feature, already in the dependency tree).

### Documentation
- README, theory (plain-language and expert parts), admissibility (draft pending legal review), usage,
  installation (SmartScreen, signatures against the Rakvor root, hub data folder, planned Rakvor Suite installer),
  reports (every finding code), case folder, forensic audit and architecture written for the hub, from the code.
- GUI screenshots regenerated with the released tool versions (rv-hashinv 0.3.1, rv-pdfauth 0.3.0, rv-rsmf 0.2.0,
  rv-imgauth 0.2.0, rv-certcheck 0.2.0).

### Build
- Release signing embeds the Rakvor root in every signature (`signtool sign /ac rakvor-code-signing-root.cer`), so
  the full chain to the pinned root is in the file on machines where the root is not installed.

### Known limitations
- Signatures are checked on Windows only, without revocation.
- The cross-check needs the tools installed and Rakvor-signed; the tools' `verify-log` commands differ (rv-hub#21).
- Timestamp tokens: the TSA chain is validated only with `--tsa-ca`; revocation of the TSA certificate is not
  checked; only RSA TSA signers are supported.
- No Rakvor Suite installer yet (rv-hub#2; needs the `RAKVOR_SUITE_TOKEN` secret).
