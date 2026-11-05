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

### Documentation
- README, theory (plain-language and expert parts), admissibility (draft pending legal review), usage,
  installation (SmartScreen, signatures against the Rakvor root, hub data folder, planned Rakvor Suite installer),
  reports (every finding code), case folder, forensic audit and architecture written for the hub, from the code.
- GUI screenshots regenerated with the released tool versions (rv-hashinv 0.3.1, rv-pdfauth 0.3.0, rv-rsmf 0.2.0,
  rv-imgauth 0.2.0, rv-certcheck 0.2.0).

### Known limitations
- Signatures are checked on Windows only, without revocation.
- The cross-check needs the tools installed and Rakvor-signed; the tools' `verify-log` commands differ (rv-hub#21).
- Timestamp tokens: the TSA chain is validated only with `--tsa-ca`; revocation of the TSA certificate is not
  checked; only RSA TSA signers are supported.
- No Rakvor Suite installer yet (rv-hub#2; needs the `RAKVOR_SUITE_TOKEN` secret).
