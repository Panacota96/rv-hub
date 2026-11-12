# Changelog

All notable changes to this project are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html). Entries are generated from
[Conventional Commits](https://www.conventionalcommits.org/) by release-please and reviewed by a human.

## Unreleased

### Features

* **core:** RV MailAuth (`rv-mailauth`, email authenticity signals for `.eml`, Outlook `.msg`, `.mbox`) is the sixth
  known tool: discovery (installer AppId `{0D5428B0-B438-4B0F-804F-C48582CC8A7B}`, install folder, PATH), signature
  check, launch, built-in description, review-log check.
* **core:** suggestions: registered emails not yet analysed go to rv-mailauth (`mail_not_analysed`; `.eml` by
  extension or header block, `.mbox` by extension or separator line). An Outlook `.msg` goes by its MAPI message
  class (read-only, `cfb` crate): `IPM.Note*` to rv-mailauth, `IPM.SkypeTeams.*` to rv-rsmf, both when the class
  cannot be read or is another one (`msg_ambiguous`). A compound file that is not a message (`.doc`, `.xls`) is no
  longer suggested to rv-rsmf.

## [0.4.0](https://github.com/Panacota96/rv-hub/compare/v0.3.0...v0.4.0) (2026-11-12)


### Features

* **cli:** list rv-mailauth in the help and document the .msg rule ([094cc6a](https://github.com/Panacota96/rv-hub/commit/094cc6a380caf31f6685e6771f06c1a8c0aad3b5))
* **core:** add RV MailAuth as a known tool and route .msg by message class ([0c9aa7f](https://github.com/Panacota96/rv-hub/commit/0c9aa7fee6f86fe8404c90694e02c6b9e7c13cea))
* RV MailAuth in RV Hub, and .msg routed by message class ([1d17d11](https://github.com/Panacota96/rv-hub/commit/1d17d1144351ba20c539d102844f7a3384e792a6))

## [0.3.0](https://github.com/Panacota96/rv-hub/compare/v0.2.1...v0.3.0) (2026-11-11)


### Features

* **gui:** TSA CA bundle in the Verify tab, evidence folder in the Case tab ([4698fc6](https://github.com/Panacota96/rv-hub/commit/4698fc699294f675f5b4f966a98f7ed6fbcd614f))
* **gui:** TSA CA bundle in the Verify tab, evidence folder in the Case tab ([d1e2ae2](https://github.com/Panacota96/rv-hub/commit/d1e2ae22eb8964bb5c85e9f7d484b31a19728057))


### Bug Fixes

* **gui:** apply and audit option edits on focus loss, tab switch and start ([092b0e0](https://github.com/Panacota96/rv-hub/commit/092b0e0b1d3a38fbf7f0bad39c9ff8d617cad4e3))

## [0.2.1](https://github.com/Panacota96/rv-hub/compare/v0.2.0...v0.2.1) (2026-11-10)


### Bug Fixes

* **security:** patch dependency advisories, blind RSA signing, check advisories in CI ([03d5126](https://github.com/Panacota96/rv-hub/commit/03d5126d9486747a7bff6a387fc43851e33a9895))
* **security:** patch dependency advisories, blind RSA signing, check advisories in CI ([82c836e](https://github.com/Panacota96/rv-hub/commit/82c836edddcc08ca0505266b2a810fb386ccad62))

## [0.2.0](https://github.com/Panacota96/rv-hub/compare/v0.1.0...v0.2.0) (2026-11-10)


### Features

* **case:** record the SHA-256 of evidence/registry.csv in the audit log ([509ddba](https://github.com/Panacota96/rv-hub/commit/509ddbac344e47dee99c11733861d1a7963234bf))
* **cli:** tools, case, launch and describe commands; verify help for the hub ([359cb43](https://github.com/Panacota96/rv-hub/commit/359cb43c1cc7ef832cbb530af85ee32e4c96c77f))
* **core:** add RV CertCheck to the built-in tools, AppIds and suggestions ([b2680a4](https://github.com/Panacota96/rv-hub/commit/b2680a42c34071b0daf075559d6d15598208e21e))
* **core:** hub core API, whole-case verify with tool cross-check, real sample case ([d5e876f](https://github.com/Panacota96/rv-hub/commit/d5e876fdf6db807e0c90979c1617c86d9e59f600))
* **core:** launch_without_case (open a tool's GUI with no case, same rules and audit) ([5f8c1ba](https://github.com/Panacota96/rv-hub/commit/5f8c1ba3f5b2fbad38b0f25636d5263309482883))
* **gui:** Tools, Case and Verify tabs ([f7d28ff](https://github.com/Panacota96/rv-hub/commit/f7d28ff7d6e174bfccb35a70c21761d784f5163c))
* **verify:** --add-folder for the cross-check discovery ([a88320f](https://github.com/Panacota96/rv-hub/commit/a88320f25122387a2219d63357f9d685b2bc71e8))


### Bug Fixes

* CI sample steps verify a copy of the sample case; re-hash fills the selected register columns ([9088a89](https://github.com/Panacota96/rv-hub/commit/9088a897e53106152b21924f8d7a6f0d0150bcbf))
* **launch:** lock the executable on Windows and re-hash it just before the start ([4b3dbf7](https://github.com/Panacota96/rv-hub/commit/4b3dbf7d87c09fb8f8b40a640f6186c3f2aec8b1))
* **proc:** bound the reading of a child's pipes by the same deadline ([18e8041](https://github.com/Panacota96/rv-hub/commit/18e804122fdcf0b9bda23d28010048cd669473c7))
* **suggest:** --evidence-dir, WhatsApp detection by content, completed runs only ([26f7432](https://github.com/Panacota96/rv-hub/commit/26f74329928fc48431fe6c90177891aa61793e0f))
* **tools:** run unknown rv-* programs only from added folders or when Rakvor-signed ([4c996f9](https://github.com/Panacota96/rv-hub/commit/4c996f9c22f835f67c1a9514d3e50923e1968f2b))
* **trust:** drive timestamp checks from the audit log; RFC 3161/5280 TSA path rules ([8260db0](https://github.com/Panacota96/rv-hub/commit/8260db0ea89f36818e64493548b604398cb7acfa))
* **trust:** verify the TSA CMS signature and, with --tsa-ca, its chain ([d124717](https://github.com/Panacota96/rv-hub/commit/d124717ec98400d257cf08a5e4e229fabf5e2850))
* **verify:** chain-level cross-check fallback only for rv-pdfauth and rv-imgauth ([5744c42](https://github.com/Panacota96/rv-hub/commit/5744c4229acb3050ca22569415629e7e444897fb))
* **verify:** every verify-log problem is a RUN_LOG_BROKEN finding ([2a3e25e](https://github.com/Panacota96/rv-hub/commit/2a3e25efb4785bee34dd35cd04eb7bc4aae88420))
* **verify:** re-check a discovered tool before its cross-check run ([e77306b](https://github.com/Panacota96/rv-hub/commit/e77306b928df9ac4f80686e6ac0119e37164179c))
* **verify:** withdraw RUN_LOG_INTACT when the run's tool disagrees ([e997952](https://github.com/Panacota96/rv-hub/commit/e9979524799f42dbf8ed3d929a5258f2992720cc))

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
