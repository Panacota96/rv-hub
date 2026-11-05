//! The hub commands of the rv-hub CLI (`tools`, `case`, `launch`, `describe`), as a library so the integration
//! tests in `src/cli/tests/` can drive them with the core's mock signature verifier and spawner: on Linux no
//! executable is Authenticode-signed, so the Windows-only outcomes (other root, invalid signature, signed by
//! Rakvor) are tested through [`rv_hub_core::signature::StaticVerifier`]. `main.rs` only parses the arguments
//! and calls these functions with the real verifier ([`rv_hub_core::signature::OsVerifier`]), the real
//! spawner and the hub's session log.
//!
//! Every function writes to the given writers and returns the exit code. None of them writes into a case
//! folder: `tools` and `launch` write only the hub's own session log (outside every case), `case` writes nothing.

pub mod hub;
