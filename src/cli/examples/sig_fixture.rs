//! A tiny program that stands for a Rakvor tool in the Windows signature tests (`tests/signing/`).
//!
//! CI signs copies of it in four ways (test root, unsigned, tampered, other root) and puts them in a folder as
//! `rv-pdfauth.exe` / `rv-pdfauth-gui.exe`. When it is started it writes its arguments to `launched.txt` in the
//! current folder (the hub starts tools in their own folder), so a test can tell whether the hub launched it.
//! `describe` exits 2, so the hub falls back to its built-in description.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("describe") {
        std::process::exit(2);
    }
    if let Err(e) = std::fs::write("launched.txt", args.join("\n")) {
        eprintln!("sig_fixture: cannot write launched.txt: {e}");
        std::process::exit(1);
    }
}
