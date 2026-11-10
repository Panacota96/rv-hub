#!/usr/bin/env sh
# Regenerates the REAL sample case (examples/sample/case) by running the four Rakvor tools on the synthetic
# evidence (examples/sample/evidence). Usage: tests/samples/make_case.sh [BIN_DIR]
#
# BIN_DIR (default tests/samples/bin, gitignored) holds a snapshot of the four CLIs: rv-hashinv, rv-pdfauth,
# rv-imgauth, rv-rsmf. Build them in their own repositories (cargo build -p <tool>-cli) and copy them there.
# The evidence is copied to a temporary folder first, so the registry records a path outside the repository;
# `rv-hub verify --rehash --evidence-dir examples/sample/evidence` finds the copies by file name.
# Offline (RV_NO_TIMESTAMP=1) and with fixed actor names; run ids and times change on every regeneration.
set -eu
root=$(cd "$(dirname "$0")/../.." && pwd)
bin=${1:-"$root/tests/samples/bin"}
for t in rv-hashinv rv-pdfauth rv-imgauth rv-rsmf; do
  [ -x "$bin/$t" ] || { echo "missing $bin/$t (build it in its repository and copy it here)" >&2; exit 2; }
done
export RV_NO_TIMESTAMP=1
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
python3 "$root/tests/samples/make_evidence.py" "$root/examples/sample/evidence"
cp -R "$root/examples/sample/evidence" "$work/evidence"
case="$work/case"
common="--lang en --progress none"

"$bin/rv-hashinv" scan --case-dir "$case" --case SAMPLE-1 --jurisdiction co -i "$work/evidence" \
  --hash sha256,md5 --actor "Examiner Intake" $common || [ $? -eq 3 ]
id() { python3 -c 'import json,sys; r=json.load(open(sys.argv[1])); print(",".join(i["evidence_id"] for i in r["items"] if i["path"].endswith(tuple(sys.argv[2:]))))' "$case/evidence/registry.json" "$@"; }
"$bin/rv-pdfauth" analyze --case-dir "$case" -E "$(id .pdf)" --actor "Examiner PDF" \
  --visual-diff off --objects-dump off $common || [ $? -eq 3 ]
"$bin/rv-imgauth" analyze --case-dir "$case" -E "$(id .jpg .png)" --actor "Examiner Image" \
  --maps none --copy-move off $common || [ $? -eq 3 ]
"$bin/rv-rsmf" convert --case-dir "$case" -E "$(id whatsapp-chat.txt)" --actor "Examiner Chat" \
  --timezone Europe/Paris --date-order dmy $common || [ $? -eq 3 ]
"$bin/rv-hashinv" verify-case "$case"

rm -rf "$root/examples/sample/case"
cp -R "$case" "$root/examples/sample/case"
python3 - "$root" "$bin" <<'PY'
import hashlib, json, subprocess, sys
from pathlib import Path
root, bin_dir = Path(sys.argv[1]), Path(sys.argv[2])
tools = {}
for t in ("rv-hashinv", "rv-pdfauth", "rv-imgauth", "rv-rsmf"):
    exe = bin_dir / t
    version = subprocess.run([str(exe), "--version"], capture_output=True, text=True).stdout.split()[-1]
    d = subprocess.run([str(exe), "describe", "--json"], capture_output=True, text=True)
    tools[t] = {"version": version, "describe": d.returncode == 0,
                "cli_sha256": hashlib.sha256(exe.read_bytes()).hexdigest()}
out = {"case_id": "SAMPLE-1", "made_by": "tests/samples/make_case.sh", "tools": tools}
(root / "examples/sample/case-tools.json").write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
ev = root / "examples/sample/evidence"
algos = ["md5", "sha1", "sha256", "sha512", "sha3_256"]
rows = ["file,size,md5,sha1,sha256,sha512,sha3-256"]
for f in sorted(ev.iterdir()):
    b = f.read_bytes()
    rows.append(",".join([f.name, str(len(b))] + [hashlib.new(a, b).hexdigest() for a in algos]))
(root / "examples/sample/expected_hashes.csv").write_text("\n".join(rows) + "\n")
PY
du -sh "$root/examples/sample/case"
echo "sample case written to examples/sample/case"
