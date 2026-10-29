#!/usr/bin/env sh
# Verifies the sample case and checks the result. Usage: examples/sample/run.sh [path-to-rv-hub]
# Works on a copy of examples/sample/case in examples/sample/out (or $RV_SAMPLE_OUT), so the committed case is
# never changed. Fails (non-zero exit) if the self-test, the verification or verify-log fails, or if the
# re-hashed evidence in the hub's hash register (hashes.csv) differs from the independently computed
# expected_hashes.csv.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
bin=${1:-rv-hub}
out=${RV_SAMPLE_OUT:-"$here/out"}
rm -rf "$out/case"
mkdir -p "$out"
cp -R "$here/case" "$out/case"
"$bin" self-test
# Expected exit code 0: four intact runs (RUN_LOG_INTACT, info), five evidence files matching the registry.
"$bin" verify --case-dir "$out/case" --rehash --evidence-dir "$here/evidence" --hash sha256,md5 --lang all \
  --actor "Sample" --crosscheck off --progress none
run=$(ls "$out/case/runs/rv-hub" | tail -n 1)
logs="$out/case/runs/rv-hub/$run/logs"
"$bin" verify-log "$logs"
# Compare the evidence rows of the hub's hash register with expected_hashes.csv: same files, sizes, SHA-256, MD5.
# hashes.csv: index,path,size,sha256,md5,status,error (path may be quoted); fields are read from the right.
awk -F, '
  FNR == 1 { if (FILENAME ~ /expected_hashes\.csv$/) { for (i = 1; i <= NF; i++) e[$i] = i } else { for (i = 1; i <= NF; i++) h[$i] = i; hn = NF }; next }
  FILENAME ~ /expected_hashes\.csv$/ { want[$e["file"]] = $e["size"] "," $e["sha256"] "," $e["md5"]; n++; next }
  {
    path = $0; sub(/^[0-9]+,/, "", path); sub(/,[0-9]+,[^,]*,[^,]*,[^,]*,[^,]*$/, "", path)
    gsub(/"/, "", path); sub(/.*[\/\\]/, "", path)
    if (path in want) { got[path] = $(NF - hn + h["size"]) "," $(NF - hn + h["sha256"]) "," $(NF - hn + h["md5"]); m++ }
  }
  END {
    for (f in want) if (got[f] != want[f]) { print "MISMATCH " f ": tool " got[f] ", expected " want[f]; bad = 1 }
    if (m != n) { print "MISMATCH: the hub re-hashed " m " evidence files, expected_hashes.csv lists " n; bad = 1 }
    if (bad) exit 3
    print "hashes.csv matches expected_hashes.csv (" n " files: size, SHA-256, MD5)"
  }' "$here/expected_hashes.csv" "$logs/hashes.csv"
echo "Reports: $out/case/runs/rv-hub/$run/reports/statistics.en.html"
