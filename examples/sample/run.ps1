# Verifies the sample case on Windows and checks the result (works on a copy in examples\sample\out).
# Fails (non-zero exit) if the self-test, the verification or verify-log fails, or if the re-hashed evidence in
# the hub's hash register (hashes.csv) differs from the independently computed expected_hashes.csv.
# Usage: .\examples\sample\run.ps1 [-Bin C:\path\to\rv-hub.exe]
param([string]$Bin = "rv-hub")
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$out = Join-Path $here "out"
$case = Join-Path $out "case"
if (Test-Path $case) { Remove-Item -Recurse -Force $case }
New-Item -ItemType Directory -Force $out | Out-Null
Copy-Item -Recurse (Join-Path $here "case") $case
& $Bin self-test; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
# Expected exit code 0: four intact runs (RUN_LOG_INTACT, info), five evidence files matching the registry.
& $Bin verify --case-dir $case --rehash --evidence-dir (Join-Path $here "evidence") --hash sha256,md5 --lang all --actor "Sample" --crosscheck off --progress none
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$run = Get-ChildItem (Join-Path $case "runs\rv-hub") | Sort-Object Name | Select-Object -Last 1
$logs = Join-Path $run.FullName "logs"
& $Bin verify-log $logs; if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$expected = Import-Csv (Join-Path $here "expected_hashes.csv")
$register = Import-Csv (Join-Path $logs "hashes.csv")
$bad = 0
foreach ($row in $expected) {
  $got = $register | Where-Object { (Split-Path -Leaf $_.path) -eq $row.file }
  if ($null -eq $got -or @($got).Count -ne 1) { Write-Host "MISMATCH: $($row.file) not in hashes.csv"; $bad = 1; continue }
  if ($got.size -ne $row.size -or $got.sha256 -ne $row.sha256 -or $got.md5 -ne $row.md5) {
    Write-Host "MISMATCH $($row.file): tool $($got.size),$($got.sha256),$($got.md5), expected $($row.size),$($row.sha256),$($row.md5)"
    $bad = 1
  }
}
if ($bad) { exit 3 }
Write-Host "hashes.csv matches expected_hashes.csv ($($expected.Count) files: size, SHA-256, MD5)"
Write-Host "Reports: $($run.FullName)\reports\statistics.en.html"
