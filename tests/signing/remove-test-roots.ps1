<#
.SYNOPSIS
  Deletes every certificate made by make-fixtures.ps1 ("CN=RV Hub CI Test ...") from the stores it touches.
  Run at the end of the CI job whatever happened (if: always()). Fails if one is left.
#>
$ErrorActionPreference = 'Continue'
$Prefix = 'RV Hub CI Test'
$stores = 'Cert:\CurrentUser\My', 'Cert:\LocalMachine\CA', 'Cert:\CurrentUser\CA', 'Cert:\LocalMachine\Root', 'Cert:\CurrentUser\Root'
function Get-TestCerts([string] $store) { Get-ChildItem $store | Where-Object { $_.Subject -like "CN=$Prefix *" } }
# Store by store, re-listed each time: CurrentUser\Root also shows LocalMachine\Root, so a machine root removed
# first is not seen (and not removed a second time, which would ask for a confirmation) under CurrentUser.
foreach ($s in $stores) {
    foreach ($c in @(Get-TestCerts $s)) {
        Write-Output "removing $($c.Subject) ($($c.Thumbprint)) from $s"
        if ($c.HasPrivateKey) { Remove-Item -Path $c.PSPath -DeleteKey } else { Remove-Item -Path $c.PSPath }
    }
}
$left = @(foreach ($s in $stores) { Get-TestCerts $s })
if ($left.Count -gt 0) {
    Write-Output "::error title=signature fixtures::$($left.Count) test certificate(s) left in the stores"
    exit 1
}
Write-Output 'no RV Hub CI test certificate left'
