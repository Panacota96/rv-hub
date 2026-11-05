<#
.SYNOPSIS
  Builds the Authenticode fixtures of the Windows signature tests at CI run time (nothing secret is committed).

.DESCRIPTION
  Makes three throwaway roots, each with a code-signing leaf (all named "CN=RV Hub CI Test ..."):
    test      root trusted by Windows; the tests pin it in place of the Rakvor root
    other     an unrelated root, also trusted by Windows ("another root")
    embedded  a root NOT installed in Windows, embedded in the signature (a workstation without the Rakvor root)
  and five copies of -Exe in -OutDir:
    signed.exe    signed with the test leaf (signtool /fd SHA256, no timestamp)
    unsigned.exe  as built
    tampered.exe  signed.exe with one byte of its body changed
    other.exe     signed with the other leaf
    embedded.exe  signed with the embedded leaf, its root added with /ac and then deleted from the stores
  The paths go to $env:GITHUB_ENV as RV_SIGTEST_* (see src/core/src/signature/fixture_tests.rs).
  remove-test-roots.ps1 deletes every certificate made here.

  The roots go to LocalMachine\Root when the shell is elevated (GitHub runners are): adding a root to
  CurrentUser\Root makes Windows show a confirmation dialog, which would hang a non-interactive job.
  CurrentUser\Root is used only when not elevated (a developer machine, where the dialog can be answered).
#>
param(
    [Parameter(Mandatory)] [string] $Exe,
    [Parameter(Mandatory)] [string] $OutDir
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$Prefix = 'RV Hub CI Test'

function Write-Note([string] $m) { Write-Output "::notice title=signature fixtures::$m" }

try {
    New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
    $OutDir = (Resolve-Path $OutDir).Path
    $Exe = (Resolve-Path $Exe).Path

    $principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    $admin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $trustStore = if ($admin) { 'Cert:\LocalMachine\Root' } else { 'Cert:\CurrentUser\Root' }

    $signtool = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\signtool.exe" -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1
    if (-not $signtool) { throw 'signtool.exe not found under Windows Kits\10\bin' }
    Write-Note "signtool: $($signtool.FullName); roots trusted in $trustStore"

    function New-TestRoot([string] $name) {
        # A CA (basic constraints ca=true, KeyUsage CertSign) whose EKU allows code signing: the default EKUs of
        # New-SelfSignedCertificate (server/client auth) would make the chain invalid for code signing.
        New-SelfSignedCertificate -Type Custom -Subject "CN=$Prefix $name Root" `
            -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 `
            -KeyUsage CertSign, CRLSign, DigitalSignature -KeyUsageProperty Sign `
            -TextExtension @('2.5.29.19={critical}{text}ca=true&pathlength=0', '2.5.29.37={text}1.3.6.1.5.5.7.3.3') `
            -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(2)
    }
    function New-TestLeaf($root, [string] $name) {
        New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=$Prefix $name Leaf" `
            -KeyAlgorithm RSA -KeyLength 2048 -HashAlgorithm SHA256 -Signer $root `
            -CertStoreLocation Cert:\CurrentUser\My -NotAfter (Get-Date).AddDays(1)
    }
    function Invoke-Sign([string] $file, $leaf, [string[]] $extra = @()) {
        & $signtool.FullName sign /fd SHA256 /sha1 $leaf.Thumbprint /s My @extra $file
        if ($LASTEXITCODE -ne 0) { throw "signtool failed ($LASTEXITCODE) on $file" }
    }

    $roots = @{}
    foreach ($name in 'test', 'other', 'embedded') {
        $root = New-TestRoot $name
        $leaf = New-TestLeaf $root $name
        $cer = Join-Path $OutDir "$name-root.cer"
        Export-Certificate -Cert $root -FilePath $cer -Type CERT | Out-Null
        if ($name -ne 'embedded') { Import-Certificate -FilePath $cer -CertStoreLocation $trustStore | Out-Null }
        $roots[$name] = @{ Root = $root; Leaf = $leaf; Cer = $cer }
    }

    $f = @{}
    foreach ($n in 'signed', 'unsigned', 'other', 'embedded') {
        $f[$n] = Join-Path $OutDir "$n.exe"
        Copy-Item $Exe $f[$n] -Force
    }
    Invoke-Sign $f.signed $roots.test.Leaf
    Invoke-Sign $f.other $roots.other.Leaf
    Invoke-Sign $f.embedded $roots.embedded.Leaf @('/ac', $roots.embedded.Cer)
    # The embedded root now exists only inside embedded.exe's signature.
    Remove-Item -Path "Cert:\CurrentUser\My\$($roots.embedded.Root.Thumbprint)" -DeleteKey

    # Tampered: one byte in the middle of the signed file (section data, far before the signature at the end).
    $f.tampered = Join-Path $OutDir 'tampered.exe'
    $bytes = [IO.File]::ReadAllBytes($f.signed)
    $off = [int][Math]::Floor($bytes.Length / 3)
    $bytes[$off] = $bytes[$off] -bxor 0xFF
    [IO.File]::WriteAllBytes($f.tampered, $bytes)

    # Sanity check with PowerShell's own Authenticode reader, so a broken fixture is not mistaken for a bug in
    # the hub. The embedded case is only reported (its root is deliberately untrusted).
    $expect = @{ signed = 'Valid'; unsigned = 'NotSigned'; tampered = 'HashMismatch'; other = 'Valid'; embedded = $null }
    foreach ($n in 'signed', 'unsigned', 'tampered', 'other', 'embedded') {
        $sig = Get-AuthenticodeSignature -FilePath $f[$n]
        Write-Note "$n.exe: $($sig.Status) ($($sig.StatusMessage)) signer=$($sig.SignerCertificate.Subject)"
        if ($expect[$n] -and "$($sig.Status)" -ne $expect[$n]) {
            throw "$n.exe: Get-AuthenticodeSignature says $($sig.Status), expected $($expect[$n])"
        }
    }

    $vars = [ordered]@{
        RV_SIGTEST_SIGNED            = $f.signed
        RV_SIGTEST_UNSIGNED          = $f.unsigned
        RV_SIGTEST_TAMPERED          = $f.tampered
        RV_SIGTEST_OTHER             = $f.other
        RV_SIGTEST_EMBEDDED          = $f.embedded
        RV_SIGTEST_ROOT_DER          = $roots.test.Cer
        RV_SIGTEST_OTHER_ROOT_DER    = $roots.other.Cer
        RV_SIGTEST_EMBEDDED_ROOT_DER = $roots.embedded.Cer
    }
    foreach ($k in $vars.Keys) {
        if ($env:GITHUB_ENV) { "$k=$($vars[$k])" | Out-File -FilePath $env:GITHUB_ENV -Append -Encoding utf8 }
        Write-Output "$k=$($vars[$k])"
    }
}
catch {
    Write-Output "::error title=signature fixtures::$($_.Exception.Message) (line $($_.InvocationInfo.ScriptLineNumber))"
    exit 1
}
