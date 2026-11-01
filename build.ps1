# Build an ad-free install set for Bounce Defense.
#
#   pwsh -File build.ps1 -Variant instant
#
# For a NEW game version, point it at the fresh APK pair; addresses are then
# re-derived from the binary instead of the hard-coded table:
#
#   pwsh -File build.ps1 -Variant instant `
#        -Base local/game/base.apk -Split local/game/split_config.arm64_v8a.apk
param(
    [ValidateSet('safe','instant')][string]$Variant = 'instant',
    [string]$Base = '',
    [string]$Split = ''
)

$ErrorActionPreference = 'Stop'
$bt = "C:\Users\ammar\AppData\Local\Android\Sdk\build-tools\36.1.0"
$keytool = "C:\Program Files\Java\jdk-25.0.2\bin\keytool.exe"
Set-Location $PSScriptRoot

$out = Join-Path $PSScriptRoot "build\$Variant"
Write-Host "== variant: $Variant ==" -ForegroundColor Cyan

if ($Base -and $Split) {
    Write-Host "== 1/5 resolve addresses from the APKs (retarget) ==" -ForegroundColor Cyan
    python analysis\retarget.py --base $Base --split $Split --variant $Variant --out $out
} else {
    Write-Host "== 1/5 apply known-build patch table ==" -ForegroundColor Cyan
    python analysis\patch.py --variant $Variant
}
if ($LASTEXITCODE -ne 0) { throw "binary patch failed" }

Write-Host "== 2/5 neutralise PairIP (sideload support) ==" -ForegroundColor Cyan
python analysis\pairip_patch.py
if ($LASTEXITCODE -ne 0) { throw "pairip patch failed" }

Write-Host "== 3/5 repack APKs ==" -ForegroundColor Cyan
python analysis\rebuild.py --variant $Variant
if ($LASTEXITCODE -ne 0) { throw "rebuild failed" }

Write-Host "== 4/5 keystore ==" -ForegroundColor Cyan
$ks = Join-Path $PSScriptRoot "build\mod.keystore"
if (-not (Test-Path $ks)) {
    & $keytool -genkeypair -keystore $ks -alias modkey -keyalg RSA -keysize 2048 `
        -validity 10000 -storepass modstore -keypass modstore `
        -dname "CN=Bounce Defense No Ads, O=Local Mod, C=MY" | Out-Null
}

Write-Host "== 5/5 align + sign ==" -ForegroundColor Cyan
foreach ($n in 'base', 'split_config.arm64_v8a') {
    & "$bt\zipalign.exe" -f -p 4 "$out\$n.unsigned.apk" "$out\$n.aligned.apk"
    if ($LASTEXITCODE -ne 0) { throw "zipalign failed: $n" }
    & "$bt\apksigner.bat" sign --ks $ks --ks-pass pass:modstore --key-pass pass:modstore `
        --ks-key-alias modkey --min-sdk-version 26 --v1-signing-enabled false `
        --v2-signing-enabled true --v3-signing-enabled true `
        --out "$out\$n.apk" "$out\$n.aligned.apk" 2>&1 | Where-Object { $_ -notmatch 'WARNING' }
    if ($LASTEXITCODE -ne 0) { throw "apksigner failed: $n" }
    $v = & "$bt\apksigner.bat" verify -v --min-sdk-version 26 "$out\$n.apk" 2>&1
    Write-Host ("  {0,-26} verified={1}" -f $n, (($v -join "`n") -match 'Verifies'))
}
Remove-Item "$out\*.aligned.apk","$out\*.unsigned.apk" -ErrorAction SilentlyContinue

Write-Host "`nArtifacts:" -ForegroundColor Green
Get-ChildItem "$out\*.apk" | Select-Object Name, @{n='MB'; e={[math]::Round($_.Length/1MB,1)}} | Format-Table -AutoSize
Write-Host "Install:  adb install-multiple <base.apk> <split_config.arm64_v8a.apk>" -ForegroundColor DarkGray
