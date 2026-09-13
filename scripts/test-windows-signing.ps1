# Run with pwsh -NoProfile -File scripts/test-windows-signing.ps1.
# No certificates or SDK required: mock only the native signtool boundary.
$ErrorActionPreference = 'Stop'
$originalTemp = $env:RUNNER_TEMP
$originalPfx = $env:WINDOWS_PFX_BASE64
$originalPassword = $env:WINDOWS_PFX_PASSWORD
$temp = Join-Path ([IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString())
New-Item -ItemType Directory $temp | Out-Null
$env:RUNNER_TEMP = $temp
$env:WINDOWS_PFX_BASE64 = [Convert]::ToBase64String([byte[]](1,2,3))
$env:WINDOWS_PFX_PASSWORD = 'test-only'
$artifact = Join-Path $temp 'fixture.msi'
Set-Content $artifact 'fixture bytes'
function global:signtool.exe {
  $global:signToolCalls += $args[0]
  $global:LASTEXITCODE = if ($args[0] -eq $global:signToolFailOperation) { 23 } else { 0 }
}
try {
  foreach ($operation in @('sign', 'verify', 'none')) {
    $global:signToolFailOperation = $operation
    $global:signToolCalls = @()
    $failed = $false
    $output = ''
    try {
      $output = (& "$PSScriptRoot/sign-windows-artifacts.ps1" -MsiPath $artifact 6>&1 | Out-String)
    } catch { $failed = $true }
    if ($failed -ne ($operation -ne 'none')) { throw "Unexpected outcome for $operation failure" }
    if (@(Get-ChildItem $temp -Filter '*.pfx').Count -ne 0) { throw "PFX leaked after $operation" }
    if ($operation -eq 'sign' -and $global:signToolCalls -contains 'verify') { throw 'Verification ran after signing failed' }
    if ($operation -eq 'none' -and ($global:signToolCalls -join ',') -ne 'sign,verify') { throw 'Success did not sign then verify' }
    if ($operation -eq 'none' -and $output -notmatch 'signed windows artifact') { throw 'Missing verified success output' }
    Write-Host "PASS: $operation failure handling and cleanup"
  }
} finally {
  Remove-Item Function:\signtool.exe -ErrorAction SilentlyContinue
  Remove-Variable signToolCalls,signToolFailOperation -Scope Global -ErrorAction SilentlyContinue
  Remove-Item $temp -Recurse -Force
  $env:RUNNER_TEMP = $originalTemp
  $env:WINDOWS_PFX_BASE64 = $originalPfx
  $env:WINDOWS_PFX_PASSWORD = $originalPassword
}
