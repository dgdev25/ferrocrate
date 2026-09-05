param(
  [string]$MsiPath = ".\\dist\\windows\\ferro-desktop-0.1.0.msi",
  [string]$TimestampUrl = "http://timestamp.digicert.com"
)

$ErrorActionPreference = "Stop"

if (!(Test-Path $MsiPath)) {
  throw "Missing MSI: $MsiPath"
}

if ([string]::IsNullOrWhiteSpace($env:WINDOWS_PFX_BASE64)) {
  throw "WINDOWS_PFX_BASE64 env var is required"
}
if ([string]::IsNullOrWhiteSpace($env:WINDOWS_PFX_PASSWORD)) {
  throw "WINDOWS_PFX_PASSWORD env var is required"
}

$signtool = Get-Command signtool.exe -ErrorAction SilentlyContinue
if ($null -eq $signtool) {
  throw "signtool.exe not found"
}

$pfxPath = Join-Path $env:RUNNER_TEMP ("codesign-" + [guid]::NewGuid().ToString() + ".pfx")
try {
  [IO.File]::WriteAllBytes($pfxPath, [Convert]::FromBase64String($env:WINDOWS_PFX_BASE64))
  & signtool.exe sign /fd SHA256 /f $pfxPath /p $env:WINDOWS_PFX_PASSWORD /tr $TimestampUrl /td SHA256 $MsiPath
  if ($LASTEXITCODE -ne 0) { throw "signtool signing failed with exit code $LASTEXITCODE" }
  & signtool.exe verify /pa /all /v $MsiPath
  if ($LASTEXITCODE -ne 0) { throw "signtool verification failed with exit code $LASTEXITCODE" }
  Write-Host "signed windows artifact: $MsiPath"
} finally {
  if (Test-Path $pfxPath) { Remove-Item -LiteralPath $pfxPath -Force }
}
