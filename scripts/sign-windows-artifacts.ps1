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
$signtoolPath = 'signtool.exe'
if ($null -eq $signtool) {
  $sdkBin = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
  $signtoolPath = Get-ChildItem -Path $sdkBin -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '\\x64\\signtool\.exe$' } |
    Select-Object -First 1 -ExpandProperty FullName
  if ([string]::IsNullOrWhiteSpace($signtoolPath)) {
    throw "signtool.exe not found"
  }
}

$pfxPath = Join-Path $env:RUNNER_TEMP ("codesign-" + [guid]::NewGuid().ToString() + ".pfx")
try {
  [IO.File]::WriteAllBytes($pfxPath, [Convert]::FromBase64String($env:WINDOWS_PFX_BASE64))
  & $signtoolPath sign /fd SHA256 /f $pfxPath /p $env:WINDOWS_PFX_PASSWORD /tr $TimestampUrl /td SHA256 $MsiPath
  if ($LASTEXITCODE -ne 0) { throw "signtool signing failed with exit code $LASTEXITCODE" }
  & $signtoolPath verify /pa /all /v $MsiPath
  if ($LASTEXITCODE -ne 0) { throw "signtool verification failed with exit code $LASTEXITCODE" }
  Write-Host "signed windows artifact: $MsiPath"
} finally {
  if (Test-Path $pfxPath) { Remove-Item -LiteralPath $pfxPath -Force }
}
