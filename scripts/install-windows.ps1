param(
  [ValidateSet('binary','source')]
  [string]$Method = 'binary',
  [ValidateSet('public','paid')]
  [string]$Channel = 'public',
  [string]$Version = 'latest',
  [string]$Repo = 'dgtise25/ferrocrate',
  [string]$Prefix = "$env:ProgramFiles\FerroCrate\bin",
  [string]$PaidReleaseBaseUrl = $env:PAID_RELEASE_BASE_URL,
  [string]$PaidReleaseToken = $env:PAID_RELEASE_TOKEN,
  [string]$PaidSessionToken = $env:PAID_SESSION_TOKEN,
  [string]$PaidReleaseTokenEndpoint = $env:PAID_RELEASE_TOKEN_ENDPOINT,
  [string]$PaidEntitlementFile = $(if ($env:PAID_ENTITLEMENT_FILE) { $env:PAID_ENTITLEMENT_FILE } else { Join-Path $HOME '.ferrocrate\entitlement.lic' }),
  [switch]$WithDesktopBin,
  [switch]$FullStack,
  [switch]$CliOnly,
  [switch]$Force
)

$ErrorActionPreference = 'Stop'

function Require-Command {
  param([string]$Name)
  if (-not (Get-Command $Name -ErrorAction SilentlyContinue)) {
    throw "Missing required command: $Name"
  }
}

function Get-ArchName {
  switch ($env:PROCESSOR_ARCHITECTURE.ToUpperInvariant()) {
    'AMD64' { return 'x86_64' }
    'ARM64' { return 'aarch64' }
    default { throw "Unsupported Windows architecture: $env:PROCESSOR_ARCHITECTURE" }
  }
}

function Resolve-ReleaseTag {
  param([string]$Repo,[string]$Version)
  if ($Version -ne 'latest') { return $Version }
  $resp = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest"
  if ([string]::IsNullOrWhiteSpace($resp.tag_name)) {
    throw 'Failed to resolve latest release tag from GitHub API'
  }
  return [string]$resp.tag_name
}

function Resolve-PaidReleaseToken {
  param([string]$Token,[string]$SessionToken,[string]$Endpoint,[string]$EntitlementFile,[string]$Tag = 'latest')
  if (-not [string]::IsNullOrWhiteSpace($Token)) {
    return $Token
  }
  if (-not [string]::IsNullOrWhiteSpace($SessionToken)) {
    if ([string]::IsNullOrWhiteSpace($Endpoint)) {
      throw 'Paid channel with -PaidSessionToken requires -PaidReleaseTokenEndpoint.'
    }
    $sessionHeaders = @{
      Authorization = "Bearer $SessionToken"
      'X-Ferrocrate-Tag' = $Tag
    }
    $sessionResp = Invoke-RestMethod -Uri $Endpoint -Method Post -Headers $sessionHeaders
    if ([string]::IsNullOrWhiteSpace($sessionResp.token)) {
      throw 'Token endpoint response did not contain a token for session auth'
    }
    return [string]$sessionResp.token
  }
  if ([string]::IsNullOrWhiteSpace($Endpoint)) {
    throw 'Paid channel requires -PaidReleaseToken (or PAID_RELEASE_TOKEN) or -PaidReleaseTokenEndpoint (or PAID_RELEASE_TOKEN_ENDPOINT).'
  }
  if (-not (Test-Path $EntitlementFile)) {
    throw "Paid channel token exchange requires entitlement file: $EntitlementFile"
  }
  $body = Get-Content -Raw -Path $EntitlementFile
  $headers = @{
    'X-Ferrocrate-Tag' = $Tag
  }
  $resp = Invoke-RestMethod -Uri $Endpoint -Method Post -ContentType 'application/json' -Body $body -Headers $headers
  if ([string]::IsNullOrWhiteSpace($resp.token)) {
    throw 'Token endpoint response did not contain a token'
  }
  return [string]$resp.token
}

function Install-File {
  param([string]$Source,[string]$Destination,[switch]$Force)
  if ((Test-Path $Destination) -and (-not $Force)) {
    throw "File exists: $Destination (use -Force to overwrite)"
  }
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Destination) | Out-Null
  Copy-Item -Path $Source -Destination $Destination -Force
}

function Install-BinariesFromDir {
  param([string]$Dir,[string]$Prefix,[bool]$InstallDesktopBin,[switch]$Force)

  $ferrocrateCandidates = @(
    (Join-Path $Dir 'ferrocrate.exe'),
    (Join-Path $Dir 'ferro-cli.exe'),
    (Join-Path $Dir 'ferrocrate\ferrocrate.exe')
  )
  $desktopCandidates = @(
    (Join-Path $Dir 'ferro-desktop.exe'),
    (Join-Path $Dir 'ferrocrate\ferro-desktop.exe')
  )

  $ferrocrate = $ferrocrateCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
  if (-not $ferrocrate) {
    throw "Could not find ferrocrate.exe in extracted artifact: $Dir"
  }

  $desktop = $desktopCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1

  New-Item -ItemType Directory -Force -Path $Prefix | Out-Null
  Install-File -Source $ferrocrate -Destination (Join-Path $Prefix 'ferrocrate.exe') -Force:$Force
  if ($InstallDesktopBin -and $desktop) {
    Install-File -Source $desktop -Destination (Join-Path $Prefix 'ferro-desktop.exe') -Force:$Force
  } elseif ($InstallDesktopBin) {
    throw 'Desktop binary requested but artifact did not contain ferro-desktop.exe. Use -Channel paid with -PaidReleaseBaseUrl (or PAID_RELEASE_BASE_URL) or install from source.'
  }
}

function Install-BinaryRelease {
  param([string]$Repo,[string]$Version,[string]$Prefix,[string]$Channel,[string]$PaidReleaseBaseUrl,[string]$PaidReleaseToken,[string]$PaidSessionToken,[string]$PaidReleaseTokenEndpoint,[string]$PaidEntitlementFile,[bool]$InstallDesktopBin,[switch]$Force)

  Require-Command -Name 'Invoke-WebRequest'
  $arch = Get-ArchName
  $tag = Resolve-ReleaseTag -Repo $Repo -Version $Version
  if ($Channel -eq 'paid') {
    $PaidReleaseToken = Resolve-PaidReleaseToken -Token $PaidReleaseToken -SessionToken $PaidSessionToken -Endpoint $PaidReleaseTokenEndpoint -EntitlementFile $PaidEntitlementFile -Tag $tag
  }

  $assetName = "ferrocrate-$tag-windows-$arch.zip"
  $checksumName = "ferrocrate-$tag-checksums.txt"
  if ($Channel -eq 'paid') {
    $checksumName = "ferrocrate-$tag-paid-checksums.txt"
  }
  if ($Channel -eq 'public') {
    $baseUrl = "https://github.com/$Repo/releases/download/$tag"
    $headers = @{}
  } else {
    if ([string]::IsNullOrWhiteSpace($PaidReleaseBaseUrl)) {
      throw 'Paid channel requires -PaidReleaseBaseUrl (or PAID_RELEASE_BASE_URL env).'
    }
    if ([string]::IsNullOrWhiteSpace($PaidReleaseToken)) {
      throw 'Paid channel requires token auth. Set -PaidReleaseToken or -PaidReleaseTokenEndpoint.'
    }
    $headers = @{
      Authorization = "Bearer $PaidReleaseToken"
      'X-Ferrocrate-Channel' = 'paid'
    }
    if ($PaidReleaseBaseUrl.Contains('{tag}')) {
      $baseUrl = $PaidReleaseBaseUrl.Replace('{tag}', $tag)
    } else {
      $baseUrl = ($PaidReleaseBaseUrl.TrimEnd('/') + "/$tag")
    }
  }

  $tmp = Join-Path $env:TEMP ([guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $tmp | Out-Null
  try {
    $zipPath = Join-Path $tmp $assetName
    $checksumPath = Join-Path $tmp $checksumName

    Write-Host "Downloading $assetName"
    Invoke-WebRequest -Uri "$baseUrl/$assetName" -OutFile $zipPath -Headers $headers

    Write-Host "Downloading $checksumName"
    Invoke-WebRequest -Uri "$baseUrl/$checksumName" -OutFile $checksumPath -Headers $headers

    $expectedLine = Get-Content $checksumPath | Where-Object { $_ -match "\s+$([regex]::Escape($assetName))$" } | Select-Object -First 1
    if (-not $expectedLine) {
      throw "Checksum entry not found for $assetName in $checksumName"
    }
    $expected = ($expectedLine -split '\s+')[0].ToLowerInvariant()
    $actual = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($expected -ne $actual) {
      throw "Checksum mismatch for $assetName. Expected=$expected Actual=$actual"
    }

    $extractDir = Join-Path $tmp 'unpack'
    Expand-Archive -Path $zipPath -DestinationPath $extractDir -Force
    Install-BinariesFromDir -Dir $extractDir -Prefix $Prefix -InstallDesktopBin:$InstallDesktopBin -Force:$Force
    Write-Host "Installed FerroCrate from release tag $tag"
  }
  finally {
    Remove-Item -Path $tmp -Recurse -Force -ErrorAction SilentlyContinue
  }
}

function Install-FromSource {
  param([string]$Repo,[string]$Version,[string]$Prefix,[bool]$InstallDesktopBin,[switch]$Force)

  Require-Command -Name 'git'
  Require-Command -Name 'cargo'

  $tmp = Join-Path $env:TEMP ([guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $tmp | Out-Null
  try {
    $src = Join-Path $tmp 'src'
    git clone "https://github.com/$Repo.git" $src --depth 1 | Out-Null
    if ($Version -ne 'latest') {
      Push-Location $src
      try {
        git fetch --tags --depth 1 | Out-Null
        git checkout $Version | Out-Null
      }
      finally {
        Pop-Location
      }
    }

    Push-Location $src
    try {
      $buildPackages = @('-p','ferro-cli')
      if ($InstallDesktopBin) {
        $buildPackages += @('-p','ferro-desktop')
      }
      cargo build --release @buildPackages
    }
    finally {
      Pop-Location
    }

    $out = Join-Path $tmp 'unpack'
    New-Item -ItemType Directory -Path $out | Out-Null
    Copy-Item (Join-Path $src 'target\release\ferro-cli.exe') (Join-Path $out 'ferrocrate.exe')
    if ($InstallDesktopBin -and (Test-Path (Join-Path $src 'target\release\ferro-desktop.exe'))) {
      Copy-Item (Join-Path $src 'target\release\ferro-desktop.exe') (Join-Path $out 'ferro-desktop.exe')
    }

    Install-BinariesFromDir -Dir $out -Prefix $Prefix -InstallDesktopBin:$InstallDesktopBin -Force:$Force
    Write-Host 'Installed FerroCrate from source'
  }
  finally {
    Remove-Item -Path $tmp -Recurse -Force -ErrorAction SilentlyContinue
  }
}

function Enable-Wsl2Host {
  foreach ($feature in @('Microsoft-Windows-Subsystem-Linux', 'VirtualMachinePlatform')) {
    $state = (Get-WindowsOptionalFeature -Online -FeatureName $feature).State
    if ($state -ne 'Enabled') {
      Write-Host "Enabling Windows feature: $feature"
      Enable-WindowsOptionalFeature -Online -FeatureName $feature -All -NoRestart | Out-Null
    }
  }
  & wsl.exe --set-default-version 2 | Out-Null
}

function Ensure-WslUbuntu {
  param([string]$Distro = 'Ubuntu')
  $installed = @(& wsl.exe --list --quiet 2>$null) | ForEach-Object { $_.Trim([char]0).Trim() }
  if ($installed -notcontains $Distro) {
    Write-Host "Installing WSL2 distro: $Distro"
    & wsl.exe --install --distribution Ubuntu --no-launch
    if ($LASTEXITCODE -ne 0) {
      throw 'WSL Ubuntu installation failed; reboot Windows if the feature enablement requires it.'
    }
  }
  & wsl.exe --set-version $Distro 2 | Out-Null
}

function Provision-WslDaemon {
  param([string]$Distro = 'Ubuntu',[string]$Repo,[string]$Version)
  $guestScript = @'
set -euo pipefail
runtime="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}"
mkdir -p "$runtime" "$HOME/.config/systemd/user" "$HOME/.local/state/ferrocrate"
if ! command -v ferrocrate >/dev/null 2>&1; then
  sudo apt-get update
  sudo apt-get install -y curl ca-certificates tar
  arch="$(uname -m)"
  case "$arch" in x86_64|amd64) arch=x86_64 ;; aarch64|arm64) arch=aarch64 ;; *) exit 1 ;; esac
  tag="$FERROCRATE_INSTALL_VERSION"
  if [ "$tag" = latest ]; then
    tag="$(curl -fsSL "https://api.github.com/repos/$FERROCRATE_INSTALL_REPO/releases/latest" | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"
  fi
  tmp="$(mktemp -d)"
  curl -fL "https://github.com/$FERROCRATE_INSTALL_REPO/releases/download/$tag/ferrocrate-$tag-linux-$arch.tar.gz" -o "$tmp/ferrocrate.tgz"
  tar -xzf "$tmp/ferrocrate.tgz" -C "$tmp"
  binary="$(find "$tmp" -type f \( -name ferrocrate -o -name ferro-cli \) | head -1)"
  sudo install -m 0755 "$binary" /usr/local/bin/ferrocrate
  rm -rf "$tmp"
fi
cat >"$HOME/.config/systemd/user/ferrocrate-daemon.service" <<'UNIT'
[Unit]
Description=Ferrocrate rootless daemon
[Service]
ExecStart=/usr/local/bin/ferrocrate daemon --docker-compat
Restart=on-failure
RestartSec=2
[Install]
WantedBy=default.target
UNIT
if systemctl --user daemon-reload >/dev/null 2>&1; then
  systemctl --user enable --now ferrocrate-daemon.service
else
  pidfile="$HOME/.local/state/ferrocrate/ferrocrate-daemon.pid"
  if ! test -s "$pidfile" || ! kill -0 "$(cat "$pidfile")" 2>/dev/null; then
    nohup ferrocrate daemon --docker-compat >"$HOME/.local/state/ferrocrate/daemon.log" 2>&1 &
    echo $! >"$pidfile"
  fi
fi
'@
  & wsl.exe -d $Distro -- env "FERROCRATE_INSTALL_REPO=$Repo" "FERROCRATE_INSTALL_VERSION=$Version" bash -lc $guestScript
  if ($LASTEXITCODE -ne 0) { throw "Failed to provision Ferrocrate daemon in $Distro" }
}

function Start-WslNamedPipeRelay {
  param([string]$Prefix,[string]$Distro = 'Ubuntu')
  $desktop = Join-Path $Prefix 'ferro-desktop.exe'
  if (-not (Test-Path $desktop)) { throw "Desktop relay binary is missing: $desktop" }
  $stateDir = Join-Path $env:LOCALAPPDATA 'Ferrocrate'
  New-Item -ItemType Directory -Force -Path $stateDir | Out-Null
  $pidPath = Join-Path $stateDir 'wsl-relay.pid'
  if (Test-Path $pidPath) {
    $existingPid = [int](Get-Content -Raw $pidPath)
    if (Get-Process -Id $existingPid -ErrorAction SilentlyContinue) { return }
  }
  # The pipe is local to this Windows host; the relay executes every request via wsl.exe.
  $process = Start-Process -FilePath $desktop -ArgumentList @('daemon','--pipe-name','ferrocrate','--wsl-distro',$Distro,'--addr','127.0.0.1:4288') -WindowStyle Hidden -PassThru
  Set-Content -Path $pidPath -Value $process.Id
}

if ($FullStack -and $Channel -eq 'public') {
  throw '-FullStack requires -Channel paid (desktop artifacts are paid-channel only).'
}

$installDesktopBin = [bool]$WithDesktopBin
if ($CliOnly) {
  $installDesktopBin = $false
} elseif ($FullStack -or ($Channel -eq 'paid' -and -not $WithDesktopBin -and -not $CliOnly)) {
  $installDesktopBin = $true
}

if ($installDesktopBin) {
  Write-Host 'Desktop binary install enabled (-WithDesktopBin).'
}

switch ($Method) {
  'binary' { Install-BinaryRelease -Repo $Repo -Version $Version -Prefix $Prefix -Channel $Channel -PaidReleaseBaseUrl $PaidReleaseBaseUrl -PaidReleaseToken $PaidReleaseToken -PaidSessionToken $PaidSessionToken -PaidReleaseTokenEndpoint $PaidReleaseTokenEndpoint -PaidEntitlementFile $PaidEntitlementFile -InstallDesktopBin:$installDesktopBin -Force:$Force }
  'source' { Install-FromSource -Repo $Repo -Version $Version -Prefix $Prefix -InstallDesktopBin:$installDesktopBin -Force:$Force }
  default { throw "Invalid method: $Method" }
}

if ($installDesktopBin) {
  Enable-Wsl2Host
  Ensure-WslUbuntu -Distro 'Ubuntu'
  Provision-WslDaemon -Distro 'Ubuntu' -Repo $Repo -Version $Version
  Start-WslNamedPipeRelay -Prefix $Prefix -Distro 'Ubuntu'
}

Write-Host "Done. Try: ferrocrate --help"
