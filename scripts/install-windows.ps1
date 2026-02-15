param(
  [ValidateSet('binary','source')]
  [string]$Method = 'binary',
  [string]$Version = 'latest',
  [string]$Repo = 'dgtise25/ferrocrate',
  [string]$Prefix = "$env:ProgramFiles\FerroCrate\bin",
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

function Install-File {
  param([string]$Source,[string]$Destination,[switch]$Force)
  if ((Test-Path $Destination) -and (-not $Force)) {
    throw "File exists: $Destination (use -Force to overwrite)"
  }
  New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Destination) | Out-Null
  Copy-Item -Path $Source -Destination $Destination -Force
}

function Install-BinariesFromDir {
  param([string]$Dir,[string]$Prefix,[switch]$Force)

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
  if ($desktop) {
    Install-File -Source $desktop -Destination (Join-Path $Prefix 'ferro-desktop.exe') -Force:$Force
  }
}

function Install-BinaryRelease {
  param([string]$Repo,[string]$Version,[string]$Prefix,[switch]$Force)

  Require-Command -Name 'Invoke-WebRequest'
  $arch = Get-ArchName
  $tag = Resolve-ReleaseTag -Repo $Repo -Version $Version

  $assetName = "ferrocrate-$tag-windows-$arch.zip"
  $checksumName = "ferrocrate-$tag-checksums.txt"
  $baseUrl = "https://github.com/$Repo/releases/download/$tag"

  $tmp = Join-Path $env:TEMP ([guid]::NewGuid().ToString('N'))
  New-Item -ItemType Directory -Path $tmp | Out-Null
  try {
    $zipPath = Join-Path $tmp $assetName
    $checksumPath = Join-Path $tmp $checksumName

    Write-Host "Downloading $assetName"
    Invoke-WebRequest -Uri "$baseUrl/$assetName" -OutFile $zipPath

    Write-Host "Downloading $checksumName"
    Invoke-WebRequest -Uri "$baseUrl/$checksumName" -OutFile $checksumPath

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
    Install-BinariesFromDir -Dir $extractDir -Prefix $Prefix -Force:$Force
    Write-Host "Installed FerroCrate from release tag $tag"
  }
  finally {
    Remove-Item -Path $tmp -Recurse -Force -ErrorAction SilentlyContinue
  }
}

function Install-FromSource {
  param([string]$Repo,[string]$Version,[string]$Prefix,[switch]$Force)

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
      cargo build --release -p ferro-cli -p ferro-desktop
    }
    finally {
      Pop-Location
    }

    $out = Join-Path $tmp 'unpack'
    New-Item -ItemType Directory -Path $out | Out-Null
    Copy-Item (Join-Path $src 'target\release\ferro-cli.exe') (Join-Path $out 'ferrocrate.exe')
    if (Test-Path (Join-Path $src 'target\release\ferro-desktop.exe')) {
      Copy-Item (Join-Path $src 'target\release\ferro-desktop.exe') (Join-Path $out 'ferro-desktop.exe')
    }

    Install-BinariesFromDir -Dir $out -Prefix $Prefix -Force:$Force
    Write-Host 'Installed FerroCrate from source'
  }
  finally {
    Remove-Item -Path $tmp -Recurse -Force -ErrorAction SilentlyContinue
  }
}

switch ($Method) {
  'binary' { Install-BinaryRelease -Repo $Repo -Version $Version -Prefix $Prefix -Force:$Force }
  'source' { Install-FromSource -Repo $Repo -Version $Version -Prefix $Prefix -Force:$Force }
  default { throw "Invalid method: $Method" }
}

Write-Host "Done. Try: ferrocrate --help"
