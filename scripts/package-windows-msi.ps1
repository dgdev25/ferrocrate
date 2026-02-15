$ErrorActionPreference = "Stop"

param(
  [string]$BinaryPath = ".\\target\\release\\ferro-desktop.exe",
  [string]$OutputDir = ".\\dist\\windows",
  [string]$ProductVersion = "0.1.0"
)

if (!(Test-Path $BinaryPath)) {
  throw "Missing binary: $BinaryPath"
}

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

$wix = Get-Command wix -ErrorAction SilentlyContinue
if ($null -eq $wix) {
  throw "WiX CLI ('wix') is required. Install from https://wixtoolset.org/"
}

$wxsPath = Join-Path $OutputDir "ferro-desktop.wxs"
$msiPath = Join-Path $OutputDir "ferro-desktop-$ProductVersion.msi"
$binAbs = (Resolve-Path $BinaryPath).Path

@"
<?xml version="1.0" encoding="UTF-8"?>
<Wix xmlns="http://wixtoolset.org/schemas/v4/wxs">
  <Package Name="FerroCrate Desktop" Manufacturer="FerroCrate" Version="$ProductVersion" UpgradeCode="7E7D7B9F-0B74-47D3-8B58-6D219F6648C6">
    <StandardDirectory Id="ProgramFiles64Folder">
      <Directory Id="INSTALLFOLDER" Name="FerroCrate">
        <Component Id="FerroDesktopExe" Guid="*">
          <File Source="$binAbs" KeyPath="yes" />
        </Component>
      </Directory>
    </StandardDirectory>
    <Feature Id="MainFeature" Title="FerroCrate Desktop" Level="1">
      <ComponentRef Id="FerroDesktopExe" />
    </Feature>
  </Package>
</Wix>
"@ | Set-Content -NoNewline -Path $wxsPath

wix build $wxsPath -o $msiPath
Write-Host "created msi: $msiPath"
