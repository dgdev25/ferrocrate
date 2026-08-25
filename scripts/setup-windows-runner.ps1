[CmdletBinding()]
param(
    [string]$ProfileRoot = 'E:\ferrocrate-runner-profile'
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Tauri extracts its NSIS and WiX toolchains below LOCALAPPDATA.  The SYSTEM
# profile is not a usable location for makensis child processes, so self-hosted
# SYSTEM runners use this stable, writable profile root instead.
$localAppData = Join-Path $ProfileRoot 'AppData\Local'
$appData = Join-Path $ProfileRoot 'AppData\Roaming'
$temp = Join-Path $ProfileRoot 'Temp'

New-Item -ItemType Directory -Force -Path $localAppData, $appData, $temp | Out-Null
