$ErrorActionPreference = "Stop"
$binary = Join-Path $PSScriptRoot "ferro-desktop.exe"
$action = New-ScheduledTaskAction -Execute $binary -Argument "serve"
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName "FerroCrate Desktop Supervisor" -Action $action -Trigger $trigger -Force
