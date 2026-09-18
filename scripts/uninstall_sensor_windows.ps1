#requires -RunAsAdministrator
$ErrorActionPreference = "Stop"
Unregister-ScheduledTask -TaskName "918 FADS Universal Sensor" -Confirm:$false -ErrorAction SilentlyContinue
$Base = Join-Path $env:ProgramData "918 Technologies\FADS"
$Venv = Join-Path $Base "venv"
if (Test-Path $Venv) { Remove-Item -Recurse -Force $Venv }
Write-Host "Sensor task and binaries removed. Enrollment token remains in $Base unless you delete it explicitly."
