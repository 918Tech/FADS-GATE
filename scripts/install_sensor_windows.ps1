#requires -RunAsAdministrator
$ErrorActionPreference = "Stop"

if (-not $env:FADS_ENROLLMENT_KEY) { throw "Set FADS_ENROLLMENT_KEY for one-time enrollment." }
if (-not $env:FADS_REGION) { throw "Set FADS_REGION to the protected asset region." }

$AssetId = if ($env:FADS_ASSET_ID) { $env:FADS_ASSET_ID } else { $env:COMPUTERNAME }
$Ref = if ($env:FADS_VERSION_REF) { $env:FADS_VERSION_REF } else { "main" }
$Base = Join-Path $env:ProgramData "918 Technologies\FADS"
$Venv = Join-Path $Base "venv"
$TokenFile = Join-Path $Base "fads.asset"
$SensorExe = Join-Path $Venv "Scripts\fads-universal-sensor.exe"
$EnrollExe = Join-Path $Venv "Scripts\fads-enroll-asset.exe"
$VenvPython = Join-Path $Venv "Scripts\python.exe"

New-Item -ItemType Directory -Force -Path $Base | Out-Null
$Python = (Get-Command python.exe -ErrorAction Stop).Source
& $Python -m venv $Venv
& $VenvPython -m pip install --upgrade pip
& $VenvPython -m pip install "git+https://github.com/918Tech/FADS-GATE.git@$Ref"
& $EnrollExe --asset-id $AssetId --region $env:FADS_REGION --platform windows --output $TokenFile

$acl = Get-Acl $TokenFile
$acl.SetAccessRuleProtection($true, $false)
$ruleSystem = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM","FullControl","Allow")
$ruleAdmins = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl","Allow")
$acl.AddAccessRule($ruleSystem)
$acl.AddAccessRule($ruleAdmins)
Set-Acl -Path $TokenFile -AclObject $acl

$Action = New-ScheduledTaskAction -Execute $SensorExe -Argument ('--token-file "' + $TokenFile + '" --interval 60')
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -RestartCount 5 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName "918 FADS Universal Sensor" -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force | Out-Null
Start-ScheduledTask -TaskName "918 FADS Universal Sensor"
Remove-Item Env:FADS_ENROLLMENT_KEY -ErrorAction SilentlyContinue
Write-Host "918 FADS Universal Sensor installed and started."
Get-ScheduledTask -TaskName "918 FADS Universal Sensor" | Format-List TaskName,State
