[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot 'config\config.json'),
    [string]$InstallPath = (Join-Path $env:ProgramData 'RDPShield'),
    [switch]$StageFirewall,
    [switch]$RegisterTasks,
    [switch]$PlanOnly
)

$ErrorActionPreference = 'Stop'
if ($RegisterTasks -and -not $StageFirewall) {
    throw 'RegisterTasks requiere StageFirewall.'
}
if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    throw "No existe $ConfigPath"
}
$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$country = [string]$config.Country
$port = 0
$interval = 0
$hour = -1
if ($country -cnotmatch '^[A-Z]{2}$') { throw 'Country no valido.' }
if (-not [int]::TryParse([string]$config.RdpPort, [ref]$port) -or $port -lt 1 -or $port -gt 65535) { throw 'RdpPort no valido.' }
if (-not [int]::TryParse([string]$config.UpdateIntervalMinutes, [ref]$interval) -or $interval -lt 5 -or $interval -gt 1440) { throw 'UpdateIntervalMinutes debe estar entre 5 y 1440.' }
if (-not [int]::TryParse([string]$config.CountryUpdateHour, [ref]$hour) -or $hour -lt 0 -or $hour -gt 23) { throw 'CountryUpdateHour debe estar entre 0 y 23.' }
$emergency = @(& (Join-Path $PSScriptRoot 'src\RDPShield-Resolve-Emergency.ps1') -ConfigPath $ConfigPath -ResolveOnly)
if ($emergency.Count -eq 0) { throw 'EmergencyAccess no es valido.' }
if ($config.EnableIPBanIntegration -eq $true -and $StageFirewall -and -not $PlanOnly) {
    & (Join-Path $PSScriptRoot 'src\RDPShield-Sync-IPBan.ps1') -ConfigPath $ConfigPath -PlanOnly | Out-Null
}

$fullInstallPath = [System.IO.Path]::GetFullPath($InstallPath)
if (Test-Path -LiteralPath $fullInstallPath) {
    throw "La ruta de instalacion ya existe: $fullInstallPath. Esta version no actualiza instalaciones existentes."
}

$plan = [pscustomobject]@{
    InstallPath = $fullInstallPath
    Country = $country
    RdpPort = $port
    EmergencyIPv4 = $emergency
    StageFirewall = [bool]$StageFirewall
    RegisterTasks = [bool]$RegisterTasks
    IPBanIntegration = [bool]$config.EnableIPBanIntegration
    CountryUpdateHour = $hour
    EmergencyUpdateMinutes = $interval
}
if ($PlanOnly) { $plan; return }

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'La instalacion requiere privilegios de administrador.'
}
if (-not $PSCmdlet.ShouldProcess($fullInstallPath, 'Preparar RDP Shield')) { return }

foreach ($subdir in @('src', 'config', 'data', 'backup')) {
    [System.IO.Directory]::CreateDirectory((Join-Path $fullInstallPath $subdir)) | Out-Null
}
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'config\config.example.json') -Destination (Join-Path $fullInstallPath 'config\config.example.json')
Copy-Item -LiteralPath $ConfigPath -Destination (Join-Path $fullInstallPath 'config\config.json')
Get-ChildItem -LiteralPath (Join-Path $PSScriptRoot 'src') -Filter '*.ps1' -File |
    Copy-Item -Destination (Join-Path $fullInstallPath 'src')

$installedConfig = Join-Path $fullInstallPath 'config\config.json'
& (Join-Path $fullInstallPath 'src\RDPShield-Update-Country.ps1') -ConfigPath $installedConfig

if ($StageFirewall) {
    & (Join-Path $fullInstallPath 'src\RDPShield-Apply-Firewall.ps1') -ConfigPath $installedConfig -StageOnly
    if ($config.EnableIPBanIntegration -eq $true) {
        & (Join-Path $fullInstallPath 'src\RDPShield-Sync-IPBan.ps1') -ConfigPath $installedConfig
    }
}

if ($RegisterTasks) {
    $powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $principalTask = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $countryScript = Join-Path $fullInstallPath 'src\RDPShield-Refresh-Country.ps1'
    $emergencyScript = Join-Path $fullInstallPath 'src\RDPShield-Refresh-Emergency.ps1'
    $countryAction = New-ScheduledTaskAction -Execute $powershell -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$countryScript`""
    $emergencyAction = New-ScheduledTaskAction -Execute $powershell -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$emergencyScript`""
    $countryTrigger = New-ScheduledTaskTrigger -Daily -At ([datetime]::Today.AddHours($hour))
    $emergencyTrigger = New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) `
        -RepetitionInterval (New-TimeSpan -Minutes $interval) -RepetitionDuration (New-TimeSpan -Days 3650)
    Register-ScheduledTask -TaskName 'RDPShield-Update-Country' -Action $countryAction -Trigger $countryTrigger -Principal $principalTask -Force | Out-Null
    Register-ScheduledTask -TaskName 'RDPShield-Update-Emergency' -Action $emergencyAction -Trigger $emergencyTrigger -Principal $principalTask -Force | Out-Null
}

$plan
Write-Warning 'La instalacion esta preparada. Revise RDPShield-Status.ps1: otras reglas Allow pueden seguir abriendo RDP.'
