[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot '..\config\config.json'),
    [Parameter(Mandatory = $true)][string[]]$DisableRuleNames,
    [Parameter(Mandatory = $true)][string]$RecoveryAddress,
    [ValidateRange(5, 60)][int]$RollbackMinutes = 10,
    [string]$StatePath = (Join-Path $PSScriptRoot '..\data\migration-active.json'),
    [switch]$PlanOnly
)

$ErrorActionPreference = 'Stop'
$parsed = $null
if (-not [System.Net.IPAddress]::TryParse($RecoveryAddress, [ref]$parsed) -or
    $parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
    throw 'RecoveryAddress debe ser una IPv4.'
}
$RecoveryAddress = $parsed.ToString()
$emergency = @(& (Join-Path $PSScriptRoot 'RDPShield-Resolve-Emergency.ps1') -ConfigPath $ConfigPath -ResolveOnly)
if ($emergency -notcontains $RecoveryAddress) {
    throw 'RecoveryAddress debe estar en EmergencyAccess y resolver a la IP desde la que probara RDP.'
}
$profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop)
if (@($profiles | Where-Object { [string]$_.Enabled -ne 'True' -or [string]$_.DefaultInboundAction -eq 'Allow' }).Count -gt 0) {
    throw 'El firewall debe estar activo y sin politica de entrada Allow en todos los perfiles.'
}
if (Test-Path -LiteralPath $StatePath -PathType Leaf) {
    $previous = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
    if ($previous.Status -eq 'Pending') { throw 'Ya existe una migracion pendiente.' }
}
if ($null -ne (Get-ScheduledTask -TaskName 'RDPShield-Migration-Rollback' -ErrorAction SilentlyContinue)) {
    throw 'Ya existe una tarea de reversion pendiente.'
}

foreach ($name in @('RDPShield-Country-TCP', 'RDPShield-Country-UDP',
        'RDPShield-Emergency-TCP', 'RDPShield-Emergency-UDP')) {
    $rule = Get-NetFirewallRule -PolicyStore ActiveStore -Name $name -ErrorAction Stop
    if (@($rule).Count -ne 1 -or [string]$rule.Enabled -ne 'True' -or $rule.Group -ne 'RDPShield') {
        throw "La regla propia $name no esta activa y verificada."
    }
    if ($name -eq 'RDPShield-Emergency-TCP') {
        $remote = @($rule | Get-NetFirewallAddressFilter | Select-Object -ExpandProperty RemoteAddress)
        if ($remote -notcontains $RecoveryAddress) { throw 'La regla de emergencia TCP no contiene RecoveryAddress.' }
    }
}

$audit = @(& (Join-Path $PSScriptRoot 'RDPShield-Audit-Firewall.ps1') -ConfigPath $ConfigPath)
$requested = @($DisableRuleNames | Sort-Object -Unique)
if ($requested.Count -eq 0) { throw 'Indique al menos una regla que deshabilitar.' }
foreach ($name in $requested) {
    if ($name -like 'RDPShield-*' -or $name -like 'IPBan*') { throw "No se puede migrar una regla de RDP Shield o IPBan: $name" }
    $matches = @($audit | Where-Object { $_.Name -eq $name })
    if ($matches.Count -ne 1) { throw "La regla $name no aparece una sola vez en la auditoria." }
    $local = Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction Stop
    if (@($local).Count -ne 1 -or $local.Name -ne $name -or
        [string]$local.Enabled -ne 'True' -or $local.Action -ne 'Allow') {
        throw "La regla $name no es una regla Allow local activa y unica."
    }
}
$remaining = @($audit | Where-Object { $requested -notcontains $_.Name })
if ($remaining.Count -gt 0) {
    throw "Quedan $($remaining.Count) reglas Allow sin resolver. Revise la auditoria antes de migrar."
}

$plan = [pscustomobject]@{
    DisableRules = $requested
    RecoveryAddress = $RecoveryAddress
    RollbackMinutes = $RollbackMinutes
    StatePath = [System.IO.Path]::GetFullPath($StatePath)
}
if ($PlanOnly) { $plan; return }
if (-not $PSCmdlet.ShouldProcess(($requested -join ', '), 'Deshabilitar reglas con reversion programada')) { return }

$scheduler = Get-Service -Name 'Schedule' -ErrorAction Stop
if ($scheduler.Status -ne 'Running') { throw 'El Programador de tareas no esta en ejecucion; no se deshabilitaran reglas.' }
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Se requieren privilegios de administrador.' }
$backupDirectory = Join-Path $PSScriptRoot '..\backup'
[System.IO.Directory]::CreateDirectory($backupDirectory) | Out-Null
$backupPath = Join-Path $backupDirectory ("firewall-before-migration-$(Get-Date -Format 'yyyyMMdd-HHmmss').wfw")
& netsh advfirewall export $backupPath | Out-Null
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $backupPath -PathType Leaf)) {
    throw 'No se pudo exportar el firewall; no se han deshabilitado reglas.'
}
$deadline = (Get-Date).AddMinutes($RollbackMinutes)
$state = [pscustomobject]@{
    Status = 'Pending'
    DisabledRules = $requested
    RecoveryAddress = $RecoveryAddress
    RollbackAt = $deadline.ToUniversalTime().ToString('o')
    CreatedAt = (Get-Date).ToUniversalTime().ToString('o')
    FirewallBackupPath = $backupPath
}
[System.IO.Directory]::CreateDirectory((Split-Path -Parent $StatePath)) | Out-Null
$state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $StatePath -Encoding UTF8

$powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$rollbackScript = Join-Path $PSScriptRoot 'RDPShield-Rollback-Migration.ps1'
$action = New-ScheduledTaskAction -Execute $powershell -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$rollbackScript`" -StatePath `"$StatePath`""
$trigger = New-ScheduledTaskTrigger -Once -At $deadline
$taskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$taskSettings = New-ScheduledTaskSettingsSet -StartWhenAvailable
try {
    Register-ScheduledTask -TaskName 'RDPShield-Migration-Rollback' -Action $action -Trigger $trigger -Principal $taskPrincipal -Settings $taskSettings -ErrorAction Stop | Out-Null
    if ($null -eq (Get-ScheduledTask -TaskName 'RDPShield-Migration-Rollback' -ErrorAction Stop)) {
        throw 'No se pudo verificar la tarea de reversion.'
    }
} catch {
    $task = Get-ScheduledTask -TaskName 'RDPShield-Migration-Rollback' -ErrorAction SilentlyContinue
    if ($null -ne $task) { Unregister-ScheduledTask -TaskName 'RDPShield-Migration-Rollback' -Confirm:$false }
    Remove-Item -LiteralPath $StatePath -ErrorAction SilentlyContinue
    throw "No se han deshabilitado reglas porque fallo la tarea de reversion: $($_.Exception.Message)"
}

try {
    foreach ($name in $requested) {
        Set-NetFirewallRule -PolicyStore PersistentStore -Name $name -Enabled False -ErrorAction Stop
    }
    $after = @(& (Join-Path $PSScriptRoot 'RDPShield-Audit-Firewall.ps1') -ConfigPath $ConfigPath)
    if ($after.Count -gt 0) { throw "La auditoria aun encuentra $($after.Count) reglas Allow." }
} catch {
    $reason = $_.Exception.Message
    & (Join-Path $PSScriptRoot 'RDPShield-Rollback-Migration.ps1') -StatePath $StatePath
    throw "Migracion revertida tras un error: $reason"
}

$plan
Write-Warning "Abra una NUEVA conexion RDP desde $RecoveryAddress. Confirme antes de $deadline con RDPShield-Confirm-Migration.ps1 -VerifiedNewConnection; si no, las reglas anteriores se restauraran. Copia: $backupPath"
