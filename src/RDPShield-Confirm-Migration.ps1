[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot '..\config\config.json'),
    [string]$StatePath = (Join-Path $PSScriptRoot '..\data\migration-active.json'),
    [switch]$VerifiedNewConnection
)

$ErrorActionPreference = 'Stop'
if (-not $VerifiedNewConnection) {
    throw 'Pruebe una NUEVA conexion RDP desde la IP de recuperacion y repita con -VerifiedNewConnection.'
}
if (-not (Test-Path -LiteralPath $StatePath -PathType Leaf)) { throw "No existe $StatePath" }
$state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
if ($state.Status -ne 'Pending') { throw "La migracion no esta pendiente: $($state.Status)" }
$rollbackAt = if ($state.RollbackAt -is [datetime]) {
    $state.RollbackAt.ToUniversalTime()
} else {
    [datetime]::Parse([string]$state.RollbackAt, [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
}
if ((Get-Date).ToUniversalTime() -ge $rollbackAt) {
    throw 'El plazo de confirmacion ha terminado; compruebe si se ejecuto la reversion.'
}
$conflicts = @(& (Join-Path $PSScriptRoot 'RDPShield-Audit-Firewall.ps1') -ConfigPath $ConfigPath)
if ($conflicts.Count -gt 0) { throw "Aun hay $($conflicts.Count) reglas Allow que pueden abrir RDP." }
foreach ($name in @('RDPShield-Country-TCP', 'RDPShield-Country-UDP',
        'RDPShield-Emergency-TCP', 'RDPShield-Emergency-UDP')) {
    $rule = Get-NetFirewallRule -PolicyStore ActiveStore -Name $name -ErrorAction Stop
    if (@($rule).Count -ne 1 -or [string]$rule.Enabled -ne 'True') { throw "La regla $name no esta activa." }
}
$task = Get-ScheduledTask -TaskName 'RDPShield-Migration-Rollback' -ErrorAction Stop
if ($null -eq $task) { throw 'No se encuentra la tarea de reversion.' }
Unregister-ScheduledTask -TaskName 'RDPShield-Migration-Rollback' -Confirm:$false
$state.Status = 'Confirmed'
$state | Add-Member -NotePropertyName CompletedAt -NotePropertyValue ((Get-Date).ToUniversalTime().ToString('o')) -Force
$state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $StatePath -Encoding UTF8
Write-Host 'Migracion confirmada; tarea de reversion cancelada.'
