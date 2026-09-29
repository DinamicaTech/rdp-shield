[CmdletBinding()]
param([string]$StatePath = (Join-Path $PSScriptRoot '..\data\migration-active.json'))

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $StatePath -PathType Leaf)) { throw "No existe $StatePath" }
$state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
if ($state.Status -ne 'Pending') { Write-Host "Migracion: $($state.Status)."; return }

$errors = @()
foreach ($name in @($state.DisabledRules)) {
    try {
        $rule = Get-NetFirewallRule -PolicyStore PersistentStore -Name $name -ErrorAction Stop
        if (@($rule).Count -ne 1 -or $rule.Name -ne $name) { throw "Regla ambigua: $name" }
        Set-NetFirewallRule -PolicyStore PersistentStore -Name $name -Enabled True -ErrorAction Stop
    } catch { $errors += "$name : $($_.Exception.Message)" }
}
if ($errors.Count -gt 0) { throw "No se pudieron restaurar todas las reglas: $($errors -join '; ')" }

$task = Get-ScheduledTask -TaskName 'RDPShield-Migration-Rollback' -ErrorAction SilentlyContinue
if ($null -ne $task) { Unregister-ScheduledTask -TaskName 'RDPShield-Migration-Rollback' -Confirm:$false }
$state.Status = 'RolledBack'
$state | Add-Member -NotePropertyName CompletedAt -NotePropertyValue ((Get-Date).ToUniversalTime().ToString('o')) -Force
$state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $StatePath -Encoding UTF8
Write-Host "Migracion revertida. Reglas restauradas: $(@($state.DisabledRules).Count)."
