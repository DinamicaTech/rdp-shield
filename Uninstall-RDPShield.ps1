[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$InstallPath = (Join-Path $env:ProgramData 'RDPShield'),
    [switch]$RemoveFirewallRules,
    [switch]$RemoveIPBanEntries
)

$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'La desinstalacion requiere privilegios de administrador.'
}
$migrationPath = Join-Path $InstallPath 'data\migration-active.json'
if (Test-Path -LiteralPath $migrationPath -PathType Leaf) {
    $migration = Get-Content -LiteralPath $migrationPath -Raw | ConvertFrom-Json
    if ($migration.Status -eq 'Pending') {
        throw 'Hay una migracion pendiente. Confirme o revierta antes de desinstalar.'
    }
}

if ($RemoveIPBanEntries -and $PSCmdlet.ShouldProcess('IPBan Whitelist', 'Eliminar solo entradas gestionadas por RDP Shield')) {
    $syncScript = Join-Path $InstallPath 'src\RDPShield-Sync-IPBan.ps1'
    if (-not (Test-Path -LiteralPath $syncScript -PathType Leaf)) { throw "No existe $syncScript" }
    & $syncScript -RemoveManaged
}

foreach ($taskName in @('RDPShield-Update-Country', 'RDPShield-Update-Emergency')) {
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    if ($null -ne $task -and $PSCmdlet.ShouldProcess($taskName, 'Eliminar tarea programada')) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }
}

if ($RemoveFirewallRules) {
    foreach ($ruleName in @('RDPShield-Country-TCP', 'RDPShield-Country-UDP',
            'RDPShield-Emergency-TCP', 'RDPShield-Emergency-UDP')) {
        $rule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
        if ($null -eq $rule) { continue }
        if (@($rule).Count -ne 1 -or $rule.Group -ne 'RDPShield') {
            throw "La regla $ruleName no pertenece a RDP Shield; no se elimina."
        }
        if ($PSCmdlet.ShouldProcess($ruleName, 'Eliminar regla de RDP Shield')) {
            Remove-NetFirewallRule -Name $ruleName
        }
    }
}

Write-Host "Las tareas propias se han procesado. Reglas eliminadas: $([bool]$RemoveFirewallRules). Los datos y copias en $InstallPath permanecen para revision."
