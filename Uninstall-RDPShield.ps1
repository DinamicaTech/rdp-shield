[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$InstallPath = (Join-Path $env:ProgramData 'RDPShield'),
    [switch]$RemoveFirewallRules
)

$ErrorActionPreference = 'Stop'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'La desinstalacion requiere privilegios de administrador.'
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
