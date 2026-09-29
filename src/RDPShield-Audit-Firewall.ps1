[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot '..\config\config.json')
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    throw "No existe la configuracion: $ConfigPath"
}
$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$port = 0
if (-not [int]::TryParse([string]$config.RdpPort, [ref]$port) -or $port -lt 1 -or $port -gt 65535) {
    throw 'RdpPort debe ser un puerto entre 1 y 65535.'
}
$trusted = @(& (Join-Path $PSScriptRoot 'RDPShield-Resolve-Emergency.ps1') -ConfigPath $ConfigPath -ResolveOnly)

function Test-PortMatch {
    param([object[]]$Values, [int]$Target)
    foreach ($value in $Values) {
        foreach ($part in ([string]$value -split ',')) {
            $part = $part.Trim()
            if ($part -eq 'Any' -or $part -eq '*') { return $true }
            if ($part -match '^\d+$' -and [int]$part -eq $Target) { return $true }
            if ($part -match '^(\d+)-(\d+)$' -and $Target -ge [int]$Matches[1] -and $Target -le [int]$Matches[2]) { return $true }
        }
    }
    return $false
}

$findings = @(
    Get-NetFirewallRule -PolicyStore ActiveStore -Direction Inbound -Action Allow -Enabled True -ErrorAction Stop |
        Where-Object { $_.Name -notlike 'RDPShield-*' } |
        ForEach-Object {
            $rule = $_
            $portFilter = $rule | Get-NetFirewallPortFilter
            $protocol = [string]$portFilter.Protocol
            if ($protocol -notin @('TCP', 'UDP', 'Any', '6', '17', '256')) { return }
            if (-not (Test-PortMatch -Values @($portFilter.LocalPort) -Target $port)) { return }
            $addressFilter = $rule | Get-NetFirewallAddressFilter
            $remote = @($addressFilter.RemoteAddress)
            if ($remote.Count -gt 0 -and @($remote | Where-Object { $trusted -notcontains $_ }).Count -eq 0) { return }
            [pscustomobject]@{
                Name = $rule.Name
                DisplayName = $rule.DisplayName
                Protocol = $protocol
                LocalPort = (@($portFilter.LocalPort) -join ',')
                RemoteAddress = ($remote -join ',')
                PolicyStoreSource = $rule.PolicyStoreSource
            }
        }
)

if ($findings.Count -gt 0) {
    Write-Warning "$($findings.Count) reglas Allow adicionales pueden admitir conexiones al puerto RDP $port. Revise sus condiciones y deshabilite o limite las que permitan acceso fuera del pais o de la emergencia."
}
$findings
