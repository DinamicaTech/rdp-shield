[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot '..\config\config.json'),
    [switch]$ResolveOnly
)

$ErrorActionPreference = 'Stop'
$ruleNames = @('RDPShield-Emergency-TCP', 'RDPShield-Emergency-UDP')

function Resolve-EmergencyAddress {
    param([Parameter(Mandatory = $true)][string]$Entry)

    $parsed = $null
    if ([System.Net.IPAddress]::TryParse($Entry, [ref]$parsed)) {
        if ($parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
            throw "Solo se admiten direcciones IPv4: $Entry"
        }
        return $parsed.ToString()
    }

    if ($Entry -notmatch '^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)+$') {
        throw "Dominio de emergencia no valido: $Entry"
    }

    $records = @(Resolve-DnsName -Name $Entry -Type A -ErrorAction Stop |
        Where-Object { $_.Type -eq 'A' -and $_.IPAddress } |
        ForEach-Object { $_.IPAddress })
    if ($records.Count -eq 0) {
        throw "El dominio $Entry no tiene registros IPv4 A"
    }
    return $records
}

if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    throw "No existe la configuracion: $ConfigPath"
}

$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$entries = @($config.EmergencyAccess)
if ($entries.Count -eq 0 -or @($entries | Where-Object { $_ -isnot [string] -or -not $_.Trim() }).Count -gt 0) {
    throw 'EmergencyAccess debe contener al menos una IP IPv4 o un dominio valido.'
}

# Resolver todas las entradas antes de modificar el firewall. Si falla una, se conserva la regla actual.
$addresses = @($entries | ForEach-Object { Resolve-EmergencyAddress -Entry $_.Trim() } |
    Sort-Object -Unique)
if ($addresses.Count -eq 0) {
    throw 'No se obtuvo ninguna direccion IPv4 de emergencia.'
}

if ($ResolveOnly) {
    $addresses
    return
}

$portNumber = 0
if (-not [int]::TryParse([string]$config.RdpPort, [ref]$portNumber) -or
    $portNumber -lt 1 -or $portNumber -gt 65535) {
    throw 'RdpPort debe ser un puerto TCP entre 1 y 65535.'
}

foreach ($ruleName in $ruleNames) {
    $rule = Get-NetFirewallRule -Name $ruleName -ErrorAction SilentlyContinue
    if ($null -eq $rule) {
        throw "No existe la regla $ruleName. Debe crearla el aplicador de RDP Shield antes de ejecutar este modulo."
    }
    if (@($rule).Count -ne 1 -or $rule.Group -ne 'RDPShield' -or
        $rule.Direction -ne 'Inbound' -or $rule.Action -ne 'Allow') {
        throw "La regla $ruleName no es una regla de entrada Allow propia de RDP Shield."
    }
    $portFilter = $rule | Get-NetFirewallPortFilter
    $protocol = if ($ruleName.EndsWith('TCP')) { 'TCP' } else { 'UDP' }
    if ([string]$portFilter.Protocol -ne $protocol -or [string]$portFilter.LocalPort -ne [string]$portNumber) {
        throw "La regla $ruleName no usa $protocol/$portNumber."
    }
}

foreach ($ruleName in $ruleNames) {
    $rule = Get-NetFirewallRule -Name $ruleName
    $addressFilter = $rule | Get-NetFirewallAddressFilter
    $current = @($addressFilter.RemoteAddress | Sort-Object -Unique)
    if (($current -join ',') -eq ($addresses -join ',')) {
        Write-Host "$ruleName sin cambios: $($addresses -join ', ')"
        continue
    }
    if ($PSCmdlet.ShouldProcess($ruleName, "Actualizar RemoteAddress a $($addresses -join ', ')")) {
        Set-NetFirewallRule -Name $ruleName -RemoteAddress $addresses -ErrorAction Stop
        Write-Host "Regla $ruleName actualizada: $($addresses -join ', ')"
    }
}
