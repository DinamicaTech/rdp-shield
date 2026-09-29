[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot '..\config\config.json'),
    [string]$CountryPath = (Join-Path $PSScriptRoot '..\data\RDPShield-Allow.txt'),
    [string]$BackupDirectory = (Join-Path $PSScriptRoot '..\backup'),
    [switch]$ValidateOnly,
    [switch]$StageOnly
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) { throw "No existe $ConfigPath" }
if (-not (Test-Path -LiteralPath $CountryPath -PathType Leaf)) { throw "No existe $CountryPath" }

$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$port = 0
if (-not [int]::TryParse([string]$config.RdpPort, [ref]$port) -or $port -lt 1 -or $port -gt 65535) {
    throw 'RdpPort debe ser un puerto entre 1 y 65535.'
}
$country = [string]$config.Country
if ($country -cnotmatch '^[A-Z]{2}$') { throw 'Country no valido.' }

$lines = @(Get-Content -LiteralPath $CountryPath)
if ($lines.Count -lt 11 -or $lines[0] -notmatch "^# RDP Shield country=$country(?:\s|$)") {
    throw "La lista de CIDR no corresponde al pais $country o esta incompleta."
}
$cidrs = @($lines | Where-Object { $_ -and -not $_.StartsWith('#') } | Sort-Object -Unique)
if ($cidrs.Count -lt 10) { throw 'La lista de CIDR es demasiado pequena.' }
foreach ($cidr in $cidrs) {
    if ($cidr -notmatch '^((?:\d{1,3}\.){3}\d{1,3})/(\d{1,2})$') { throw "CIDR no valido: $cidr" }
    $ip = $null
    if (-not [System.Net.IPAddress]::TryParse($Matches[1], [ref]$ip) -or
        $ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -or
        [int]$Matches[2] -lt 1 -or [int]$Matches[2] -gt 32) { throw "CIDR no valido: $cidr" }
}

$emergency = @(& (Join-Path $PSScriptRoot 'RDPShield-Resolve-Emergency.ps1') -ConfigPath $ConfigPath -ResolveOnly)
if ($emergency.Count -eq 0) { throw 'No hay acceso de emergencia valido.' }
if ($ValidateOnly) {
    [pscustomobject]@{ Country = $country; CountryCidrs = $cidrs.Count; EmergencyIPv4 = $emergency; RdpPort = $port }
    return
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Se necesitan privilegios de administrador para aplicar reglas.'
}

# Cualquier otra regla Allow que pueda cubrir este puerto impide garantizar el filtro geografico.
$conflicts = @(& (Join-Path $PSScriptRoot 'RDPShield-Audit-Firewall.ps1') -ConfigPath $ConfigPath)
if ($conflicts.Count -gt 0 -and -not $StageOnly) {
    $names = ($conflicts | Select-Object -First 5 -ExpandProperty Name) -join ', '
    throw "$($conflicts.Count) reglas Allow adicionales pueden abrir RDP ($names). Revise y limite esas reglas antes de aplicar RDP Shield."
}
if ($conflicts.Count -gt 0 -and $StageOnly) {
    Write-Warning "Modo preparacion: $($conflicts.Count) reglas Allow adicionales siguen activas. RDP Shield aun NO restringe el puerto RDP."
}

$specs = @(
    @{ Name = 'RDPShield-Country-TCP'; Label = 'RDP Shield - Country TCP'; Protocol = 'TCP'; Addresses = $cidrs },
    @{ Name = 'RDPShield-Country-UDP'; Label = 'RDP Shield - Country UDP'; Protocol = 'UDP'; Addresses = $cidrs },
    @{ Name = 'RDPShield-Emergency-TCP'; Label = 'RDP Shield - Emergency TCP'; Protocol = 'TCP'; Addresses = $emergency },
    @{ Name = 'RDPShield-Emergency-UDP'; Label = 'RDP Shield - Emergency UDP'; Protocol = 'UDP'; Addresses = $emergency }
)

# Verificar todas las reglas existentes antes de modificar cualquiera.
foreach ($spec in $specs) {
    $rule = Get-NetFirewallRule -Name $spec.Name -ErrorAction SilentlyContinue
    if ($null -eq $rule) { continue }
    if (@($rule).Count -ne 1 -or $rule.Group -ne 'RDPShield' -or
        $rule.Direction -ne 'Inbound' -or $rule.Action -ne 'Allow') {
        throw "La regla $($spec.Name) existe pero no pertenece a RDP Shield o tiene propiedades inesperadas."
    }
    $filter = $rule | Get-NetFirewallPortFilter
    if ([string]$filter.Protocol -ne $spec.Protocol -or [string]$filter.LocalPort -ne [string]$port) {
        throw "La regla $($spec.Name) no usa $($spec.Protocol)/$port."
    }
}

if ($WhatIfPreference) {
    foreach ($spec in $specs) { $PSCmdlet.ShouldProcess($spec.Name, 'Crear o actualizar regla') | Out-Null }
    return
}

[System.IO.Directory]::CreateDirectory($BackupDirectory) | Out-Null
$backupPath = Join-Path $BackupDirectory ("firewall-$(Get-Date -Format 'yyyyMMdd-HHmmss').wfw")
& netsh advfirewall export $backupPath | Out-Null
if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $backupPath -PathType Leaf)) {
    throw 'No se pudo exportar una copia del firewall; no se han aplicado cambios.'
}

foreach ($spec in $specs) {
    if (-not $PSCmdlet.ShouldProcess($spec.Name, 'Crear o actualizar regla')) { continue }
    $rule = Get-NetFirewallRule -Name $spec.Name -ErrorAction SilentlyContinue
    if ($null -eq $rule) {
        New-NetFirewallRule -Name $spec.Name -DisplayName $spec.Label -Group 'RDPShield' `
            -Direction Inbound -Action Allow -Enabled True -Profile Any `
            -Protocol $spec.Protocol -LocalPort $port -RemoteAddress $spec.Addresses `
            -Description 'Managed by RDP Shield' -ErrorAction Stop | Out-Null
    } else {
        Set-NetFirewallRule -Name $spec.Name -RemoteAddress $spec.Addresses `
            -Enabled True -ErrorAction Stop | Out-Null
    }
    $verified = Get-NetFirewallRule -Name $spec.Name -ErrorAction Stop | Get-NetFirewallAddressFilter
    if (@($verified.RemoteAddress).Count -ne @($spec.Addresses).Count) {
        throw "La regla $($spec.Name) no contiene el numero esperado de direcciones. Copia: $backupPath"
    }
    Write-Host "$($spec.Name): $(@($spec.Addresses).Count) direcciones"
}
Write-Host "Copia del firewall: $backupPath"
