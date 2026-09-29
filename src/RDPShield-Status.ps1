[CmdletBinding()]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot '..\config\config.json'),
    [string]$CountryPath = (Join-Path $PSScriptRoot '..\data\RDPShield-Allow.txt')
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) { throw "No existe $ConfigPath" }
$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$port = 0
if (-not [int]::TryParse([string]$config.RdpPort, [ref]$port) -or $port -lt 1 -or $port -gt 65535) {
    throw 'RdpPort no valido.'
}

$countryCount = 0
$countryUpdated = $null
if (Test-Path -LiteralPath $CountryPath -PathType Leaf) {
    $countryCount = @(Get-Content -LiteralPath $CountryPath | Where-Object { $_ -and -not $_.StartsWith('#') }).Count
    $countryUpdated = (Get-Item -LiteralPath $CountryPath).LastWriteTime
}

$emergency = @()
$dnsError = $null
try {
    $emergency = @(& (Join-Path $PSScriptRoot 'RDPShield-Resolve-Emergency.ps1') -ConfigPath $ConfigPath -ResolveOnly)
} catch {
    $dnsError = $_.Exception.Message
}

$ruleNames = @('RDPShield-Country-TCP', 'RDPShield-Country-UDP',
    'RDPShield-Emergency-TCP', 'RDPShield-Emergency-UDP')
$rules = @()
$conflicts = @()
$firewallError = $null
try {
    Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop | Select-Object -First 1 | Out-Null
    foreach ($name in $ruleNames) {
        $rule = Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue
        if ($null -eq $rule) {
            $rules += [pscustomobject]@{ Name = $name; Exists = $false; Enabled = $false; Addresses = 0 }
        } else {
            $filter = $rule | Get-NetFirewallAddressFilter
            $rules += [pscustomobject]@{ Name = $name; Exists = $true; Enabled = ([string]$rule.Enabled -eq 'True'); Addresses = @($filter.RemoteAddress).Count }
        }
    }
    $conflicts = @(& (Join-Path $PSScriptRoot 'RDPShield-Audit-Firewall.ps1') -ConfigPath $ConfigPath 3>$null)
} catch {
    $firewallError = $_.Exception.Message
}

$ipBanStatus = 'Disabled'
$ipBanManaged = 0
if ($config.EnableIPBanIntegration -eq $true) {
    $service = Get-Service -Name 'IPBan' -ErrorAction SilentlyContinue
    $ipBanStatus = if ($null -eq $service) { 'Not installed' } else { [string]$service.Status }
    $managedPath = Join-Path $PSScriptRoot '..\data\ipban-managed.json'
    if (Test-Path -LiteralPath $managedPath -PathType Leaf) {
        $managed = Get-Content -LiteralPath $managedPath -Raw | ConvertFrom-Json
        $ipBanManaged = @($managed.ManagedAddresses).Count
    }
}

$migrationStatus = 'Not started'
$rollbackAt = $null
$migrationPath = Join-Path $PSScriptRoot '..\data\migration-active.json'
if (Test-Path -LiteralPath $migrationPath -PathType Leaf) {
    $migration = Get-Content -LiteralPath $migrationPath -Raw | ConvertFrom-Json
    $migrationStatus = [string]$migration.Status
    $rollbackAt = $migration.RollbackAt
}

$state = if ($firewallError) { 'Unknown' }
    elseif ($dnsError -or $countryCount -lt 10 -or @($rules | Where-Object { -not $_.Exists -or -not $_.Enabled }).Count -gt 0) { 'Incomplete' }
    elseif ($conflicts.Count -gt 0) { 'Staged: other Allow rules remain' }
    else { 'No broad Allow rules detected; verify on the target host' }

[pscustomobject]@{
    State = $state
    Country = [string]$config.Country
    CountryCidrs = $countryCount
    CountryUpdated = $countryUpdated
    EmergencyIPv4 = $emergency
    EmergencyResolutionError = $dnsError
    RdpPort = $port
    Rules = $rules
    OtherAllowRules = $conflicts.Count
    FirewallReadError = $firewallError
    IPBanStatus = $ipBanStatus
    IPBanManagedAddresses = $ipBanManaged
    MigrationStatus = $migrationStatus
    MigrationRollbackAt = $rollbackAt
}
