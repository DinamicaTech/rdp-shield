[CmdletBinding()]
param([string]$ConfigPath = (Join-Path $PSScriptRoot '..\config\config.json'))

$ErrorActionPreference = 'Stop'
$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
if ($config.EnableIPBanIntegration -eq $true) {
    & (Join-Path $PSScriptRoot 'RDPShield-Sync-IPBan.ps1') -ConfigPath $ConfigPath
}
& (Join-Path $PSScriptRoot 'RDPShield-Resolve-Emergency.ps1') -ConfigPath $ConfigPath
