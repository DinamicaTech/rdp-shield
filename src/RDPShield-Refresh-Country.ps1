[CmdletBinding()]
param([string]$ConfigPath = (Join-Path $PSScriptRoot '..\config\config.json'))

$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'RDPShield-Update-Country.ps1') -ConfigPath $ConfigPath
& (Join-Path $PSScriptRoot 'RDPShield-Apply-Firewall.ps1') -ConfigPath $ConfigPath -StageOnly
