[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot '..\config\config.json'),
    [string]$IPBanConfigPath,
    [string]$StatePath = (Join-Path $PSScriptRoot '..\data\ipban-managed.json'),
    [switch]$PlanOnly,
    [switch]$RemoveManaged
)

$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) { throw "No existe $ConfigPath" }
$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
if ($config.EnableIPBanIntegration -ne $true -and -not $RemoveManaged) { throw 'EnableIPBanIntegration no esta activado.' }
$addresses = @()
if (-not $RemoveManaged) {
    $addresses = @(& (Join-Path $PSScriptRoot 'RDPShield-Resolve-Emergency.ps1') -ConfigPath $ConfigPath -ResolveOnly | Sort-Object -Unique)
    if ($addresses.Count -eq 0) { throw 'No hay direcciones IPv4 de emergencia.' }
}
if (-not $IPBanConfigPath -and $config.IPBanConfigPath) { $IPBanConfigPath = [string]$config.IPBanConfigPath }

if (-not $IPBanConfigPath) {
    $service = Get-CimInstance Win32_Service -Filter "Name='IPBan'" -ErrorAction Stop
    if ($null -eq $service -or -not $service.PathName) { throw 'No se encontro el servicio IPBan.' }
    if ($service.State -ne 'Running') { throw 'El servicio IPBan no esta en ejecucion.' }
    $commandLine = $service.PathName.Trim()
    if ($commandLine -match '^"([^"]+\.exe)"' -or $commandLine -match '^(.+?\.exe)(?:\s|$)') {
        $executable = $Matches[1]
    } else { throw 'No se pudo identificar el ejecutable del servicio IPBan.' }
    $IPBanConfigPath = Join-Path (Split-Path -Parent $executable) 'ipban.override.config'
}
if (-not (Test-Path -LiteralPath $IPBanConfigPath -PathType Leaf)) { throw "No existe $IPBanConfigPath" }
$fullIPBanPath = [System.IO.Path]::GetFullPath($IPBanConfigPath)

$xml = New-Object System.Xml.XmlDocument
$xml.PreserveWhitespace = $true
$xml.Load($fullIPBanPath)
$settings = $xml.SelectSingleNode('/configuration/appSettings')
if ($null -eq $settings) { throw 'IPBan no tiene un nodo configuration/appSettings compatible.' }
$whitelist = $xml.SelectSingleNode('/configuration/appSettings/add[@key="Whitelist"]')
if ($null -eq $whitelist) { throw 'IPBan no tiene la clave Whitelist en ipban.override.config.' }
$existing = @(([string]$whitelist.GetAttribute('value')) -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)

$managedBefore = @()
if (Test-Path -LiteralPath $StatePath -PathType Leaf) {
    $state = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
    if ([string]$state.IPBanConfigPath -ine $fullIPBanPath) { throw 'El estado anterior pertenece a otra configuracion IPBan.' }
    $managedBefore = @($state.ManagedAddresses)
    foreach ($address in $managedBefore) {
        $parsed = $null
        if (-not [System.Net.IPAddress]::TryParse([string]$address, [ref]$parsed) -or
            $parsed.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork) {
            throw 'El estado anterior de IPBan contiene una direccion no valida.'
        }
    }
}

$preserved = @($existing | Where-Object { $managedBefore -notcontains $_ })
$managedAfter = @($addresses | Where-Object { $preserved -notcontains $_ })
$merged = @($preserved + $managedAfter | Select-Object -Unique)
$newValue = $merged -join ','
$plan = [pscustomobject]@{
    IPBanConfigPath = $fullIPBanPath
    PreservedEntries = $preserved
    ManagedBefore = $managedBefore
    ManagedAfter = $managedAfter
    WhitelistChanges = ([string]$whitelist.GetAttribute('value') -cne $newValue)
}
if ($PlanOnly) { $plan; return }
if (-not $PSCmdlet.ShouldProcess($fullIPBanPath, 'Sincronizar IP de emergencia con Whitelist')) { return }

if ($plan.WhitelistChanges) {
    $whitelist.SetAttribute('value', $newValue)
    $tempPath = Join-Path (Split-Path -Parent $fullIPBanPath) ('.rdpshield-ipban-' + [guid]::NewGuid().ToString('N') + '.tmp')
    try {
        $xml.Save($tempPath)
        $check = New-Object System.Xml.XmlDocument
        $check.Load($tempPath)
        [System.IO.File]::Replace($tempPath, $fullIPBanPath, ($fullIPBanPath + '.rdpshield.bak'))
    } finally {
        if (Test-Path -LiteralPath $tempPath -PathType Leaf) { Remove-Item -LiteralPath $tempPath }
    }
}

$stateDirectory = Split-Path -Parent $StatePath
[System.IO.Directory]::CreateDirectory($stateDirectory) | Out-Null
$stateValue = @{ IPBanConfigPath = $fullIPBanPath; ManagedAddresses = @($managedAfter) } | ConvertTo-Json -Depth 3
$stateTemp = Join-Path $stateDirectory ('.rdpshield-ipban-state-' + [guid]::NewGuid().ToString('N') + '.tmp')
try {
    [System.IO.File]::WriteAllText($stateTemp, $stateValue, (New-Object System.Text.UTF8Encoding($false)))
    if ([System.IO.File]::Exists($StatePath)) {
        [System.IO.File]::Replace($stateTemp, $StatePath, ($StatePath + '.bak'))
    } else {
        [System.IO.File]::Move($stateTemp, $StatePath)
    }
} finally {
    if ([System.IO.File]::Exists($stateTemp)) { [System.IO.File]::Delete($stateTemp) }
}
Write-Host "IPBan Whitelist sincronizada: $($managedAfter.Count) entradas gestionadas por RDP Shield."
