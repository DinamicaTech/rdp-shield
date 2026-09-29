[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [string]$ConfigPath = (Join-Path $PSScriptRoot '..\config\config.json'),
    [string]$OutputPath = (Join-Path $PSScriptRoot '..\data\RDPShield-Allow.txt'),
    [string]$SourcePath
)

$ErrorActionPreference = 'Stop'

if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) {
    throw "No existe la configuracion: $ConfigPath"
}
$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$country = [string]$config.Country
if ($country -cnotmatch '^[A-Z]{2}$') {
    throw 'Country debe ser un codigo ISO 3166-1 de dos letras mayusculas, por ejemplo ES.'
}

$url = "https://www.ipdeny.com/ipblocks/data/aggregated/$($country.ToLowerInvariant())-aggregated.zone"
if ($SourcePath) {
    $lines = @(Get-Content -LiteralPath $SourcePath -ErrorAction Stop)
    $source = $SourcePath
} else {
    # Windows PowerShell 5.1 necesita TLS 1.2 para muchos sitios HTTPS.
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $response = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 60 -ErrorAction Stop
    $lines = @($response.Content -split '\r?\n')
    $source = $url
}

$cidrs = New-Object 'System.Collections.Generic.List[string]'
foreach ($raw in $lines) {
    $value = $raw.Trim()
    if (-not $value -or $value.StartsWith('#')) { continue }
    if ($value -notmatch '^((?:\d{1,3}\.){3}\d{1,3})/(\d{1,2})$') {
        throw "CIDR no valido en la fuente: $value"
    }
    $ip = $null
    $prefix = [int]$Matches[2]
    if (-not [System.Net.IPAddress]::TryParse($Matches[1], [ref]$ip) -or
        $ip.AddressFamily -ne [System.Net.Sockets.AddressFamily]::InterNetwork -or
        $prefix -lt 1 -or $prefix -gt 32) {
        throw "CIDR IPv4 no valido en la fuente: $value"
    }
    $cidrs.Add("$($ip.ToString())/$prefix")
}

$unique = @($cidrs | Sort-Object -Unique)
if ($unique.Count -lt 10) {
    throw "La fuente solo contiene $($unique.Count) CIDR validos; no se reemplaza la lista anterior."
}

$outputDirectory = Split-Path -Parent $OutputPath
if (-not $outputDirectory) { throw 'OutputPath debe incluir un directorio.' }
if ($PSCmdlet.ShouldProcess($OutputPath, "Guardar $($unique.Count) CIDR de $country desde $source")) {
    [System.IO.Directory]::CreateDirectory($outputDirectory) | Out-Null
    $fullOutput = [System.IO.Path]::GetFullPath($OutputPath)
    $tempPath = Join-Path $outputDirectory ('.RDPShield-Allow-' + [guid]::NewGuid().ToString('N') + '.tmp')
    try {
        $content = @("# RDP Shield country=$country source=$source updated=$((Get-Date).ToUniversalTime().ToString('o'))") + $unique
        [System.IO.File]::WriteAllLines($tempPath, [string[]]$content, (New-Object System.Text.UTF8Encoding($false)))
        if ([System.IO.File]::Exists($fullOutput)) {
            $backupPath = Join-Path $outputDirectory 'RDPShield-Allow.prev.txt'
            [System.IO.File]::Replace($tempPath, $fullOutput, $backupPath)
        } else {
            [System.IO.File]::Move($tempPath, $fullOutput)
        }
    } finally {
        if ([System.IO.File]::Exists($tempPath)) { [System.IO.File]::Delete($tempPath) }
    }
    Write-Host "$($unique.Count) CIDR de $country guardados en $fullOutput"
}
