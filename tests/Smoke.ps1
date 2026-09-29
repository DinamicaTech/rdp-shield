$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$temp = Join-Path ([System.IO.Path]::GetTempPath()) ('rdpshield-tests-' + [guid]::NewGuid().ToString('N'))
[System.IO.Directory]::CreateDirectory($temp) | Out-Null

try {
    $configPath = Join-Path $temp 'config.json'
    $sourcePath = Join-Path $temp 'country-source.txt'
    $outputPath = Join-Path $temp 'country-output.txt'
    $config = '{"Country":"ES","EmergencyAccess":["203.0.113.10","203.0.113.10"],"RdpPort":3389,"UpdateIntervalMinutes":15,"CountryUpdateHour":2}'
    [System.IO.File]::WriteAllText($configPath, $config)
    $cidrs = 1..10 | ForEach-Object { "10.$_.0.0/16" }
    [System.IO.File]::WriteAllLines($sourcePath, [string[]]$cidrs)

    $resolved = @(& (Join-Path $root 'src\RDPShield-Resolve-Emergency.ps1') -ConfigPath $configPath -ResolveOnly)
    if ($resolved.Count -ne 1 -or $resolved[0] -ne '203.0.113.10') { throw 'Emergency IPv4 deduplication failed.' }

    & (Join-Path $root 'src\RDPShield-Update-Country.ps1') -ConfigPath $configPath -SourcePath $sourcePath -OutputPath $outputPath | Out-Null
    $original = [System.IO.File]::ReadAllText($outputPath)
    if (@(Get-Content $outputPath).Count -ne 11) { throw 'Country output has an unexpected number of lines.' }

    [System.IO.File]::WriteAllLines($sourcePath, [string[]](@($cidrs[0..8]) + '0.0.0.0/0'))
    $rejected = $false
    try {
        & (Join-Path $root 'src\RDPShield-Update-Country.ps1') -ConfigPath $configPath -SourcePath $sourcePath -OutputPath $outputPath | Out-Null
    } catch { $rejected = $true }
    if (-not $rejected) { throw 'The unsafe /0 country entry was accepted.' }
    if ([System.IO.File]::ReadAllText($outputPath) -cne $original) { throw 'Invalid country data replaced the previous list.' }

    $validation = & (Join-Path $root 'src\RDPShield-Apply-Firewall.ps1') -ConfigPath $configPath -CountryPath $outputPath -ValidateOnly
    if ($validation.CountryCidrs -ne 10 -or $validation.EmergencyIPv4.Count -ne 1) { throw 'Firewall input validation failed.' }

    $plan = & (Join-Path $root 'Install-RDPShield.ps1') -ConfigPath $configPath -InstallPath (Join-Path $temp 'install') -PlanOnly
    if ($plan.Country -ne 'ES' -or $plan.RegisterTasks) { throw 'Installer plan is incorrect.' }
    if (Test-Path -LiteralPath (Join-Path $temp 'install')) { throw 'PlanOnly created an install directory.' }

    Write-Host 'RDP Shield smoke tests passed.'
} finally {
    $safeRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    $safePrefix = Join-Path $safeRoot 'rdpshield-tests-'
    if ([System.IO.Path]::GetFullPath($temp).StartsWith($safePrefix, [StringComparison]::OrdinalIgnoreCase)) {
        [System.IO.Directory]::Delete($temp, $true)
    }
}
