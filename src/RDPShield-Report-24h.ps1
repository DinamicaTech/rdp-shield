[CmdletBinding()]
param(
    [string]$ConfigPath,
    [datetime]$EndTime = (Get-Date),
    [ValidateRange(1, 168)][int]$Hours = 24,
    [string]$CsvPath,
    [switch]$PassThru,
    [object[]]$InputEvents,
    [ValidateSet('Auto', 'Enabled', 'Disabled')][string]$AuditMode = 'Auto'
)

$ErrorActionPreference = 'Stop'
if (-not $PSBoundParameters.ContainsKey('ConfigPath')) {
    $candidates = @(
        (Join-Path $PSScriptRoot 'config\config.json'),
        (Join-Path $PSScriptRoot '..\config\config.json')
    )
    $ConfigPath = $candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf } | Select-Object -First 1
    if (-not $ConfigPath) {
        throw "Configuration not found. Checked: $($candidates -join ', '). Use -ConfigPath to specify it."
    }
}
if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) { throw "Configuration not found: $ConfigPath" }
$config = Get-Content -LiteralPath $ConfigPath -Raw | ConvertFrom-Json
$port = 0
if (-not [int]::TryParse([string]$config.RdpPort, [ref]$port) -or $port -lt 1 -or $port -gt 65535) {
    throw 'RdpPort must be between 1 and 65535.'
}

$start = $EndTime.AddHours(-$Hours)
$rows = @()
for ($i = 0; $i -lt $Hours; $i++) {
    $from = $start.AddHours($i)
    $rows += [pscustomobject]@{ From = $from; To = $from.AddHours(1); FirewallBlocked = 0; FailedLogonsWithIP = 0; FailedRdpLogons = 0; FailedNetworkLogons = 0 }
}

$readError = $null
$oldest = $null
function Add-EventToReport([object]$record) {
    if ($record.TimeCreated -lt $start -or $record.TimeCreated -ge $EndTime) { return }
    $index = [int][math]::Floor(($record.TimeCreated - $start).TotalHours)
    if ($index -lt 0 -or $index -ge $Hours) { return }
    try {
        $values = $record.Properties
        if ($record.Id -eq 4625 -and $null -ne $values -and $values.Count -ge 20) {
            # 4625 version 0: LogonType=10, IpAddress=19.
            $logonType = [string]$values[10].Value
            $sourceIp = [string]$values[19].Value
            if ($sourceIp -and $sourceIp -ne '-') {
                $rows[$index].FailedLogonsWithIP++
                if ($logonType -eq '3') { $rows[$index].FailedNetworkLogons++ }
            }
            if ($logonType -eq '10') { $rows[$index].FailedRdpLogons++ }
        } elseif ($record.Id -eq 5157 -and $null -ne $values -and $values.Count -ge 8) {
            # 5157: Direction=2, DestPort=6, Protocol=7.
            if ([string]$values[2].Value -eq '%%14592' -and [string]$values[6].Value -eq [string]$port -and
                [string]$values[7].Value -in @('6', '17')) { $rows[$index].FirewallBlocked++ }
        } else {
            # Offline fixtures and unexpected event layouts use named XML fields.
            [xml]$xml = $record.ToXml()
            $fields = @{}
            foreach ($field in $xml.Event.EventData.Data) { $fields[[string]$field.Name] = [string]$field.'#text' }
            if ($record.Id -eq 5157 -and $fields.Direction -eq '%%14592' -and
                $fields.DestPort -eq [string]$port -and $fields.Protocol -in @('6', '17')) {
                $rows[$index].FirewallBlocked++
            } elseif ($record.Id -eq 4625) {
                if ($fields.IpAddress -and $fields.IpAddress -ne '-') {
                    $rows[$index].FailedLogonsWithIP++
                    if ($fields.LogonType -eq '3') { $rows[$index].FailedNetworkLogons++ }
                }
                if ($fields.LogonType -eq '10') { $rows[$index].FailedRdpLogons++ }
            }
        }
    } catch {
        $script:readError = "Could not parse one or more Security events: $($_.Exception.Message)"
    }
}

if ($PSBoundParameters.ContainsKey('InputEvents')) {
    foreach ($record in $InputEvents) { Add-EventToReport $record }
} else {
    try {
        $oldest = Get-WinEvent -LogName Security -Oldest -MaxEvents 1 -ErrorAction Stop
        # Process records as they arrive; do not materialize the entire window.
        Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = @(5157, 4625); StartTime = $start; EndTime = $EndTime } -ErrorAction Stop |
            ForEach-Object { Add-EventToReport $_ }
    } catch {
        # Get-WinEvent also throws when the query has no matching events.
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { $readError = $_.Exception.Message }
    }
}

function Get-FailureAuditState([string]$subcategoryGuid) {
    try {
        $lines = @(& auditpol.exe /get "/subcategory:$subcategoryGuid" /r 2>$null)
        if ($LASTEXITCODE -ne 0) { return 'Unknown' }
        # /r includes the subcategory GUID and a numeric setting (0..3).
        # Match those stable fields instead of localized CSV column names.
        $guidText = $subcategoryGuid.Trim('{}')
        $policyLine = $lines | Where-Object { $_ -match [regex]::Escape($guidText) } | Select-Object -First 1
        if (-not $policyLine) { return 'Unknown' }
        $value = [string](@($policyLine -split ',') | Select-Object -Last 1)
        $value = $value.Trim(' ', '"')
        if ($value -notmatch '^[0-3]$') { return 'Unknown' }
        if (([int]$value -band 2) -ne 0) { return 'Enabled' }
        return 'Disabled'
    } catch { return 'Unknown' }
}

$firewallAudit = $AuditMode
$logonAudit = $AuditMode
if ($AuditMode -eq 'Auto' -and -not $PSBoundParameters.ContainsKey('InputEvents')) {
    $firewallAudit = Get-FailureAuditState '{0CCE9226-69AE-11D9-BED3-505054503030}'
    $logonAudit = Get-FailureAuditState '{0CCE9215-69AE-11D9-BED3-505054503030}'
} elseif ($AuditMode -eq 'Auto') {
    $firewallAudit = 'Unknown'
    $logonAudit = 'Unknown'
}

$coverage = if ($PSBoundParameters.ContainsKey('InputEvents')) { 'Offline input' }
    elseif ($readError) { 'Unknown' }
    elseif ($null -eq $oldest -or $oldest.TimeCreated -gt $start) { 'Partial or unknown' }
    else { 'Log retained for full period' }

$report = [pscustomobject]@{
    Start = $start
    End = $EndTime
    RdpPort = $port
    FirewallAudit = $firewallAudit
    LogonAudit = $logonAudit
    SecurityLogCoverage = $coverage
    ReadError = $readError
    FirewallBlockedTotal = ($rows | Measure-Object -Property FirewallBlocked -Sum).Sum
    FailedLogonsWithIPTotal = ($rows | Measure-Object -Property FailedLogonsWithIP -Sum).Sum
    FailedRdpLogonsTotal = ($rows | Measure-Object -Property FailedRdpLogons -Sum).Sum
    FailedNetworkLogonsTotal = ($rows | Measure-Object -Property FailedNetworkLogons -Sum).Sum
    Hours = $rows
}

if ($CsvPath) { $rows | Export-Csv -LiteralPath $CsvPath -NoTypeInformation -Encoding UTF8 }
if ($PassThru) { return $report }

Write-Host "RDP Shield | $($start.ToString('yyyy-MM-dd HH:mm')) to $($EndTime.ToString('yyyy-MM-dd HH:mm')) | port $port"
$rows | Format-Table @{ Label = 'From'; Expression = { $_.From.ToString('MM-dd HH:mm') } },
    FirewallBlocked, FailedLogonsWithIP, FailedRdpLogons, FailedNetworkLogons -AutoSize | Out-Host
Write-Host "Totals: firewall blocked $($report.FirewallBlockedTotal); failed logons with IP $($report.FailedLogonsWithIPTotal); type 10 $($report.FailedRdpLogonsTotal); type 3 $($report.FailedNetworkLogonsTotal)"
Write-Host "Firewall failure audit: $firewallAudit | Logon failure audit: $logonAudit | Security log coverage: $coverage"
if ($readError) { Write-Warning $readError }
if ($firewallAudit -ne 'Enabled' -or $logonAudit -ne 'Enabled' -or $coverage -ne 'Log retained for full period') {
    Write-Warning 'A zero may mean missing audit data. Check audit policy and Security log retention on the server.'
}
