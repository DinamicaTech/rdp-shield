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
$source = $null
if ($PSBoundParameters.ContainsKey('InputEvents')) {
    $source = $InputEvents
} else {
    try {
        $oldest = Get-WinEvent -LogName Security -Oldest -MaxEvents 1 -ErrorAction Stop
        $source = Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = @(5157, 4625); StartTime = $start; EndTime = $EndTime } -ErrorAction Stop
    } catch {
        # Get-WinEvent also throws when the query has no matching events.
        if ($_.FullyQualifiedErrorId -notlike 'NoMatchingEventsFound*') { $readError = $_.Exception.Message }
        $source = @()
    }
}

foreach ($event in $source) {
    if ($event.TimeCreated -lt $start -or $event.TimeCreated -gt $EndTime) { continue }
    $index = [int][math]::Floor(($event.TimeCreated - $start).TotalHours)
    if ($index -lt 0 -or $index -ge $Hours) { continue }
    try {
        [xml]$xml = $event.ToXml()
        $fields = @{}
        foreach ($field in $xml.Event.EventData.Data) { $fields[[string]$field.Name] = [string]$field.'#text' }
        if ($event.Id -eq 5157 -and $fields.Direction -eq '%%14592' -and
            $fields.DestPort -eq [string]$port -and $fields.Protocol -in @('6', '17')) {
            $rows[$index].FirewallBlocked++
        } elseif ($event.Id -eq 4625) {
            if ($fields.IpAddress -and $fields.IpAddress -ne '-') {
                $rows[$index].FailedLogonsWithIP++
                if ($fields.LogonType -eq '3') { $rows[$index].FailedNetworkLogons++ }
            }
            if ($fields.LogonType -eq '10') { $rows[$index].FailedRdpLogons++ }
        }
    } catch {
        $readError = "Could not parse one or more Security events: $($_.Exception.Message)"
    }
}

function Get-FailureAuditState([string]$subcategoryGuid) {
    try {
        $lines = @(& auditpol.exe /get "/subcategory:$subcategoryGuid" /r 2>$null)
        if ($LASTEXITCODE -ne 0) { return 'Unknown' }
        $csv = @($lines | Where-Object { $_ -match ',' })
        $headerIndex = -1
        for ($i = 0; $i -lt $csv.Count; $i++) {
            if ($csv[$i] -match 'Setting Value') { $headerIndex = $i; break }
        }
        if ($headerIndex -lt 0) { return 'Unknown' }
        $policy = @($csv[$headerIndex..($csv.Count - 1)] | ConvertFrom-Csv |
            Where-Object { $_.'Subcategory GUID' -eq $subcategoryGuid } | Select-Object -First 1)
        if ($policy.Count -eq 0) { return 'Unknown' }
        $value = [string]$policy[0].'Setting Value'
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
