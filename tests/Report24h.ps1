$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$configPath = Join-Path $env:TEMP ("rdpshield-report-$([guid]::NewGuid().ToString('N')).json")
try {
    '{"RdpPort":3389}' | Set-Content -LiteralPath $configPath -Encoding UTF8
    $end = [datetime]'2026-09-29T12:30:00'
    function New-TestEvent([int]$id, [datetime]$time, [string]$data) {
        $event = [pscustomobject]@{ Id = $id; TimeCreated = $time; XmlText = "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><EventData>$data</EventData></Event>" }
        $event | Add-Member -MemberType ScriptMethod -Name ToXml -Value { return $this.XmlText }
        return $event
    }
    $events = @(
        (New-TestEvent 5157 $end.AddMinutes(-10) '<Data Name="Direction">%%14592</Data><Data Name="DestPort">3389</Data><Data Name="Protocol">6</Data>'),
        (New-TestEvent 5157 $end.AddMinutes(-20) '<Data Name="Direction">%%14593</Data><Data Name="DestPort">3389</Data><Data Name="Protocol">6</Data>'),
        (New-TestEvent 5157 $end.AddHours(-2) '<Data Name="Direction">%%14592</Data><Data Name="DestPort">3389</Data><Data Name="Protocol">17</Data>'),
        (New-TestEvent 4625 $end.AddMinutes(-5) '<Data Name="LogonType">10</Data>'),
        (New-TestEvent 4625 $end.AddMinutes(-4) '<Data Name="LogonType">3</Data>')
    )
    $report = & (Join-Path $root 'src\RDPShield-Report-24h.ps1') -ConfigPath $configPath -EndTime $end -InputEvents $events -AuditMode Enabled -PassThru
    if ($report.Hours.Count -ne 24) { throw 'Expected 24 hourly rows.' }
    if ($report.FirewallBlockedTotal -ne 2) { throw 'Incorrect firewall blocked total.' }
    if ($report.FailedRdpLogonsTotal -ne 1) { throw 'Incorrect failed RDP logon total.' }
    if ($report.Hours[23].FirewallBlocked -ne 1 -or $report.Hours[23].FailedRdpLogons -ne 1) { throw 'Incorrect latest hour.' }
    if ($report.Hours[22].FirewallBlocked -ne 1) { throw 'Incorrect previous hour.' }
    if ($report.FirewallAudit -ne 'Enabled' -or $report.LogonAudit -ne 'Enabled') { throw 'Incorrect audit state.' }
    Write-Host 'Report24h passed.'
} finally {
    Remove-Item -LiteralPath $configPath -ErrorAction SilentlyContinue
}
