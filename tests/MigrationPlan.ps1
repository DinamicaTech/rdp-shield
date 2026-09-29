$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$configPath = Join-Path ([System.IO.Path]::GetTempPath()) ('rdpshield-migration-test-' + [guid]::NewGuid().ToString('N') + '.json')
[System.IO.File]::WriteAllText($configPath, '{"Country":"ES","EmergencyAccess":["203.0.113.10"],"RdpPort":3389}')
$global:RDPShieldTestExtraRule = $false
$global:RDPShieldTestRuleDisabled = $false
$global:RDPShieldTestRollbackTask = $false
$global:RDPShieldTestRestored = @()
$global:RDPShieldTestIPBanWide = $false

function Get-NetFirewallProfile { [pscustomobject]@{ Enabled = 'True'; DefaultInboundAction = 'Block' } }
function Get-ScheduledTask {
    if ($global:RDPShieldTestRollbackTask) { [pscustomobject]@{ TaskName = 'RDPShield-Migration-Rollback' } }
}
function Unregister-ScheduledTask { $global:RDPShieldTestRollbackTask = $false }
function Set-NetFirewallRule { param($PolicyStore, $Name, $Enabled, $ErrorAction); $global:RDPShieldTestRestored += $Name }
function Get-NetFirewallRule {
    param($PolicyStore, $Name, $Direction, $Action, $Enabled, $ErrorAction)
    $ownedNames = @('RDPShield-Country-TCP', 'RDPShield-Country-UDP', 'RDPShield-Emergency-TCP', 'RDPShield-Emergency-UDP')
    if ($Name) {
        if ($ownedNames -contains $Name) {
            return [pscustomobject]@{ Name = $Name; Group = 'RDPShield'; Enabled = 'True'; Direction = 'Inbound'; Action = 'Allow' }
        }
        if ($Name -eq 'Legacy-RDP') {
            return [pscustomobject]@{ Name = $Name; Group = ''; Enabled = 'True'; Direction = 'Inbound'; Action = 'Allow' }
        }
        return $null
    }
    $rules = @()
    if (-not $global:RDPShieldTestRuleDisabled) {
        $rules += [pscustomobject]@{ Name = 'Legacy-RDP'; DisplayName = 'Legacy RDP'; Enabled = 'True'; Direction = 'Inbound'; Action = 'Allow'; PolicyStoreSource = 'PersistentStore' }
    }
    $rules += [pscustomobject]@{ Name = 'IPBan_Whitelist'; DisplayName = 'IPBan whitelist'; Enabled = 'True'; Direction = 'Inbound'; Action = 'Allow'; PolicyStoreSource = 'PersistentStore' }
    if ($global:RDPShieldTestExtraRule) {
        $rules += [pscustomobject]@{ Name = 'Other-RDP'; DisplayName = 'Other RDP'; Enabled = 'True'; Direction = 'Inbound'; Action = 'Allow'; PolicyStoreSource = 'PersistentStore' }
    }
    return $rules
}
function Get-NetFirewallPortFilter {
    param([Parameter(ValueFromPipeline = $true)]$InputObject)
    process { [pscustomobject]@{ Protocol = 'TCP'; LocalPort = '3389' } }
}
function Get-NetFirewallAddressFilter {
    param([Parameter(ValueFromPipeline = $true)]$InputObject)
    process {
        $remote = if ($InputObject.Name -eq 'RDPShield-Emergency-TCP' -or
            ($InputObject.Name -eq 'IPBan_Whitelist' -and -not $global:RDPShieldTestIPBanWide)) { '203.0.113.10' } else { 'Any' }
        [pscustomobject]@{ RemoteAddress = @($remote) }
    }
}

try {
    $script = Join-Path $root 'src\RDPShield-Start-Migration.ps1'
    $plan = & $script -ConfigPath $configPath -DisableRuleNames 'Legacy-RDP' -RecoveryAddress '203.0.113.10' -PlanOnly 3>$null
    if (@($plan.DisableRules).Count -ne 1 -or $plan.DisableRules[0] -ne 'Legacy-RDP') { throw 'Migration plan did not select the requested rule.' }

    $global:RDPShieldTestExtraRule = $true
    $rejected = $false
    try { & $script -ConfigPath $configPath -DisableRuleNames 'Legacy-RDP' -RecoveryAddress '203.0.113.10' -PlanOnly 3>$null | Out-Null }
    catch { $rejected = $true }
    if (-not $rejected) { throw 'Migration accepted an unresolved Allow rule.' }

    $global:RDPShieldTestExtraRule = $false
    $global:RDPShieldTestIPBanWide = $true
    $rejected = $false
    try { & $script -ConfigPath $configPath -DisableRuleNames 'Legacy-RDP' -RecoveryAddress '203.0.113.10' -PlanOnly 3>$null | Out-Null }
    catch { $rejected = $true }
    if (-not $rejected) { throw 'Migration accepted a broad IPBan whitelist rule.' }
    $global:RDPShieldTestIPBanWide = $false

    $global:RDPShieldTestExtraRule = $false
    $statePath = Join-Path ([System.IO.Path]::GetTempPath()) ('rdpshield-migration-state-' + [guid]::NewGuid().ToString('N') + '.json')
    $state = @{ Status = 'Pending'; DisabledRules = @('Legacy-RDP'); RollbackAt = (Get-Date).AddMinutes(10).ToUniversalTime().ToString('o') }
    $state | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding UTF8
    & (Join-Path $root 'src\RDPShield-Rollback-Migration.ps1') -StatePath $statePath | Out-Null
    if ((Get-Content $statePath -Raw | ConvertFrom-Json).Status -ne 'RolledBack' -or $global:RDPShieldTestRestored -notcontains 'Legacy-RDP') {
        throw 'Rollback did not restore the original rule.'
    }

    $state.Status = 'Pending'
    $state | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding UTF8
    $global:RDPShieldTestRuleDisabled = $true
    $global:RDPShieldTestRollbackTask = $true
    & (Join-Path $root 'src\RDPShield-Confirm-Migration.ps1') -ConfigPath $configPath -StatePath $statePath -VerifiedNewConnection | Out-Null
    if ((Get-Content $statePath -Raw | ConvertFrom-Json).Status -ne 'Confirmed' -or $global:RDPShieldTestRollbackTask) {
        throw 'Confirmation did not cancel rollback.'
    }
    Remove-Item -LiteralPath $statePath
    Write-Host 'Migration plan tests passed.'
} finally {
    Remove-Item -LiteralPath $configPath
    foreach ($name in @('RDPShieldTestExtraRule', 'RDPShieldTestRuleDisabled', 'RDPShieldTestRollbackTask', 'RDPShieldTestRestored', 'RDPShieldTestIPBanWide')) {
        Remove-Variable -Name $name -Scope Global -ErrorAction SilentlyContinue
    }
}
