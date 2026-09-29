# RDP Shield

![RDP Shield — layered access control for Windows Remote Desktop](assets/rdp-shield-banner.svg)

**Country-based RDP access, dynamic emergency access, and firewall visibility for Windows.** RDP Shield is a PowerShell toolkit being developed for Windows Server. [IPBan](https://github.com/DigitalRuby/IPBan) can provide an independent brute-force protection layer; optional whitelist synchronization is available for testing.

**Want IPBan protection? Install IPBan separately first.** RDP Shield does not download or install it. Use the official [IPBan Windows installation instructions](https://github.com/DigitalRuby/IPBan#install) or the [official releases](https://github.com/DigitalRuby/IPBan/releases), then explicitly enable the optional integration.

> [!WARNING]
> **Development status:** The scripts are not yet a production-ready installer. The firewall workflow has not been tested on Windows Server. Keep an open session and an independent recovery path when testing RDP rules.

## How it works

| Layer | Current capability |
|---|---|
| Country ranges | Download and validate IPv4 CIDR ranges from [IPdeny](https://www.ipdeny.com/ipblocks/data/aggregated/) for a configured country. |
| Emergency access | Resolve static IPv4 addresses and DNS names before updating dedicated TCP and UDP firewall rules. |
| Firewall audit | Find other active inbound Allow rules that may still admit traffic to the RDP port. |
| Firewall rules | Stage or update rules owned by RDP Shield, with a Windows Firewall export before changes. |
| Status | Report country data, resolved emergency addresses, managed rules, and possible competing Allow rules. |
| IPBan | Optionally synchronizes resolved emergency IPv4 addresses into an existing IPBan whitelist. [Details](docs/IPBAN-INTEGRATION.md). |

An Allow rule scoped to a country does **not** restrict traffic allowed by another active rule. The audit must be clear before claiming that RDP access is geographically restricted.

## Configuration

Copy `config/config.example.json` to `config/config.json`. The working configuration is ignored by Git. Set `Country`, `RdpPort`, and at least one IPv4 address or DNS name in `EmergencyAccess`.

```json
"EmergencyAccess": ["my-access.example.org", "203.0.113.10"]
```

These addresses are examples only. Check that your emergency access resolves correctly before making firewall changes.

## Read-only and local validation

Run these from the repository root in PowerShell. Country download writes only to the ignored `data/` directory. Firewall audit requires administrator privileges.

```powershell
.\src\RDPShield-Resolve-Emergency.ps1 -ResolveOnly
.\src\RDPShield-Update-Country.ps1
.\src\RDPShield-Apply-Firewall.ps1 -ValidateOnly
.\src\RDPShield-Audit-Firewall.ps1
.\src\RDPShield-Status.ps1 | Format-List
```

## Staging firewall rules in a test environment

Run elevated on a Windows test host after validating the configuration. `-StageOnly` creates country and emergency TCP/UDP rules without disabling existing rules. **The country filter is not effective while a broader Allow rule remains enabled.** The script saves a `.wfw` export in the ignored `backup/` directory.

```powershell
.\src\RDPShield-Apply-Firewall.ps1 -StageOnly -WhatIf
.\src\RDPShield-Apply-Firewall.ps1 -StageOnly
```

Review the audit results and verify remote access before changing any pre-existing firewall rules.

## Controlled migration of existing RDP rules

The migration tool disables **only local Allow rules named explicitly** on its command line. It refuses IPBan and Group Policy rules and requires every remaining competing Allow rule to be resolved first. It schedules a one-time SYSTEM rollback **before** disabling anything. If a new RDP connection is not tested and confirmed within the chosen window, the old rules are re-enabled.

Use the rule `Name` values reported by `RDPShield-Audit-Firewall.ps1`, not their display names. The recovery IPv4 address must already resolve from `EmergencyAccess` and appear in the active emergency TCP rule. Run from the installed `%ProgramData%\RDPShield` directory on a test server with independent console access:

```powershell
.\src\RDPShield-Start-Migration.ps1 -DisableRuleNames '<rule-name-1>','<rule-name-2>' -RecoveryAddress '<your-current-public-ip>' -PlanOnly
.\src\RDPShield-Start-Migration.ps1 -DisableRuleNames '<rule-name-1>','<rule-name-2>' -RecoveryAddress '<your-current-public-ip>'
# Open a NEW RDP connection from that recovery address, then:
.\src\RDPShield-Confirm-Migration.ps1 -VerifiedNewConnection
```

The default rollback window is 10 minutes. To revert immediately, run `RDPShield-Rollback-Migration.ps1`. Do not confirm merely because the original RDP session is still open.

## Preview installer and scheduled refresh

The installer copies scripts and configuration to `%ProgramData%\RDPShield`. Its default action prepares files and downloads the country list. `-StageFirewall` additionally creates the four managed firewall rules. `-RegisterTasks` adds daily country refresh and periodic emergency DNS refresh as SYSTEM; it requires `-StageFirewall`. It does not disable or edit existing firewall rules.

```powershell
.\Install-RDPShield.ps1 -PlanOnly
.\Install-RDPShield.ps1 -WhatIf
.\Install-RDPShield.ps1 -StageFirewall -RegisterTasks
```

The commands above require a populated `config/config.json`; the third command changes the local Windows firewall and scheduled tasks and must only be run in a disposable test environment for now. The installer refuses to overwrite an existing installation. `Uninstall-RDPShield.ps1` removes its scheduled tasks; use `-RemoveFirewallRules` only when an independent RDP access path has been checked. It leaves installed files and firewall exports for review.

To test optional IPBan synchronization, set `EnableIPBanIntegration` to `true` after installing IPBan. The service executable is used to locate `ipban.override.config`; set `IPBanConfigPath` explicitly if discovery fails. Preview with `RDPShield-Sync-IPBan.ps1 -PlanOnly`. The sync preserves existing entries, tracks only addresses it adds, and writes a `.rdpshield.bak` backup beside the IPBan configuration. It does not restart IPBan or modify ban thresholds or ban rules.

## Smoke tests

The offline smoke test checks address resolution, country list validation and preservation, firewall input validation, and the install plan without changing the firewall:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\tests\Smoke.ps1
```

## Roadmap

1. Expand isolated tests for real firewall rule updates, scheduled tasks, and uninstall.
2. Verify IPBan configuration reload and firewall rule behavior for the installed IPBan version.
3. Test installation, migration, timeout rollback, and recovery on Windows Server before the first stable release.

The local `Scripts` directory contains server-specific reference material and is excluded from Git. RDP Shield is released under the [MIT License](LICENSE).
