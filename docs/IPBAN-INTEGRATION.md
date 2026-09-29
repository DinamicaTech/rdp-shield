# IPBan integration (development)

IPBan remains an optional, separately installed product. RDP Shield will not install IPBan, change its ban thresholds, or manage its ban rules.

Users who want IPBan must install it themselves using the official [Windows installation instructions](https://github.com/DigitalRuby/IPBan#install) or [release downloads](https://github.com/DigitalRuby/IPBan/releases). RDP Shield will detect an existing installation; it will not run IPBan's installer.

## Data flow

1. RDP Shield owns the country and emergency RDP Allow rules.
2. IPBan owns failed-login detection and ban rules.
3. When enabled, RDP Shield resolves `EmergencyAccess` and copies **only those IPv4 addresses** into IPBan's `Whitelist` setting. It preserves entries that were already there and tracks the entries it added for later updates.
4. RDP Shield checks the active IPBan firewall rules during its audit. An IPBan whitelist rule can allow traffic outside the country ranges, so every whitelisted source must be intentional.

IPBan documents IPv4 addresses, CIDR ranges, URLs, and DNS names in `Whitelist`. RDP Shield synchronizes **resolved IPv4 addresses** on the emergency refresh schedule so the firewall and IPBan receive the same sources. The [IPBan configuration guide](https://github.com/DigitalRuby/IPBan/wiki/Configuration) describes the setting; its [configuration reload code](https://github.com/DigitalRuby/IPBan/blob/master/IPBanCore/Core/IPBan/IPBanService_Private.cs) watches the override file for changes. The target version's reload behavior still needs a Windows Server test.

## Update and recovery rules

- Discover the IPBan service and override configuration location, with an explicit `IPBanConfigPath` fallback. No fixed `Program Files` path is assumed.
- Back up the override file before edits. Parse it as XML, validate the result, and replace it only when the value changes.
- Track entries added by RDP Shield so future updates remove only its own obsolete entries. Preserve administrator-managed entries and unrelated settings.
- If integration is enabled but IPBan is absent or its configuration is unsupported, stop the synchronized emergency refresh and leave existing rules unchanged. Disable integration in `config.json` to run country and emergency updates independently.
- Never import IPs learned from successful RDP logins into the country list or emergency access automatically. Such IPs may be useful for a local IPBan policy, but they are not an authorization to widen RDP access.

The server-specific `Actualizar-IPBan-Whitelist.ps1` in the local reference directory is not part of the public project. Its user names, fixed IPs, and five-minute task are deployment details, not safe defaults for other installations.
