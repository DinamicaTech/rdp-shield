# Planned IPBan integration

IPBan remains an optional, separately installed product. RDP Shield will not install IPBan, change its ban thresholds, or manage its ban rules.

Users who want IPBan must install it themselves using the official [Windows installation instructions](https://github.com/DigitalRuby/IPBan#install) or [release downloads](https://github.com/DigitalRuby/IPBan/releases). RDP Shield will detect an existing installation; it will not run IPBan's installer.

## Data flow

1. RDP Shield owns the country and emergency RDP Allow rules.
2. IPBan owns failed-login detection and ban rules.
3. When enabled, RDP Shield copies **only explicitly configured** emergency IPv4 addresses or DNS names into IPBan's `Whitelist` setting. It preserves all entries that were already there.
4. RDP Shield checks the active IPBan firewall rules during its audit. An IPBan whitelist rule can allow traffic outside the country ranges, so every whitelisted source must be intentional.

IPBan documents IPv4 addresses, CIDR ranges, URLs, and DNS names in `Whitelist`. We will test DNS refresh behavior against the target IPBan version before deciding whether to store the DNS name directly or synchronize resolved addresses. The [IPBan configuration guide](https://github.com/DigitalRuby/IPBan/wiki/Configuration) describes the setting; its [configuration reload code](https://github.com/DigitalRuby/IPBan/blob/master/IPBanCore/Core/IPBan/IPBanService_Private.cs) watches the override file for changes. The integration will avoid service restarts when the installed version applies configuration changes automatically.

## Update and recovery rules

- Discover the IPBan service and override configuration location. Never assume a fixed `Program Files` path.
- Back up the override file before the first edit. Parse it as XML, validate the resulting file, and replace it only when the value changes.
- Track entries added by RDP Shield so future updates remove only its own obsolete entries. Preserve administrator-managed entries and all unrelated settings.
- If IPBan is absent or its configuration is unsupported, report that status and leave IPBan unchanged. Country and emergency firewall rules continue to work independently.
- Never import IPs learned from successful RDP logins into the country list or emergency access automatically. Such IPs may be useful for a local IPBan policy, but they are not an authorization to widen RDP access.

The server-specific `Actualizar-IPBan-Whitelist.ps1` in the local reference directory is not part of the public project. Its user names, fixed IPs, and five-minute task are deployment details, not safe defaults for other installations.
