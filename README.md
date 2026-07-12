# Wazuh Detection Rules

Curated, production-tested detection rules and integrations for [Wazuh](https://wazuh.com/) 4.x — a maintained fork of [SocFortress/Wazuh-Rules](https://github.com/socfortress/Wazuh-Rules) with per-folder documentation and an added ruleset for current (2025–2026) attacker techniques.

Wazuh's default ruleset is a solid baseline but light on modern endpoint tradecraft. This repo layers on richer, MITRE ATT&CK-mapped detections built around Sysmon telemetry plus ~40 tool and cloud integrations.

## What this fork adds

- **[Emerging Threats](Emerging%20Threats)** — new ruleset (IDs 150000–150199) for the techniques dominating current threat reporting: ClickFix / fake-CAPTCHA paste-and-run lures, RMM tool abuse, `cloudflared`/`ngrok` C2 tunneling, USB worms (Raspberry Robin), BYOVD/EDR-killer behavior, infostealer credential-store access, and SMB admin-share lateral movement.
- **A README in every integration folder** — what it detects, which files matter, rule ID ranges, and prerequisites.
- **Kept in sync with upstream** (last synced 2026-07-12, includes the PingCastle integration and the March 2026 MITRE/Sysmon ruleset refresh).
- Consolidated the duplicate `Active_Response`/`Active Response` folders into one.

## Getting started

**Prerequisite:** Wazuh Manager 4.x ([install docs](https://documentation.wazuh.com/current/index.html)). Windows detections additionally require [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) on agents — config and installer script are in [`Windows_Sysmon`](Windows_Sysmon).

### Option 1 — Pick and choose (recommended)

Each folder is self-contained. Copy the `.xml` rule files you want to the manager and restart:

```bash
cp "Emerging Threats/150000-emerging_threats.xml" /var/ossec/etc/rules/
# decoders (only a few folders have them, e.g. Manager/) go to /var/ossec/etc/decoders/
/var/ossec/bin/wazuh-logtest   # sanity-check before restarting
systemctl restart wazuh-manager
```

### Option 2 — Install everything via script

> ⚠️ **Check for rule ID collisions first.** If you already run custom rules, duplicate IDs will stop the `wazuh-manager` service. Back up `/var/ossec/etc/rules/` before running.

```bash
git clone https://github.com/joe85black/wazuh-rules.git
cd wazuh-rules && sudo bash wazuh_socfortress_rules.sh
```

Note: the script's internal `git clone` pulls from the SocFortress upstream. To install *this fork's* rules (including Emerging Threats), use Option 1, or edit the repo URL near line 195 of the script.

## Rule ID map

Custom rules in this repo use these ranges — keep your own rules clear of them:

| Range | Contents |
|---|---|
| 100000–121999 | Sysmon MITRE technique rules (per event ID), integrations (AWS, MISP, Office 365, Beelzebub, …) |
| 150000–150199 | **Emerging Threats (this fork)** |
| 200000–201999 | Chainsaw/Sigma, threat-intel + API integrations, inventory/SCA/software indexing |
| 300001+ | Sigma rules for native Windows event logs |
| 400000+ / 500010+ | OpnSense; Wazuh manager self-monitoring |
| 600000+ | Active Response audit rules |
| 700000+ | Tetragon; PingCastle (700400) |
| 800100+ / 900000+ | SOCFortress custom detections; exclusion (noise-reduction) rules |

## Integrations index

### Windows endpoint

| Folder | What you get |
|---|---|
| [Windows_Sysmon](Windows_Sysmon) | The core: MITRE-mapped rules for Sysmon events 1–22, Sysmon config + installer |
| [Sysmon New Events](Sysmon%20New%20Events) | Overrides adding Sysmon events 17/18 (named pipes) and newer event IDs to Wazuh's defaults |
| [Windows Sigma Rules](Windows%20Sigma%20Rules) | Sigma-converted detections for native Security logs (no Sysmon needed) |
| [Windows Chainsaw](Windows%20Chainsaw) | [Chainsaw](https://github.com/WithSecureLabs/chainsaw) + Sigma scanning of event logs, with rules to ingest results |
| [Windows Powershell](Windows%20Powershell) | PowerShell ScriptBlock-logging detections (encoded commands, download cradles) |
| [Windows Autoruns](Windows%20Autoruns) | Sysinternals Autoruns persistence sweeps into Wazuh |
| [Windows Sysinternals Sigcheck](Windows%20Sysinternals%20Sigcheck) | Unsigned-binary sweeps via Sigcheck |
| [Windows Logon Sessions](Windows%20Logon%20Sessions) | Logon-session tracking and anomalies |
| [Emerging Threats](Emerging%20Threats) | **This fork:** ClickFix, RMM abuse, tunneling, USB worms, EDR killers, infostealers, SMB lateral movement |
| [SOCFortress](SOCFortress) | Misc. custom Windows detections (ETW tampering, …) |
| [Exclusion Rules](Exclusion%20Rules) | Noise reduction: sink known-benign events (level 0) |

### Linux / cloud / containers

| Folder | What you get |
|---|---|
| [Sysmon Linux](Sysmon%20Linux) | Sysmon for Linux rules + decoder |
| [Auditd](Auditd) | auditd decoders + rules |
| [Falco](Falco) | Container runtime security events |
| [Tetragon](Tetragon) | eBPF runtime security (process exec, kernel probes, rootkit indicators) |
| [AWS](AWS) | CloudWatch / WAF events via the aws-s3 wodle |
| [Osquery](Osquery) | osquery pack results |
| [Yara](Yara) | YARA scan integration (active response scanning + rules) |

### Network & perimeter

| Folder | What you get |
|---|---|
| [Suricata](Suricata) | IDS alerts (JSON eve.log) |
| [Packetbeat](Packetbeat) | Network flow/protocol metadata |
| [Modsecurity](Modsecurity) | WAF events (incl. OPNsense/NAXSI decoder) |
| [OpnSense](OpnSense) | OPNsense firewall logs |
| [Nmap](Nmap) | Scheduled Nmap scans indexed as events |
| [Maltrail](Maltrail) | Malicious-traffic detection events |
| [Beelzebub](Beelzebub) | SSH honeypot session alerts |

### Threat intel & enrichment

| Folder | What you get |
|---|---|
| [MISP](MISP) | IoC lookups against MISP |
| [OpenCTI](OpenCTI) | IoC enrichment via OpenCTI |
| [AbuseIPDB](AbuseIPDB) | IP reputation lookups |
| [Domain Stats](Domain%20Stats) | Domain age/first-seen enrichment (catches fresh phishing domains) |
| [DNStwist](DNStwist) | Typosquat/lookalike-domain monitoring |
| [SOCFortress API](SOCFortress%20API) | SOCFortress IoC API verdicts |

### EDR / AV / email security

| Folder | What you get |
|---|---|
| [Crowdstrike](Crowdstrike), [Cisco Secure Endpoint](Cisco%20Secure%20Endpoint), [Sophos](Sophos), [Trend Micro](Trend%20Micro), [F-Secure](F-Secure), [Office Defender](Office%20Defender) | Vendor EDR/AV alert ingestion |
| [Office 365](Office%20365) | O365 audit/management activity |
| [Mimecast](Mimecast), [Sublime](Sublime) | Email security verdicts (blocked mail, phishing detections) |
| [Duo](Duo) | MFA authentication logs |

### Assessment, inventory & operations

| Folder | What you get |
|---|---|
| [Pingcastle](Pingcastle) | Active Directory security audit findings |
| [AD_Inventory](AD_Inventory) | Scheduled AD inventory collection |
| [Wazuh Inventory](Wazuh%20Inventory), [Software](Software), [SCA](SCA) | Syscollector/SCA results as indexed events |
| [Snyk](Snyk) | Dependency vulnerability findings |
| [Open-Audit](Open-Audit) | IT asset discovery events |
| [Pentest-Tools](Pentest-Tools) | External attack-surface scan findings |
| [SAP](SAP) | SAP security audit log integration |
| [DFIR-IRIS](DFIR-IRIS) | IR case-management activity |
| [Healthcheck](Healthcheck) | SIEM stack health probes |
| [Manager](Manager) | Wazuh manager self-monitoring (decoder + rules) |
| [Active Response](Active%20Response) | Windows response scripts (disable account, sinkhole domain, firewall block) + audit rules |

### Repo utilities

| File | Purpose |
|---|---|
| `wazuh_socfortress_rules.sh` | Bulk installer (backs up existing rules, clones, deploys, restarts) |
| `wazuh-certs-tool.sh` + `config.yml` | Wazuh indexer/manager certificate generation helper |
| `prexisting_sysmon_wazuh_uninstall.ps1` | Cleanly removes pre-existing Sysmon + Wazuh agent installs before re-deployment |

## Testing changes

Always dry-run rules before restarting the manager:

```bash
/var/ossec/bin/wazuh-logtest        # paste a sample log line, verify the expected rule fires
systemctl restart wazuh-manager && systemctl status wazuh-manager
```

If the manager fails to start after adding rules, check `/var/ossec/logs/ossec.log` for duplicate rule IDs or XML syntax errors.

## Contributing

Issues and PRs are welcome — new integrations, tuning improvements, or false-positive reports all help. For rule contributions: keep MITRE mappings on every rule, comment non-obvious regexes, and stay inside the rule ID ranges above.

## Credits & license

- All original rules and integrations: **[SOCFortress](https://www.socfortress.co/)** ([upstream repo](https://github.com/socfortress/Wazuh-Rules), [blog](https://socfortress.medium.com/)) — thank you for open-sourcing this.
- [Wazuh](https://wazuh.com/) team, [Taylor Walton](https://www.youtube.com/channel/UC4EUQtTxeC8wGrKRafI6pZg), [Juan Romero](https://github.com/juaromu).
- The upstream repository does not declare an explicit license; this fork preserves all upstream content and attribution. The Emerging Threats additions in this fork are free to use without restriction.
