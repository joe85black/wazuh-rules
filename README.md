# Wazuh Detection Rules

[![Validate rules](https://github.com/joe85black/wazuh-rules/actions/workflows/validate.yml/badge.svg)](https://github.com/joe85black/wazuh-rules/actions/workflows/validate.yml)
[![Update threat-intel lists](https://github.com/joe85black/wazuh-rules/actions/workflows/update-threat-intel.yml/badge.svg)](https://github.com/joe85black/wazuh-rules/actions/workflows/update-threat-intel.yml)

Detection rules and integrations for [Wazuh](https://wazuh.com/) 4.x (validated against **4.14.8**). This is a maintained fork of [SOCFortress/Wazuh-Rules](https://github.com/socfortress/Wazuh-Rules) that adds:

- weekly-refreshed open threat intel
- detections for current attacker techniques and exploited vulnerabilities
- CI validation of every rule

Wazuh's default ruleset is a solid baseline but light on modern endpoint tradecraft. This repo adds about 2,180 MITRE ATT&CK-mapped rules built around Sysmon telemetry, plus ~45 tool and cloud integrations.

## What this fork adds

- **[Threat Intel](Threat%20Intel):** CDB lists built from abuse.ch (Feodo Tracker, SSLBL, ThreatFox, URLhaus, MalwareBazaar), Spamhaus DROP and the CISA KEV catalog, refreshed every Monday by a GitHub Action. Rules 151000–151011 match them against:
  - Sysmon network and DNS events
  - Suricata EVE events
  - firewall logs
  - FIM hashes
  - vulnerability-detection findings (any KEV CVE on an agent is raised to level 13, and level 14 if it's used by ransomware)
- **[Emerging Threats](Emerging%20Threats)** (150000–150095), detections for:
  - ClickFix, RMM abuse, C2 tunneling, USB worms, BYOVD, infostealers and SMB lateral movement
  - post-exploitation of CISA KEV products (SharePoint ToolShell, ScreenConnect, PaperCut, WSUS, web shells)
  - 2026 exploits translated from SigmaHQ (ADCS Certighost CVE-2026-54121, RedSun, Snipping Tool CVE-2026-33829, Netlogon CVE-2026-41089)
  - the Axios and TanStack npm supply-chain compromises
- **Working Sysmon rules.** About 250 upstream rules used PascalCase field names, which never match Wazuh's camelCase. Most rule-name conditions targeted names the current sysmon-modular config no longer emits, and the Event 17 and Event 22 chains were broken by misnumbered overwrites. All of this is fixed; see [`Windows_Sysmon/COVERAGE.md`](Windows_Sysmon/COVERAGE.md) and the [changelog](CHANGELOG.md).
- **Current MITRE ATT&CK.** Every `<mitre>` ID is checked against the latest ATT&CK release; ~150 revoked or deprecated IDs were remapped.
- **CI and tooling** in [`tools/`](tools): a linter for rule IDs, parents, groups, MITRE IDs, field names and list references; pattern regression tests; the threat-intel generator; and the Sysmon re-anchor script.
- **A README in every integration folder.** The repo is kept in sync with upstream (last checked 2026-10-05; no new upstream commits).

## Getting started

**Prerequisite:** Wazuh manager 4.x ([install docs](https://documentation.wazuh.com/current/index.html)). Windows detections also need [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) on agents. [`Windows_Sysmon/sysmon_install.ps1`](Windows_Sysmon/sysmon_install.ps1) installs it with a pinned, hash-verified sysmon-modular config.

### Option 1: install everything with the script

```bash
git clone https://github.com/joe85black/wazuh-rules.git
cd wazuh-rules && sudo bash wazuh_socfortress_rules.sh
```

The script:

1. Backs up `etc/rules`, `etc/decoders`, `etc/lists` and `ossec.conf`.
2. Copies every rule and decoder from this fork.
3. Installs and registers every CDB list the rules reference.
4. Validates the configuration with `wazuh-analysisd -t`, then restarts the manager.

If anything fails, it restores the backup. Use `-r <git url>` / `-b <branch>` to install from another repo or branch.

### Option 2: pick and choose

Each folder is self-contained. Copy the `.xml` rule files you want (and any decoders or lists the folder's README mentions) to the manager, then restart:

```bash
cp "Emerging Threats/150000-emerging_threats.xml" /var/ossec/etc/rules/
/var/ossec/bin/wazuh-analysisd -t      # configuration test
systemctl restart wazuh-manager
```

## Rule ID map

Keep your own custom rules clear of these ranges:

| Range | Contents |
|---|---|
| 61645–61653 | Overwrites of Wazuh's built-in Sysmon base rules ([Sysmon New Events](Sysmon%20New%20Events)) |
| 96600–96601 | Snyk (below Wazuh's custom range; doesn't clash with 4.14 built-ins) |
| 100000–101349 | Suricata, AWS, Autoruns, Sigcheck, Domain Stats, MISP, OpenCTI, Maltrail, AbuseIPDB, Beelzebub, Sysmon Event 1–2, PowerShell (these ranges interleave) |
| 102101–121201 | Sysmon Events 3–22, Office 365 (108000), Office Defender (109000), Sysmon New Events (109209–109210) |
| 150000–150099 | Emerging Threats |
| 151000–151049 | Threat Intel |
| 200000–201999 | Chainsaw, Yara, Auditd, Sysmon for Linux, Osquery, Packetbeat, vendor and API integrations, inventory |
| 300001–300102 | Windows Sigma rules, Cisco Secure Endpoint |
| 400201–400225 | Open-Audit |
| 500010 | Wazuh manager self-monitoring |
| 600000+ | Active Response audit rules |
| 700001–700420 | Tetragon, PingCastle (700400) |
| 800100+ / 900000+ | SOCFortress custom detections; exclusion (noise-reduction) rules |

Wazuh 4.14 itself ships rules at 150100–150103, 150150, 184665–185013 and 500000–500102. The linter flags any collision with the built-in ruleset.

## Integrations index

### Windows endpoint

| Folder | What you get |
|---|---|
| [Windows_Sysmon](Windows_Sysmon) | The core: MITRE-mapped rules for Sysmon events 1–22, plus the Sysmon installer |
| [Sysmon New Events](Sysmon%20New%20Events) | Makes Sysmon events 17–25 visible (pipes, WMI, file delete, clipboard, tampering) |
| [Emerging Threats](Emerging%20Threats) | Current attacker techniques, KEV post-exploitation, 2026 exploits and supply-chain compromises |
| [Windows Sigma Rules](Windows%20Sigma%20Rules) | Sigma-converted detections for native Security, System and Application logs (no Sysmon needed) |
| [Windows Chainsaw](Windows%20Chainsaw) | [Chainsaw](https://github.com/WithSecureLabs/chainsaw) + Sigma scanning of event logs, with rules to ingest results |
| [Windows Powershell](Windows%20Powershell) | PowerShell script-block detections (PowerView/PowerSploit cmdlets, encoded commands, download cradles) |
| [Windows Autoruns](Windows%20Autoruns) | Sysinternals Autoruns persistence sweeps |
| [Windows Sysinternals Sigcheck](Windows%20Sysinternals%20Sigcheck) | Unsigned-binary sweeps via Sigcheck |
| [Windows Logon Sessions](Windows%20Logon%20Sessions) | Logon-session tracking and anomalies |
| [SOCFortress](SOCFortress) | Misc. custom Windows detections (ETW tampering, …) |
| [Exclusion Rules](Exclusion%20Rules) | Noise reduction: sinks known-benign events |

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
| [Suricata](Suricata) | IDS alerts and EVE metadata (JSON eve.log) |
| [Packetbeat](Packetbeat) | Network flow/protocol metadata |
| [Modsecurity](Modsecurity) | WAF events |
| [OpnSense](OpnSense) | OPNsense / NAXSI logs + decoder |
| [Nmap](Nmap) | Scheduled Nmap scans indexed as events |
| [Maltrail](Maltrail) | Malicious-traffic detection events |
| [Beelzebub](Beelzebub) | SSH honeypot session alerts |

### Threat intel & enrichment

| Folder | What you get |
|---|---|
| [Threat Intel](Threat%20Intel) | Weekly abuse.ch / Spamhaus / CISA KEV CDB lists and matching rules (no API keys) |
| [MISP](MISP) | IoC lookups against MISP |
| [OpenCTI](OpenCTI) | IoC enrichment via OpenCTI |
| [AbuseIPDB](AbuseIPDB) | IP reputation lookups |
| [Domain Stats](Domain%20Stats) | Domain age/first-seen enrichment (catches fresh phishing domains), AlienVault OTX |
| [DNStwist](DNStwist) | Typosquat/lookalike-domain monitoring |
| [SOCFortress API](SOCFortress%20API) | SOCFortress IoC API verdicts |

### EDR / AV / email / identity

| Folder | What you get |
|---|---|
| [Crowdstrike](Crowdstrike), [Cisco Secure Endpoint](Cisco%20Secure%20Endpoint), [Sophos](Sophos), [Trend Micro](Trend%20Micro), [F-Secure](F-Secure), [Office Defender](Office%20Defender) | Vendor EDR/AV alert ingestion |
| [Office 365](Office%20365) | O365 audit/management activity |
| [Mimecast](Mimecast), [Sublime](Sublime) | Email security verdicts (blocked mail, phishing detections) |
| [Duo](Duo) | MFA denials, fraud reports, bypasses and push-bombing |

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
| `wazuh_socfortress_rules.sh` | Bulk installer (backup → install rules, decoders and lists → config test → restart, with rollback) |
| `tools/validate_rules.py` | Linter run in CI: rule ID collisions (repo + Wazuh 4.14.8 built-ins), missing parents/groups, ATT&CK IDs, field casing, list references |
| `tools/test_emerging_threats.py` | Pattern regression tests for the Emerging Threats rules |
| `tools/update_threat_intel.py` | Rebuilds the Threat Intel CDB lists (run weekly by GitHub Actions) |
| `tools/reanchor_sysmon.py` | Re-keys Sysmon rules on ATT&CK technique IDs and writes `Windows_Sysmon/COVERAGE.md` |
| `tools/update_mitre_ids.py` | Remaps revoked/deprecated ATT&CK IDs in every rule |
| `tools/refresh_reference_data.py` | Refreshes the Wazuh built-in, ATT&CK and sysmon-modular reference data the tools use |
| `wazuh-certs-tool.sh` + `config.yml` | Wazuh indexer/manager certificate generation helper |
| `prexisting_sysmon_wazuh_uninstall.ps1` | Removes pre-existing Sysmon + Wazuh agent installs before re-deployment |

## Validation

Every push and pull request runs [`validate.yml`](.github/workflows/validate.yml):

```bash
python tools/validate_rules.py          # 0 errors required
python tools/test_emerging_threats.py
python tools/reanchor_sysmon.py && git diff --exit-code -- Windows_Sysmon/
```

These are static checks and can't replace a live test. After deploying, confirm the expected rule fires with `/var/ossec/bin/wazuh-logtest` and a real sample event. If the manager fails to start, check `/var/ossec/logs/ossec.log`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for ID allocation, MITRE and field conventions, and how to run the checks. Issues and PRs are welcome: new integrations, tuning, or false-positive reports.

## Credits & license

- Original rules and integrations: **[SOCFortress](https://www.socfortress.co/)** ([upstream repo](https://github.com/socfortress/Wazuh-Rules), [blog](https://socfortress.medium.com/)). Thank you for open-sourcing this.
- [Wazuh](https://wazuh.com/) team, [Taylor Walton](https://www.youtube.com/channel/UC4EUQtTxeC8wGrKRafI6pZg), [Juan Romero](https://github.com/juaromu).
- Detection logic in Emerging Threats rules 150070+ is adapted from [SigmaHQ](https://github.com/SigmaHQ/sigma) under the [Detection Rule License 1.1](https://github.com/SigmaHQ/Detection-Rule-License).
- Threat-intel data: [abuse.ch](https://abuse.ch/) (CC0), [Spamhaus DROP](https://www.spamhaus.org/drop/), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (public domain).
- The upstream repository doesn't declare a license. This fork preserves all upstream content and attribution. The fork's own additions (Emerging Threats rules 150000–150060, Threat Intel rules, `tools/`) are free to use without restriction.
