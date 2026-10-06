# Changelog

Changes made in this fork. Upstream history is in [socfortress/Wazuh-Rules](https://github.com/socfortress/Wazuh-Rules/commits/main).

## 2026-10-05: Threat intel, rule repair and CI

Validated against Wazuh **4.14.8** and the current MITRE ATT&CK Enterprise release (modified 2026-08-04).

### Added

- **Threat Intel** (`Threat Intel/`, rules 151000–151011). CDB lists from abuse.ch Feodo Tracker, SSLBL, ThreatFox, URLhaus and MalwareBazaar, plus Spamhaus DROP and CISA KEV. The rules match them against Sysmon network/DNS events, Suricata EVE, firewall logs, FIM hashes and vulnerability-detection findings. KEV CVEs on an agent alert at level 13, or 14 when used by ransomware.
- **Emerging Threats** rules 150070–150095:
  - SharePoint ToolShell web shells, generic web shells, ScreenConnect server, PaperCut and WSUS (CVE-2025-59287) post-exploitation
  - ADCS Certighost (CVE-2026-54121), RedSun, Snipping Tool (CVE-2026-33829) and Netlogon (CVE-2026-41089)
  - the Axios and TanStack npm supply-chain compromises

  All are translated from SigmaHQ.
- **Duo** rules 200931–200935: denials, user-reported fraud, MFA bypass, lockouts, and push-bombing (5 denials in 10 minutes).
- **Tooling** (`tools/`): `validate_rules.py`, `test_emerging_threats.py`, `update_threat_intel.py`, `reanchor_sysmon.py`, `update_mitre_ids.py`, `refresh_reference_data.py`, plus committed reference data (Wazuh 4.14.8 built-in rule IDs and groups, ATT&CK techniques, sysmon-modular rule-name history).
- **GitHub Actions:** `validate.yml` on every push and PR; `update-threat-intel.yml` every Monday.
- `CONTRIBUTING.md`, `CHANGELOG.md`, `.gitignore`, `.gitattributes`, `Windows_Sysmon/COVERAGE.md`.

### Fixed

- **Windows_Sysmon:**
  - 240 conditions used `win.eventdata.RuleName` and 5 used `TargetObject`. Wazuh emits camelCase, so they never matched.
  - 163 `ruleName` conditions written for older sysmon-modular rule names now key on the technique ID. 59 revoked or deprecated IDs were remapped (e.g. T1089/T1562.001 → T1685, T1086 → T1059.001).
  - `<mitre>` tags now carry the exact (sub-)technique in the matched `RuleName`, instead of just its parent technique.
  - 63 rules that became exact duplicates were removed. Three higher-level duplicates were kept unchanged so no severity was lowered.
  - Conditions matching names used only by SOCFortress's private Sysmon config are kept as they were and documented.
  - The Cobalt Strike named-pipe rules 116102/117102 now match the current config's rule name and alert at level 12.
- **`sysmon_install.ps1`:**
  - The config URL returned 404. It now downloads sysmon-modular release `configs-082cba578667` and verifies its SHA256.
  - It now applies the config to existing Sysmon installs instead of skipping them.
- **Sysmon New Events:**
  - The overwrites of 61644, 61646 and 61647 reused the wrong event IDs, which broke the Event 17 and 22 rule chains and hid Event 16/19.
  - Level-3 catch-alls (109203–109208, 109211) shadowed the built-in children.

  Replaced with faithful level-3 overwrites of 61645–61649 and 61651–61653, and re-parented the Event 17/18 rules.
- **Windows Sigma Rules 300001–300007:** these filtered on `win.eventdata.EventID` and PascalCase fields, so none could match. They're rewritten with `win.system.eventID` and camelCase fields. 300005 used `TaskName` on event 7045; it now uses `serviceName`.
- **Exclusion Rules:** 53 rules used `if_group sysmon_event_7`, which doesn't exist (Wazuh's group is `sysmon_event7`). 14 duplicate rules were removed.
- **Windows PowerShell:**
  - 100550 pointed at a missing parent (100535); it now uses 100534.
  - 100543 only fired when a whole script block equalled a cmdlet name. It now uses a regex built from the same PowerView list, minus `Get-ADObject` and `Set-ADObject`, which are legitimate AD-module cmdlets.
- **Emerging Threats:**
  - 150031 and 150060 used backslash counts that never match Wazuh's doubled backslashes.
  - 150011 used two conditions on the same field, which is undocumented behaviour; it now uses a single pattern.
- **MITRE:** ~150 revoked or deprecated ATT&CK IDs were remapped across Auditd, Office 365, Osquery, Sysmon Linux, Tetragon and others. Malformed `T047` and `T0137` were fixed.
- **Group names:** Modsecurity, Crowdstrike, Falco, Nmap, Sophos and Suricata group names lacked a trailing comma, so inner groups were concatenated (e.g. `Modsecuritybruteforce`).
- **Office 365:** removed 108023, which was always shadowed by its level-5 duplicate 108055.
- **AbuseIPDB integration:** `custom-abuseipdb.py` had broken indentation and could not run. It also wrote the API key to `integrations.log` on every call. Both are fixed.
- **`wazuh_socfortress_rules.sh`:**
  - It now installs this fork instead of upstream.
  - It installs and registers CDB lists.
  - It runs `wazuh-analysisd -t` before restarting.
  - It fully restores rules, decoders, lists and `ossec.conf` on failure.
  - Fixed the `$(SYS_TYPE)` command-substitution bug.

### Docs

- Root README: corrected rule ID map (OpnSense is 200460, not 400000+; added Snyk, Cisco, the built-in overwrites, Wazuh's own 150100+ IDs), plus Threat Intel, validation and tooling sections.
- Rewrote the READMEs for Windows_Sysmon (it named the wrong config), Windows Sigma Rules (it claimed "a large set"; there are 7), Sysmon New Events, Duo and Emerging Threats.

## 2026-07-12: Professionalize fork

- Synced upstream, added the Emerging Threats ruleset (150000–150060), and documented every integration folder.
