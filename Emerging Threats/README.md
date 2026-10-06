# Emerging Threats (2025–2026)

Detections added in this fork for the techniques that dominate current threat reporting, the products on the CISA Known Exploited Vulnerabilities list, and 2026 exploits and supply-chain compromises. They're written for Wazuh 4.x and run on top of the Sysmon telemetry described in [`Windows_Sysmon`](../Windows_Sysmon).

## What it detects

| Rule IDs | Threat | MITRE ATT&CK |
|---|---|---|
| 150000–150003 | **ClickFix / fake-CAPTCHA "paste-and-run"**: download cradles spawned by explorer, Win+R `RunMRU` evidence, fake-verification text, remote HTA via `mshta` | T1204.004, T1059.001, T1218.005 |
| 150010–150012 | **RMM tool abuse**: NetSupport, ScreenConnect, AnyDesk, Atera and RustDesk running; NetSupport from non-standard paths; silent MSI installs of RMM software | T1219 |
| 150020–150021 | **C2 tunneling**: `cloudflared`, `ngrok`, `bore`, SSH reverse tunnels | T1572, T1090 |
| 150030–150031 | **USB-borne worms** (Raspberry Robin, Gamarue): `msiexec` fetching remote MSIs, script hosts started from a removable-drive root | T1091, T1218.007 |
| 150040–150041 | **BYOVD / EDR killers**: drivers without a valid signature, service-stop commands aimed at EDR/AV products | T1068, T1685 |
| 150050 | **Infostealers**: command-line copies of browser credential stores (`Login Data`, `key4.db`, …) | T1555.003 |
| 150060 | **SMB lateral movement**: executables written to `ADMIN$`/`C$` (ransomware staging) | T1021.002 |
| 150070–150071 | **SharePoint "ToolShell"** web shells (`spinstall*.aspx`, `debug_dev.js`) and script files written into `TEMPLATE\LAYOUTS` | T1190, T1505.003 |
| 150072 | **Web shells**: IIS, Apache, nginx, PHP, Tomcat or Exchange workers spawning shells and recon tools | T1505.003, T1190 |
| 150073–150076 | **Exploited server products (CISA KEV)**: ScreenConnect server, PaperCut `pc-app.exe` and WSUS (CVE-2025-59287) spawning shells | T1190, T1059, T1203 |
| 150080–150082 | **ADCS "Certighost" (CVE-2026-54121)**: CDC-chase certificate requests and issuance, `GHOST*$` machine accounts | T1649, T1136.002 |
| 150083–150085 | **RedSun** local privilege escalation: staged `TieringEngineService.exe`, `\REDSUN` pipe, SYSTEM `conhost.exe` | T1036.005, T1055, T1134.002 |
| 150086 | **Snipping Tool CVE-2026-33829**: `ms-screensketch:` URI pointing at a UNC or HTTP path (NTLM coercion) | T1187 |
| 150087 | **Netlogon CVE-2026-41089**: LSASS crash in `netlogon.dll` with `0xc0000409` | T1499.004 |
| 150090–150095 | **npm supply-chain compromises**: Axios 1.14.1 / 0.30.4 (`plain-crypto-js` dropper) and TanStack "Mini Shai-Hulud" (files, processes, C2 DNS) | T1195.002, T1059.007 |

Rules 150070 onwards are translations of SigmaHQ rules (named in a comment above each rule), mapped to Wazuh's field names and backslash escaping.

## Prerequisites

- Sysmon on Windows agents. Any config that logs process creation, file creation, pipe and DNS events works; [`Windows_Sysmon/sysmon_install.ps1`](../Windows_Sysmon/sysmon_install.ps1) installs a pinned sysmon-modular config. The rules chain off the `sysmon_event1`, `sysmon_event6`, `sysmon_event_11`, `sysmon_event_13`, `sysmon_event_17` and `sysmon_event_22` groups.
- **150060** needs the *Audit Detailed File Share* policy (Security event 5145). It is off by default and can be high-volume on file servers.
- **150080–150081** need ADCS auditing on the CA: `certutil -setreg CA\AuditFilter 127`, restart CertSvc, and enable the *Certification Services* audit subcategory.
- **150082** needs *Audit Computer Account Management*.

## Tuning

- **150010** fires at level 6 on *any* RMM execution by design; treat it as an inventory signal. Allow-list the RMM products your organization sanctions, then raise the level so unexpected RMM software alerts loudly.
- **150002** (fake-CAPTCHA text) is the highest-fidelity rule here. Treat any hit as an incident until proven otherwise.
- **150072** can fire on web applications that legitimately shell out. Add a negated `win.eventdata.commandLine` or `parentImage` field for those.
- **150080**: add a negated `win.eventdata.attributes` field listing your domain controllers. Legitimate chase requests name a real DC.
- Rule IDs stop at 150099. Wazuh 4.14 ships its own rules at 150100–150103 and 150150.

## Testing

```bash
python tools/test_emerging_threats.py   # regex/escaping regression tests (runs in CI)
/var/ossec/bin/wazuh-logtest            # on the manager, with a real event
```

## Sources

- [ReliaQuest Threat Spotlight, March–May 2026](https://reliaquest.com/blog/threat-spotlight-whats-trending-top-cyber-attacker-techniques-march-may-2026): ClickFix at ~15% of initial access, SMB at 36% of lateral movement, cloudflared and NetSupport named
- [Microsoft: Think before you ClickFix (Aug 2025)](https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/)
- [ANY.RUN ClickFix technique tracker](https://any.run/malware-trends/clickfix/)
- [CISA Known Exploited Vulnerabilities catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog): SharePoint, ConnectWise, PaperCut and WSUS entries
- [SigmaHQ](https://github.com/SigmaHQ/sigma) `rules/` and `rules-emerging-threats/` (Detection Rule License 1.1)
