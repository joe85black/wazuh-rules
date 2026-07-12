# Emerging Threats (2025–2026)

Custom detections added in this fork for the techniques dominating current threat reporting — written for Wazuh 4.x on top of the Sysmon ruleset shipped in [`Windows_Sysmon`](../Windows_Sysmon).

## What it detects

| Rule IDs | Threat | MITRE ATT&CK |
|---|---|---|
| 150000–150003 | **ClickFix / fake-CAPTCHA "paste-and-run"** — explorer-spawned download cradles, Win+R `RunMRU` evidence, fake-verification marker text, remote HTA via `mshta` | T1204.004, T1059.001, T1218.005 |
| 150010–150012 | **RMM tool abuse** — NetSupport/ScreenConnect/AnyDesk/Atera/RustDesk execution, NetSupport from non-standard paths, silent MSI installs of RMM software | T1219 |
| 150020–150021 | **Tunneling for C2** — `cloudflared`, `ngrok`, `bore`, SSH reverse tunnels | T1572, T1090 |
| 150030–150031 | **USB-borne worms** (Raspberry Robin, Gamarue) — `msiexec` fetching remote MSIs, script hosts launched from removable-drive roots | T1091, T1218.007 |
| 150040–150041 | **BYOVD / EDR killers** — drivers with non-valid signatures, service-stop commands aimed at EDR/AV products | T1068, T1562.001 |
| 150050 | **Infostealers** — command-line copies of browser credential stores (`Login Data`, `key4.db`, …) | T1555.003 |
| 150060 | **SMB lateral movement** — executables written to `ADMIN$`/`C$` shares (ransomware staging) | T1021.002 |

## Prerequisites

- Sysmon on Windows agents, configured per this repo's `Windows_Sysmon` folder (rules chain off the `sysmon_event1`, `sysmon_event_13`, and `sysmon_event6` groups).
- Rule **150060** additionally requires the *Audit Detailed File Share* policy (Security event 5145), which is not enabled by default and can be high-volume on file servers.

## Tuning

- **150010** fires at level 6 on *any* RMM execution by design — it is an inventory signal. Allow-list the RMM products your organization sanctions, then raise the level so unexpected RMM software alerts loudly.
- **150002** (fake-CAPTCHA marker text) is the highest-fidelity rule here; treat any hit as an incident until proven otherwise.
- Test before deploying: `/var/ossec/bin/wazuh-logtest`, then `systemctl restart wazuh-manager`.

## Sources

- [ReliaQuest Threat Spotlight, March–May 2026](https://reliaquest.com/blog/threat-spotlight-whats-trending-top-cyber-attacker-techniques-march-may-2026) — ClickFix at ~15% of initial access; SMB at 36% of lateral movement; cloudflared and NetSupport called out by name
- [Microsoft — Think before you ClickFix (Aug 2025)](https://www.microsoft.com/en-us/security/blog/2025/08/21/think-before-you-clickfix-analyzing-the-clickfix-social-engineering-technique/)
- [ANY.RUN ClickFix technique tracker](https://any.run/malware-trends/clickfix/)
