# Windows Sigma Rules (Built-in Event Log)

Seven detections converted from [SigmaHQ](https://github.com/SigmaHQ/sigma) rules for **native Windows event logs**. No Sysmon is needed.

| Rule | Event | Detects | ATT&CK |
|---|---|---|---|
| 300001 | Security 5136 | PowerView `Add-DomainObjectAcl` granting DCSync rights | T1098, T1003.006 |
| 300002 | Security 4662 | WriteDAC on the domain object | T1222.001 |
| 300003 | Security 4662 | AD replication (DCSync) requested by a non-machine account | T1003.006 |
| 300004 / 300005 | Security 4698 / System 7045 | Chafer (APT39) scheduled task / service names | T1053.005, T1543.003 |
| 300006 | System 7045 | Turla PNG dropper service (`WerFaultSvc`) | T1543.003 |
| 300007 | Application | `Microsoft-Windows-Audit-CVE` events (Windows reporting a known-CVE exploitation attempt) | T1203 |

Fields use Wazuh's eventchannel names: the event ID is in `win.system.eventID` and event data is camelCase (`win.eventdata.accessMask`). Earlier versions used `win.eventdata.EventID` and PascalCase names, so none of these rules could match.

**Prerequisites:** *Directory Service Access* and *Directory Service Changes* auditing on domain controllers (300001–300003), *Other Object Access Events* (300004).

For Sigma coverage of Sysmon telemetry, see [`Windows_Sysmon`](../Windows_Sysmon), [`Emerging Threats`](../Emerging%20Threats) and [`Windows Chainsaw`](../Windows%20Chainsaw).
