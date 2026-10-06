# Sysmon New Events

Makes Sysmon event types visible that Wazuh's built-in ruleset (`0595-win-sysmon_rules.xml`) decodes at level 0. It also adds two Windows Security detections. Original rules by [SOCFortress](https://www.socfortress.co/).

| Rule | Event | Notes |
|---|---|---|
| 61645, 61646 | Sysmon 17 / 18 (pipe created / connected) | Overwrites the built-ins at level 3. Parents of the `Windows_Sysmon` Event 17/18 rules. |
| 61647–61649 | Sysmon 19–21 (WMI event filter / consumer / binding) | Overwrites at level 3, T1546.003 |
| 61651 | Sysmon 23 (file delete archived) | Overwrites at level 3, T1070.004, T1485 |
| 61652 | Sysmon 24 (clipboard change) | Overwrites at level 3, T1115 |
| 61653 | Sysmon 25 (process tampering) | Overwrites at level 3, T1055 |
| 109209 | Security log cleared | Level 12, T1685.005 |
| 109210 | Logon type 9 via `seclogo`/Negotiate | Possible Pass-the-Hash. Level 12, T1550.002 |

Each overwrite keeps the built-in's event ID, parent and group; only the level, description and MITRE mapping change. The built-in IDs for events 6 and 22 are left alone, because `Windows_Sysmon/121201` and `121101` already surface those.

**Why overwrites instead of new rules:** Wazuh evaluates sibling rules highest level first and stops at the first match. Older versions of this file had two problems:

- Level-3 catch-alls hung directly off 61600 matched before the level-0 built-ins, which hid every built-in child rule.
- 61644, 61646 and 61647 were repurposed for the wrong event IDs (Wazuh 4.14 uses them for events 16, 18 and 19), which broke the Event 17 and Event 22 rule chains.
