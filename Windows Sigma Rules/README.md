# Windows Sigma Rules (Built-in Event Log)

A large set of detections converted from community [Sigma](https://github.com/SigmaHQ/sigma) rules, targeting **native Windows Security event logs** (no Sysmon required) — DCSync attempts, AD object ACL abuse, and many more.

| File | Purpose |
|---|---|
| `300001-win_sigma_rules_builtin.xml` | Sigma-derived rules (group `windows,security`) — rule IDs 300001+ |

**Note:** for Sigma coverage of *Sysmon* telemetry, see [`Windows_Sysmon`](../Windows_Sysmon) and [`Windows Chainsaw`](../Windows%20Chainsaw). Some rules assume advanced audit policies are enabled (e.g. Directory Service Access auditing for the DCSync detections).
