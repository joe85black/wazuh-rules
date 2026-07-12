# PingCastle

Rules for [PingCastle](https://www.pingcastle.com/), the Active Directory security auditing tool. Runs PingCastle on a schedule, extracts the health-check findings, and alerts on AD weaknesses (stale accounts, dangerous delegations, weak policies) through Wazuh.

| File | Purpose |
|---|---|
| `findings.ps1` | PowerShell wrapper that runs PingCastle, parses the XML health-check report, and writes findings as JSON events for the agent to pick up |
| `700400-pingcastle.xml` | Rules (JSON format) grading findings by PingCastle severity — rule IDs 700400+ |

**Deploy:** place PingCastle + `findings.ps1` on a domain-joined host, schedule the script, copy the XML to the manager's rules directory, restart the manager.
