# Manager

Self-monitoring rules for the Wazuh manager's own log (`ossec.log`) — catch operational problems in the SIEM itself, such as duplicate agent authentication.

| File | Purpose |
|---|---|
| `decoder-manager-logs.xml` | Decoder for manager log lines (goes in `/var/ossec/etc/decoders/`) |
| `500010-manager_logs.xml` | Rules (group `manager_logs`), e.g. duplicate-agent auth detection — rule IDs 500010+ |

**Note:** unlike most folders here, this one includes a **decoder** — copy it to the decoders directory, not the rules directory. The install script in the repo root handles this automatically.
