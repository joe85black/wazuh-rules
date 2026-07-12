# Beelzebub

Rules for [Beelzebub](https://github.com/mariocandela/beelzebub), a low-code honeypot framework. Any interaction with the honeypot's fake SSH terminal is inherently suspicious, so these rules surface attacker sessions with high signal.

| File | Purpose |
|---|---|
| `100660-beelzebub.xml` | Rules (group `beelzebub`) for honeypot SSH terminal session interaction — rule IDs 100660+ |

**Prerequisite:** Beelzebub deployed and its JSON event log forwarded to Wazuh (agent `localfile` or syslog).
