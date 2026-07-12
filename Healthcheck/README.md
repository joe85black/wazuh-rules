# Healthcheck

Rules for the SOCFortress healthcheck integration — periodic health probes of your SIEM stack components, indexed so an unhealthy component raises a Wazuh alert instead of failing silently.

| File | Purpose |
|---|---|
| `200990-healthcheck.xml` | Rules (group `socfortress_healthcheck`) — healthy results index quietly, unhealthy states alert with the failing message — rule IDs 200990+ |
