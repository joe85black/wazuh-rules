# Duo

Rules for [Cisco Duo](https://duo.com/) MFA authentication logs. Brings second-factor denials, fraud reports, and bypass events into Wazuh so MFA anomalies correlate with the rest of your telemetry.

| File | Purpose |
|---|---|
| `200930-duo.xml` | Rules (group `duo`) over Duo Authentication Log API events — rule IDs 200930+ |

**Prerequisite:** a poller for the Duo Admin API (`/admin/v2/logs/authentication`) shipping JSON to the manager.
