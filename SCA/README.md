# SCA

Rules for Wazuh's built-in [Security Configuration Assessment](https://documentation.wazuh.com/current/user-manual/capabilities/sec-config-assessment/index.html) (SCA) module — reshapes SCA scan results into indexed, per-check events for dashboards and compliance reporting.

| File | Purpose |
|---|---|
| `200910-wazuh_sca.xml` | Rules (group `wazuh_sca`) indexing SCA collection results — rule IDs 200910+ |

**Prerequisite:** SCA enabled on agents (it is by default); typically paired with an external poller that pulls per-check results from the Wazuh API.
