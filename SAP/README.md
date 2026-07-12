# SAP

Rules for the SAP SIEM integration — surfaces SAP security audit log events (logon failures, error details) in Wazuh so ERP-layer attacks are visible next to OS and network telemetry.

| File | Purpose |
|---|---|
| `200500-sap.xml` | Rules (group `sap_siem`) over SAP audit events, including per-error detail alerts — rule IDs 200500+ |

**Prerequisite:** SAP audit log forwarding (e.g. via the SOCFortress SAP integration pipeline) delivering JSON to the manager.
