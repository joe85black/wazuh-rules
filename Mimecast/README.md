# Mimecast

Rules for [Mimecast](https://www.mimecast.com/) email security logs — brings blocked/held mail, impersonation catches, and URL-protect events into Wazuh alongside your endpoint telemetry.

| File | Purpose |
|---|---|
| `200940-mimecast.xml` | Rules (group `mimecast`) over Mimecast integration logs — rule IDs 200940+ |

**Prerequisite:** a poller for the Mimecast API shipping JSON events to the manager.
