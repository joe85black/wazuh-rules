# DFIR-IRIS

Rules for [DFIR-IRIS](https://dfir-iris.org/), an open-source incident response case management platform. Ingesting case activity into Wazuh lets you correlate IR casework with live alerts and audit analyst actions.

| File | Purpose |
|---|---|
| `200960-dfir_iris.xml` | Rules (group `dfir_iris`) indexing IRIS case collection events — rule IDs 200960+ |

**Prerequisite:** an integration script or API poller shipping IRIS case data to the manager (see the SOCFortress blog for the companion walkthrough).
