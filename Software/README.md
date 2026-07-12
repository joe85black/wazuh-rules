# Software

Rules that index Wazuh agent **software inventory scan results** (syscollector packages) as searchable events — know what's installed where, and when it changed.

| File | Purpose |
|---|---|
| `201015-software.xml` | Rules (group `wazuh_software`) indexing software scan results — rule IDs 201015+ |

**Prerequisite:** syscollector enabled on agents (default); typically paired with a poller that pulls package inventory from the Wazuh API.
