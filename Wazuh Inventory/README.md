# Wazuh Inventory

Rules that index Wazuh **agent inventory collection** (syscollector: OS, hardware, network interfaces, ports) as searchable events — the foundation for asset dashboards in the indexer.

| File | Purpose |
|---|---|
| `200900-wazuh_inventory.xml` | Rules (group `wazuh_inventory`) indexing inventory collection results — rule IDs 200900+ |

**Prerequisite:** syscollector enabled on agents (default); typically paired with a poller that pulls inventory from the Wazuh API. See also the [`Software`](../Software) and [`AD_Inventory`](../AD_Inventory) folders.
