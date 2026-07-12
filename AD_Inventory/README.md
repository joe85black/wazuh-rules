# AD Inventory

Collects an Active Directory inventory (users, computers, group membership) with a scheduled PowerShell script and ingests the results into Wazuh so directory changes become searchable, alertable events.

| File | Purpose |
|---|---|
| `ad_inventory.ps1` | Runs on a domain-joined host, queries AD, and writes JSON results into the agent's active-response log for pickup |
| `201010-ad_inventory.xml` | Rules (group `ad_inventory` / `ad_integration`) that index the collection results — rule IDs 201010+ |

**Deploy:** schedule `ad_inventory.ps1` (Task Scheduler, e.g. daily) on a host with RSAT/AD module, copy the XML to `/var/ossec/etc/rules/` on the manager, restart the manager.
