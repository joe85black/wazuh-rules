# SOCFortress API (Threat Intel Enrichment)

Rules for the [SOCFortress threat-intel API integration](https://github.com/socfortress) — alerts are enriched by looking up observables (hashes, domains, IPs) against the SOCFortress IoC database; matches raise dedicated alerts.

| File | Purpose |
|---|---|
| `200980-socfortress.xml` | Rules (group `socfortress`) — "IoC matched" alerts with the API's verdict message, plus a quiet no-match rule — rule IDs 200980+ |

**Prerequisite:** the SOCFortress `custom-socfortress` integration script configured in `ossec.conf` with an API key.
