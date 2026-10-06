# Threat Intel (IOC lists)

Indicator matching against free, reputable threat-intel feeds, using Wazuh CDB lists. A GitHub Action refreshes the lists every Monday. No API keys or external lookups are needed at alert time.

| File | Purpose |
|---|---|
| `151000-threat_intel_iocs.xml` | Rules 151000–151011 |
| `lists/` | Generated CDB lists plus `SOURCES.md` (provenance, counts, licences) |
| `allowlist.txt` | Domains, IPs, hashes or CVEs you never want listed. A domain also covers its subdomains. |

## Feeds

| List | Built from | Used by |
|---|---|---|
| `abusech-c2-ip` | [Feodo Tracker](https://feodotracker.abuse.ch/) (recommended), [SSLBL](https://sslbl.abuse.ch/), [ThreatFox](https://threatfox.abuse.ch/) `ip:port`, [URLhaus](https://urlhaus.abuse.ch/) payload hosts | 151000, 151003, 151007 |
| `abusech-malicious-domain` | ThreatFox domains, URLhaus payload hosts | 151002, 151004–151006 |
| `abusech-malware-sha256` | ThreatFox SHA256, [MalwareBazaar](https://bazaar.abuse.ch/) recent samples | 151009 |
| `spamhaus-drop` | [Spamhaus DROP](https://www.spamhaus.org/drop/) (as `a.b.c.` address prefixes) | 151001, 151008 |
| `cisa-kev-cve` | [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (value: known ransomware use) | 151010, 151011 |

Noise controls applied by [`tools/update_threat_intel.py`](../tools/update_threat_intel.py):

- ThreatFox IOCs need confidence ≥ 75 and must have been first seen in the last 90 days.
- Compromised legitimate domains are skipped.
- Domains that are, or sit under, a Tranco top-20,000 site are dropped, so abused platforms like `github.com` or `drive.google.com` never become IOCs.
- Private IPs are removed.

## Rules

| Rule | Level | Fires when | Telemetry |
|---|---|---|---|
| 151000 | 12 | A process connects to a C2 or malware-hosting IP | Sysmon event 3 |
| 151001 | 10 | A process connects to a Spamhaus DROP netblock | Sysmon event 3 |
| 151002 | 12 | A process resolves a malicious domain | Sysmon event 22 |
| 151003 | 12 | Traffic to a C2 IP (flow, dns, tls or http event) | Suricata EVE (child of `Suricata/100002`) |
| 151004–151006 | 12 | DNS query, TLS SNI or HTTP host matches a malicious domain | Suricata EVE |
| 151007 / 151008 | 12 / 10 | Firewall logs show a connection to a C2 IP / DROP netblock | Any decoder that sets `dstip` and the `firewall` group |
| 151009 | 13 | FIM sees a new or changed file whose SHA256 is known malware | Wazuh syscheck (FIM) |
| 151010 | 13 | Vulnerability detection finds a CISA KEV CVE on an agent | Wazuh 4.8+ vulnerability detection (23503–23506) |
| 151011 | 14 | …and that CVE is used in ransomware campaigns | Same |

The Suricata rules expect the Suricata 6/7 EVE field names (`dest_ip`, `dns.rrname`, `tls.sni`, `http.hostname`).

## Install

The bulk installer (`wazuh_socfortress_rules.sh`) copies and registers the lists automatically. To install by hand:

```bash
cp "Threat Intel/151000-threat_intel_iocs.xml" /var/ossec/etc/rules/
cp "Threat Intel/lists/"abusech-* "Threat Intel/lists/"spamhaus-drop "Threat Intel/lists/"cisa-kev-cve /var/ossec/etc/lists/
chown wazuh:wazuh /var/ossec/etc/lists/*
```

Then register each list inside `<ruleset>` in `/var/ossec/etc/ossec.conf`:

```xml
<list>etc/lists/abusech-c2-ip</list>
<list>etc/lists/abusech-malicious-domain</list>
<list>etc/lists/abusech-malware-sha256</list>
<list>etc/lists/spamhaus-drop</list>
<list>etc/lists/cisa-kev-cve</list>
```

Restart the manager to compile the lists. To keep them current, re-run the installer or `git pull` and copy `lists/` on a schedule. The repo copy changes weekly.

## Refreshing manually

```bash
python tools/update_threat_intel.py            # --days 90 --tranco-top 20000 by default
python tools/validate_rules.py
```

The script is deterministic and only rewrites a list when its contents change. If a feed is unreachable, that feed's previous entries are kept and the failure is recorded in `lists/SOURCES.md`.

## Triage tip

Wazuh doesn't copy a list entry's value into the alert. To see which malware family or report an indicator belongs to, look it up in the list file (value: `source/threat_type/malware`) or search for it on ThreatFox or URLhaus.

## Licences

The abuse.ch data is CC0. CISA KEV is US public domain. Spamhaus DROP is free to use under [Spamhaus's terms](https://www.spamhaus.org/drop/). The Tranco list is used only for filtering and isn't redistributed.
