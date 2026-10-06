#!/usr/bin/env python3
"""Build Wazuh CDB lists from free, reputable threat-intel feeds.

Output goes to "Threat Intel/lists/" as plain `key:value` CDB source files.
The Wazuh manager compiles them at start-up; rules in
"Threat Intel/151000-threat_intel_iocs.xml" look them up.

  abusech-c2-ip          Feodo Tracker (recommended), SSLBL botnet C2 IPs,
                         ThreatFox ip:port IOCs, URLhaus payload hosts (IPs)
  abusech-malicious-domain
                         ThreatFox domains and URLhaus payload hosts
  abusech-malware-sha256 ThreatFox SHA256 IOCs and MalwareBazaar recent samples
  spamhaus-drop          Spamhaus DROP netblocks as Wazuh address prefixes
  cisa-kev-cve           CISA Known Exploited Vulnerabilities (value = known
                         ransomware use: Known / Unknown)

Noise control:
  * ThreatFox IOCs need confidence >= 75 and first_seen within --days (90).
  * Compromised-but-legitimate domains (ThreatFox is_compromised) are skipped.
  * Domains that are, or sit under, a Tranco top-N site are dropped, so abused
    platforms (github.com, drive.google.com, ...) never become IOCs.
  * Private/reserved IPs are dropped. "Threat Intel/allowlist.txt" removes
    anything else you never want listed.

If a feed can't be fetched, its previous entries are kept and the run
reports a warning. The script exits non-zero only if every feed fails.
Output is sorted and deterministic, so files change only when data changes.

    python tools/update_threat_intel.py [--days 90] [--tranco-top 20000]
"""
import argparse
import csv
import datetime as dt
import io
import ipaddress
import json
import re
import sys
import urllib.request
import zipfile
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TI_DIR = ROOT / "Threat Intel"
LIST_DIR = TI_DIR / "lists"
ALLOWLIST = TI_DIR / "allowlist.txt"

FEEDS = {
    "feodo": "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.txt",
    "sslbl": "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
    "threatfox": "https://threatfox.abuse.ch/export/json/full/",
    "urlhaus": "https://urlhaus.abuse.ch/downloads/text_online/",
    "malwarebazaar": "https://bazaar.abuse.ch/export/txt/sha256/recent/",
    "spamhaus_drop": "https://www.spamhaus.org/drop/drop_v4.json",
    "cisa_kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "tranco": "https://tranco-list.eu/top-1m.csv.zip",
}

LISTS = {
    "abusech-c2-ip": "Botnet C2 and malware-hosting IPv4 addresses",
    "abusech-malicious-domain": "Malware C2, payload and phishing-kit domains",
    "abusech-malware-sha256": "SHA256 hashes of recent malware samples",
    "spamhaus-drop": "Hijacked / criminal-operated netblocks (address prefixes)",
    "cisa-kev-cve": "CVEs known to be exploited in the wild",
}

LICENCES = {
    "feodo": "abuse.ch Feodo Tracker, CC0",
    "sslbl": "abuse.ch SSLBL, CC0",
    "threatfox": "abuse.ch ThreatFox, CC0",
    "urlhaus": "abuse.ch URLhaus, CC0",
    "malwarebazaar": "abuse.ch MalwareBazaar, CC0",
    "spamhaus_drop": "Spamhaus DROP, free to use (https://www.spamhaus.org/drop/)",
    "cisa_kev": "CISA KEV catalog, US public domain",
    "tranco": "Tranco list (filtering only, not redistributed)",
}

DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$")


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "wazuh-rules threat-intel updater"})
    with urllib.request.urlopen(req, timeout=180) as resp:
        return resp.read()


def clean_value(text):
    """CDB values must not contain ':' and should stay readable."""
    return re.sub(r"[^A-Za-z0-9._/+=-]+", "_", str(text or "unknown")).strip("_")[:120] or "unknown"


def public_ipv4(value):
    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        return None
    if ip.version != 4 or not ip.is_global:
        return None
    return str(ip)


def lines(raw):
    for line in raw.decode("utf-8", "replace").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            yield line


def load_allowlist():
    if not ALLOWLIST.exists():
        return set()
    return {l.strip().lower() for l in ALLOWLIST.read_text(encoding="utf-8").splitlines()
            if l.strip() and not l.strip().startswith("#")}


def read_existing(name):
    path = LIST_DIR / name
    out = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            key, _, value = line.partition(":")
            out[key] = value
    return out


class Collector:
    def __init__(self):
        self.data = defaultdict(lambda: defaultdict(set))  # list -> key -> {tags}
        self.ok, self.failed = [], []

    def add(self, list_name, key, tag):
        self.data[list_name][key].add(clean_value(tag))


def parse_feeds(args, col, allow):
    since = (dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=args.days)).strftime("%Y-%m-%d")

    def run(name, fn):
        try:
            fn(fetch(FEEDS[name]))
            col.ok.append(name)
        except Exception as exc:  # keep going; previous data is preserved below
            col.failed.append(f"{name}: {exc}")

    def feodo(raw):
        for line in lines(raw):
            ip = public_ipv4(line.split(",")[0])
            if ip:
                col.add("abusech-c2-ip", ip, "feodo/botnet_cc")

    def sslbl(raw):
        for row in csv.reader(lines(raw)):
            ip = public_ipv4(row[1] if len(row) > 1 else row[0])
            if ip:
                col.add("abusech-c2-ip", ip, "sslbl/botnet_cc")

    def threatfox(raw):
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            data = json.loads(zf.read(zf.namelist()[0]))
        for entries in data.values():
            for ioc in entries:
                if (ioc.get("confidence_level") or 0) < 75 or (ioc.get("first_seen_utc") or "") < since:
                    continue
                tag = f"threatfox/{ioc.get('threat_type')}/{ioc.get('malware_printable')}"
                value, kind = (ioc.get("ioc_value") or "").strip().lower(), ioc.get("ioc_type")
                if kind == "ip:port":
                    ip = public_ipv4(value.rsplit(":", 1)[0])
                    if ip:
                        col.add("abusech-c2-ip", ip, tag)
                elif kind == "domain" and not ioc.get("is_compromised"):
                    col.add("abusech-malicious-domain", value.rstrip("."), tag)
                elif kind == "sha256_hash" and SHA256_RE.match(value):
                    col.add("abusech-malware-sha256", value, tag)

    def urlhaus(raw):
        for url in lines(raw):
            m = re.match(r"^[a-z][a-z0-9+.-]*://([^/:?#]+)", url, re.I)
            if not m:
                continue
            host = m.group(1).lower().rstrip(".")
            ip = public_ipv4(host)
            if ip:
                col.add("abusech-c2-ip", ip, "urlhaus/payload_delivery")
            elif DOMAIN_RE.match(host):
                col.add("abusech-malicious-domain", host, "urlhaus/payload_delivery")

    def malwarebazaar(raw):
        for line in lines(raw):
            h = line.strip('" ').lower()
            if SHA256_RE.match(h):
                col.add("abusech-malware-sha256", h, "malwarebazaar/recent")

    def spamhaus_drop(raw):
        for line in raw.decode("utf-8", "replace").splitlines():
            if '"cidr"' not in line:
                continue
            row = json.loads(line)
            for key in cidr_to_prefixes(row["cidr"]):
                col.add("spamhaus-drop", key, f"spamhaus/{row.get('sblid', 'drop')}")

    def cisa_kev(raw):
        for vuln in json.loads(raw)["vulnerabilities"]:
            cve = vuln.get("cveID", "").strip().upper()
            if CVE_RE.match(cve):
                use = "Known" if vuln.get("knownRansomwareCampaignUse") == "Known" else "Unknown"
                col.add("cisa-kev-cve", cve, use)

    for name, fn in [("feodo", feodo), ("sslbl", sslbl), ("threatfox", threatfox), ("urlhaus", urlhaus),
                     ("malwarebazaar", malwarebazaar), ("spamhaus_drop", spamhaus_drop), ("cisa_kev", cisa_kev)]:
        run(name, fn)

    # Drop popular sites (and anything under them) from the domain list.
    popular = set()
    try:
        with zipfile.ZipFile(io.BytesIO(fetch(FEEDS["tranco"]))) as zf:
            reader = csv.reader(io.TextIOWrapper(zf.open(zf.namelist()[0]), encoding="utf-8"))
            for rank, row in enumerate(reader):
                if rank >= args.tranco_top:
                    break
                popular.add(row[1].strip().lower())
        col.ok.append("tranco")
    except Exception as exc:
        col.failed.append(f"tranco: {exc}")

    domains = col.data["abusech-malicious-domain"]
    for domain in list(domains):
        labels = domain.split(".")
        suffixes = {".".join(labels[i:]) for i in range(len(labels) - 1)}
        if suffixes & (popular | allow):
            del domains[domain]
    for list_name in col.data:
        for key in list(col.data[list_name]):
            if key.lower() in allow:
                del col.data[list_name][key]


def cidr_to_prefixes(cidr):
    """Express an IPv4 network as Wazuh address_match_key keys ("a.", "a.b.", "a.b.c." or full IPs)."""
    net = ipaddress.ip_network(cidr, strict=False)
    if net.version != 4:
        return []
    for boundary in (8, 16, 24, 32):
        if net.prefixlen <= boundary:
            break
    octets = boundary // 8
    keys = []
    for sub in net.subnets(new_prefix=boundary) if net.prefixlen < boundary else [net]:
        parts = str(sub.network_address).split(".")[:octets]
        keys.append(".".join(parts) + ("." if octets < 4 else ""))
    return keys


def write_lists(col):
    changed = []
    LIST_DIR.mkdir(parents=True, exist_ok=True)
    source_of = {
        "abusech-c2-ip": {"feodo", "sslbl", "threatfox", "urlhaus"},
        "abusech-malicious-domain": {"threatfox", "urlhaus"},
        "abusech-malware-sha256": {"threatfox", "malwarebazaar"},
        "spamhaus-drop": {"spamhaus_drop"},
        "cisa-kev-cve": {"cisa_kev"},
    }
    failed = {f.split(":")[0] for f in col.failed}
    counts = {}
    for name in LISTS:
        entries = {k: "+".join(sorted(v)) for k, v in col.data[name].items()}
        if source_of[name] & failed:
            # A source is down: keep its previous entries rather than dropping them.
            for key, value in read_existing(name).items():
                entries.setdefault(key, value)
        text = "".join(f"{k}:{entries[k]}\n" for k in sorted(entries))
        path = LIST_DIR / name
        counts[name] = len(entries)
        if not path.exists() or path.read_text(encoding="utf-8") != text:
            path.write_text(text, encoding="utf-8", newline="\n")
            changed.append(name)
    return changed, counts


def write_sources(counts, col, args):
    now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rows = "\n".join(f"| `{n}` | {LISTS[n]} | {counts[n]:,} |" for n in LISTS)
    feeds = "\n".join(f"- [{LICENCES[k]}]({FEEDS[k]})" for k in FEEDS)
    warn = ""
    if col.failed:
        warn = "\n**Feeds that failed on the last run (previous entries kept):**\n\n" + "\n".join(f"- {f}" for f in col.failed) + "\n"
    (LIST_DIR / "SOURCES.md").write_text(f"""# Threat-intel list provenance

Generated by `tools/update_threat_intel.py` on **{now}**. Do not edit the lists by hand; add exceptions to `../allowlist.txt` instead.

| List | Contents | Entries |
|---|---|---|
{rows}

## Feeds and licences

{feeds}

## Filters applied

- ThreatFox: confidence of at least 75 and first seen in the last {args.days} days. Compromised legitimate domains are skipped.
- Domains: anything that is, or sits under, a Tranco top-{args.tranco_top:,} site is removed.
- IPs: IPv4 only. Private and reserved ranges are removed.
- `../allowlist.txt` entries are removed from every list.
{warn}""", encoding="utf-8", newline="\n")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--days", type=int, default=90, help="ThreatFox look-back window (default 90)")
    ap.add_argument("--tranco-top", type=int, default=20000, help="popular-domain filter size (default 20000)")
    args = ap.parse_args()

    col = Collector()
    parse_feeds(args, col, load_allowlist())
    if not col.ok or col.ok == ["tranco"]:
        print("every feed failed:\n  " + "\n  ".join(col.failed), file=sys.stderr)
        return 1
    changed, counts = write_lists(col)
    if changed or not (LIST_DIR / "SOURCES.md").exists():
        write_sources(counts, col, args)
    for name in LISTS:
        print(f"{name:26} {counts[name]:>7}{'  (updated)' if name in changed else ''}")
    for failure in col.failed:
        print(f"WARNING feed failed, previous data kept: {failure}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
