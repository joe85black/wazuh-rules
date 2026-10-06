#!/usr/bin/env python3
"""Re-anchor the Windows_Sysmon MITRE rules on technique IDs.

The rules in Windows_Sysmon/ chain off Sysmon's RuleName field, which the
sysmon-modular config fills with "technique_id=<ID>,technique_name=<name>".
Matching the whole string breaks whenever ATT&CK renames, revokes or
deprecates a technique. This script:

  1. leaves a ruleName pattern untouched if it still matches a rule name the
     pinned sysmon-modular config emits ("live");
  2. if the pattern matches a name sysmon-modular emitted at some point in its
     history (tools/sysmon_modular_rule_names.json) but no longer does, maps
     the technique ID to its current ATT&CK ID (revoked-by relationships plus a
     small manual map for deprecated IDs) and rewrites the pattern to
     "^technique_id=<ID>," so it keys on the ID only ("reanchored");
  3. leaves every other pattern alone: those rules were written for a
     different, non-public Sysmon config and are kept as-is ("custom");
  4. fixes RuleName -> ruleName casing and remaps revoked <mitre><id> values;
  5. drops a re-anchored rule only if it became redundant (same parent and
     conditions as another rule for the same technique) AND nothing references
     it;
  6. writes Windows_Sysmon/COVERAGE.md comparing the rules with the config.

Re-run it after bumping SYSMON_CONFIG_TAG or refreshing ATT&CK data:

    python tools/refresh_reference_data.py --skip-wazuh
    python tools/reanchor_sysmon.py            # add --dry-run to preview
"""
import argparse
import json
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
SYSMON_DIR = ROOT / "Windows_Sysmon"

# Keep in sync with Windows_Sysmon/sysmon_install.ps1.
SYSMON_CONFIG_TAG = "configs-082cba578667"
SYSMON_CONFIG_URL = f"https://github.com/olafhartong/sysmon-modular/releases/download/{SYSMON_CONFIG_TAG}/sysmonconfig.xml"

# Deprecated (not revoked) techniques have no replaced_by in ATT&CK; these are
# the closest current techniques. Malformed IDs found in the repo are fixed too.
MANUAL_MAP = {
    "T1064": "T1059",       # Scripting -> Command and Scripting Interpreter
    "T1043": "T1071",       # Commonly Used Port -> Application Layer Protocol
    "T1175": "T1559.001",   # Component Object Model and DCOM -> IPC: COM
    "T047": "T1047",        # typo for Windows Management Instrumentation
    "T0137": "T1037.005",   # typo for Boot or Logon Initialization Scripts: Startup Items
}

# Sysmon config element that produces each rule file's events.
FILE_EVENT = {
    "EVENT1": "ProcessCreate", "EVENT2": "FileCreateTime", "EVENT3": "NetworkConnect",
    "EVENT6": "DriverLoad", "EVENT7": "ImageLoad", "EVENT10": "ProcessAccess",
    "EVENT11": "FileCreate", "EVENT12": "RegistryEvent", "EVENT13": "RegistryEvent",
    "EVENT14": "RegistryEvent", "EVENT15": "FileCreateStreamHash", "EVENT17": "PipeEvent",
    "EVENT18": "PipeEvent", "EVENT22": "DnsQuery",
}

RULE_RE = re.compile(r'(?P<lead>[ \t]*(?:<!--[^\n]*-->\r?\n[ \t]*)?)(?P<rule><rule id="(?P<id>\d+)"[^>]*>.*?</rule>)(?P<trail>[ \t]*\r?\n)?', re.S)
RULENAME_RE = re.compile(r'<field name="win\.eventdata\.(?:RuleName|ruleName)"(?P<attrs>[^>]*)>(?P<pat>[^<]*)</field>')
TECH_RE = re.compile(r"(?:technique_id=)?T?(?P<num>0?\d{3,4}(?:\\?\.\d{3})?)")


def load_attack():
    return json.loads((HERE / "attack_techniques.json").read_text(encoding="utf-8"))["techniques"]


def current_id(tid, techniques):
    """Follow revocations/deprecations until an active technique is reached."""
    seen = set()
    while tid not in seen:
        seen.add(tid)
        if tid in MANUAL_MAP:
            tid = MANUAL_MAP[tid]
            continue
        tech = techniques.get(tid)
        if tech is None or tech["status"] == "active":
            return tid
        if tech.get("replaced_by"):
            tid = tech["replaced_by"]
            continue
        return tid
    return tid


def fetch_config(cache):
    cache.parent.mkdir(parents=True, exist_ok=True)
    if not cache.exists():
        req = urllib.request.Request(SYSMON_CONFIG_URL, headers={"User-Agent": "wazuh-rules-tooling"})
        with urllib.request.urlopen(req, timeout=120) as resp:
            cache.write_bytes(resp.read())
    return cache.read_text(encoding="utf-8")


def emitted_names(config):
    """Rule names per Sysmon event element in the config (include rules only)."""
    names = defaultdict(set)
    for event in set(FILE_EVENT.values()):
        for block in re.findall(rf'<{event}\b[^>]*onmatch="include"[^>]*>(.*?)</{event}>', config, re.S):
            names[event].update(re.findall(r'name="(technique_id=[^"]*)"', block))
    return names


OS_REGEX_CLASSES = {
    "w": r"[A-Za-z0-9\-@_]", "d": r"\d", "s": " ", "t": r"\t", "p": r"[()*+,\-.:;<=>?\[\]!\"'#$%&|{}]",
    "W": r"[^A-Za-z0-9\-@_]", "D": r"\D", "S": r"[^ ]", ".": ".",
}


def os_regex_to_python(pattern):
    """Translate Wazuh's OS_Regex syntax (the default for <field>) to Python re."""
    out, i = [], 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern):
            nxt = pattern[i + 1]
            out.append(OS_REGEX_CLASSES.get(nxt, re.escape(nxt)))
            i += 2
            continue
        out.append(ch if ch in "^$|()+*" else re.escape(ch))
        i += 1
    return "".join(out)


def os_regex_matches(pattern, value):
    try:
        return re.search(os_regex_to_python(pattern.strip()), value) is not None
    except re.error:
        return False


def referenced_ids():
    refs = set()
    for path in ROOT.rglob("*.xml"):
        text = path.read_text(encoding="utf-8-sig")
        for tag in ("if_sid", "if_matched_sid"):
            for value in re.findall(rf"<{tag}>([^<]*)</{tag}>", text):
                refs.update(int(v) for v in re.split(r"[,\s]+", value) if v.strip().isdigit())
    return refs


def condition_key(rule_xml):
    """Everything that decides whether a rule matches (not how it reports)."""
    el = ET.fromstring(rule_xml)
    parts = []
    for child in el:
        if child.tag in ("description", "mitre", "options", "group", "info"):
            continue
        parts.append((child.tag, tuple(sorted(child.attrib.items())), (child.text or "").strip()))
    return tuple(sorted(parts))


def rule_level(rule_xml):
    return int(re.search(r'level="(\d+)"', rule_xml).group(1))


def file_event(path):
    m = re.search(r"SYSMON_(EVENT\d+)", path.name)
    return FILE_EVENT.get(m.group(1)) if m else None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    techniques = load_attack()
    config = fetch_config(HERE / ".cache" / f"sysmonconfig-{SYSMON_CONFIG_TAG}.xml")
    emitted = emitted_names(config)
    history = set(json.loads((HERE / "sysmon_modular_rule_names.json").read_text(encoding="utf-8"))["names"])
    refs = referenced_ids()

    stats = defaultdict(int)
    dropped, coverage = [], {}

    for path in sorted(SYSMON_DIR.glob("*MITRE_TECHNIQUES_FROM_SYSMON_EVENT*.xml")):
        event = file_event(path)
        names = emitted.get(event, set())
        with open(path, encoding="utf-8", newline="") as fh:
            text = fh.read()

        rewritten = {}  # rule id -> new rule xml
        info = {}       # rule id -> (class, technique id, base key)
        originals = {}  # rule id -> rule xml with only the casing fix
        for m in RULE_RE.finditer(text):
            rid, rule = m.group("id"), m.group("rule")
            new_rule = rule.replace('name="win.eventdata.RuleName"', 'name="win.eventdata.ruleName"')
            fm = RULENAME_RE.search(new_rule)
            if not fm:
                rewritten[rid] = new_rule
                continue
            stats["rulename_conditions"] += 1
            pat = fm.group("pat")
            tm = TECH_RE.search(pat)
            old_tid = "T" + tm.group("num").replace("\\", "") if tm else None
            new_tid = current_id(old_tid, techniques) if old_tid else None
            if any(os_regex_matches(pat, n) for n in names):
                cls = "live"
            elif old_tid and any(os_regex_matches(pat, n) for n in history):
                cls = "reanchored"
                new_rule = new_rule.replace(fm.group(0), f'<field name="win.eventdata.ruleName"{fm.group("attrs")}>^technique_id={new_tid},</field>')
                if new_tid != old_tid:
                    stats["id_remapped"] += 1
            else:
                cls = "custom"  # written for a different (non-public) Sysmon config; keep as-is
            stats[cls] += 1
            originals[rid] = rule.replace('name="win.eventdata.RuleName"', 'name="win.eventdata.ruleName"')
            if new_tid in techniques:
                new_rule = re.sub(r"(<mitre>\s*<id>)[^<]*(</id>)", rf"\g<1>{new_tid}\g<2>", new_rule, count=1)
            base = condition_key(RULENAME_RE.sub("", new_rule))
            info[rid] = (cls, new_tid, base)
            rewritten[rid] = new_rule

        # A re-anchored rule is redundant when, under the same parent and other
        # conditions, an earlier re-anchored rule has the same technique, or
        # live rules already match every name the config emits for it.
        drop, seen = set(), {}
        for rid, (cls, tid, base) in info.items():
            if cls != "reanchored":
                continue
            reason, coverers = None, []
            cfg = [n for n in names if n.startswith(f"technique_id={tid},")]
            # live siblings that match at least one config name for this technique
            live = [o for o, (c, t, b) in info.items() if c == "live" and b == base and o != rid
                    and any(os_regex_matches(RULENAME_RE.search(rewritten[o]).group("pat"), n) for n in cfg)]
            live_pats = [RULENAME_RE.search(rewritten[o]).group("pat") for o in live]
            if (base, tid) in seen:
                reason = "same technique as an earlier re-anchored rule"
                coverers = [seen[(base, tid)]] + live
            elif cfg and all(any(os_regex_matches(p, n) for p in live_pats) for n in cfg):
                reason = "already covered by a live rule"
                coverers = live
            else:
                seen[(base, tid)] = rid
            if not reason or int(rid) in refs:
                continue
            cover_levels = [rule_level(rewritten[o]) for o in coverers]
            if rule_level(rewritten[rid]) > max(cover_levels):
                # Upstream tuned this one higher than whatever covers it; keep
                # its original pattern rather than silently lowering severity.
                rewritten[rid] = re.sub(r"<id>(T[0-9.]+)</id>", lambda x: f"<id>{current_id(x.group(1), techniques)}</id>", originals[rid])
                info[rid] = ("custom", tid, base)
                stats["reanchored"] -= 1
                stats["kept_higher_level"] += 1
                continue
            drop.add(rid)
            dropped.append((path.name, rid, tid, reason))

        def substitute(m):
            rid = m.group("id")
            if rid in drop:
                return ""
            return m.group("lead") + rewritten.get(rid, m.group("rule")) + (m.group("trail") or "")

        new_text = RULE_RE.sub(substitute, text)
        # Any remaining revoked/deprecated MITRE IDs (catch-all and custom rules).
        new_text = re.sub(r"<id>(T[0-9.]+)</id>", lambda x: f"<id>{current_id(x.group(1), techniques)}</id>", new_text)

        pats = [fm.group("pat") for fm in RULENAME_RE.finditer(new_text)]
        state = defaultdict(int)
        for p in pats:
            if any(os_regex_matches(p, n) for n in names):
                state["live"] += 1
            elif any(os_regex_matches(p, n) for n in history):
                state["other"] += 1
            else:
                state["custom"] += 1
        cfg_ids = {m.group(1) for m in (re.match(r"technique_id=(T[0-9.]+),", n) for n in names) if m}
        uncovered = sorted(i for i in cfg_ids if not any(
            os_regex_matches(p, n) for p in pats for n in names if n.startswith(f"technique_id={i},")))
        coverage[path.name] = {"event": event, **state, "uncovered": uncovered}
        if new_text != text and not args.dry_run:
            with open(path, "w", encoding="utf-8", newline="") as fh:
                fh.write(new_text)

    stats["dropped_redundant"] = len(dropped)
    for k, v in sorted(stats.items()):
        print(f"{k:22} {v}")
    for name, rid, tid, why in dropped:
        print(f"  dropped {name} rule {rid} ({tid}): {why}")

    if not args.dry_run:
        write_coverage(coverage, stats)
    return 0


def write_coverage(coverage, stats):
    def total(key):
        return sum(c.get(key, 0) for c in coverage.values())

    tag_url = f"https://github.com/olafhartong/sysmon-modular/releases/tag/{SYSMON_CONFIG_TAG}"
    lines = [
        "# Windows_Sysmon coverage",
        "",
        "Generated by `tools/reanchor_sysmon.py`. Do not edit by hand.",
        "",
        "The rules in this folder match the `RuleName` that Sysmon writes into each event. "
        "This report compares them with the config pinned in `sysmon_install.ps1`: "
        f"sysmon-modular release [`{SYSMON_CONFIG_TAG}`]({tag_url}), Sysmon 15.21 profile.",
        "",
        "## Summary",
        "",
        f"- **{total('live')}** `ruleName` conditions match a rule name the pinned config emits.",
        f"- **{total('other')}** conditions use sysmon-modular technique IDs that the pinned config doesn't tag for that event type. "
        "They fire again if a future config does.",
        f"- **{total('custom')}** conditions match descriptive names such as `Rubeus Pass-the-Ticket` that no public config emits. "
        "They come from SOCFortress's own Sysmon config and are kept unchanged. **With the sysmon-modular config they never fire.** "
        "Use a config that emits those names if you want them.",
        "",
        "Rules written for older sysmon-modular rule names are re-keyed on the technique ID (`^technique_id=<ID>,`), "
        "with revoked or deprecated ATT&CK IDs mapped to their current replacements. Re-run `tools/reanchor_sysmon.py` after bumping the "
        "pinned config or refreshing `tools/attack_techniques.json`.",
        "",
        "## Per file",
        "",
        "| Rule file | Sysmon event | Matching pinned config | Custom-config names | Other non-matching | Config technique IDs with no dedicated rule |",
        "|---|---|---|---|---|---|",
    ]
    for name, c in coverage.items():
        unc = ", ".join(c["uncovered"]) or "none"
        lines.append(f"| `{name}` | {c['event']} | {c.get('live', 0)} | {c.get('custom', 0)} | {c.get('other', 0)} | {unc} |")
    lines += [
        "",
        "Events whose technique has no dedicated rule still alert through the event's catch-all rule, "
        "but without a specific MITRE mapping.",
        "",
    ]
    (SYSMON_DIR / "COVERAGE.md").write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
