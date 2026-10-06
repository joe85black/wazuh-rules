#!/usr/bin/env python3
"""Static validation for every Wazuh rule file in this repository.

Checks (errors fail the run, warnings are reported only):
  error   XML is well-formed (each file is wrapped in a dummy root first)
  error   rule IDs are unique across the repo
  error   IDs below 100000 that collide with a Wazuh built-in carry overwrite="yes"
  error   level is 0-16 and every rule has a description
  error   if_sid / if_matched_sid parents exist in the repo or in Wazuh's ruleset
  error   if_group / if_matched_group groups exist in the repo or in Wazuh's ruleset
  error   <mitre><id> values are current ATT&CK Enterprise techniques
  error   win.eventdata / win.system field names use Wazuh's camelCase
  error   <list> references point to a list shipped in the repo or a Wazuh default list
  error   outer <group name="..."> values end with a comma
  warning pcre2 patterns that Python's regex engine cannot compile (best effort)

Reference data comes from tools/wazuh_builtin_ruleset.json and
tools/attack_techniques.json (regenerate with tools/refresh_reference_data.py).

Usage: python tools/validate_rules.py [--quiet]
"""
import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent

# Lists that ship with a default Wazuh manager install (etc/lists/...).
WAZUH_DEFAULT_LISTS = {
    "audit-keys",
    "amazon/aws-eventnames",
    "security-eventchannel",
    "malicious-ioc/malware-hashes",
    "malicious-ioc/malicious-ip",
    "malicious-ioc/malicious-domains",
}
CAMEL_CASE_FIELD = re.compile(r"^win\.(eventdata|system)\.[A-Z]")


class Report:
    def __init__(self):
        self.errors = []
        self.warnings = []

    def error(self, where, msg):
        self.errors.append(f"{where}: {msg}")

    def warn(self, where, msg):
        self.warnings.append(f"{where}: {msg}")


def load_reference():
    wazuh = json.loads((HERE / "wazuh_builtin_ruleset.json").read_text(encoding="utf-8"))
    attack = json.loads((HERE / "attack_techniques.json").read_text(encoding="utf-8"))
    return set(wazuh["rule_ids"]), set(wazuh["groups"]), attack["techniques"], wazuh["wazuh_tag"]


def rule_files():
    for path in sorted(ROOT.rglob("*.xml")):
        rel = path.relative_to(ROOT)
        if any(part.startswith(".") for part in rel.parts):
            continue
        yield path, rel.as_posix()


def parse(path, rel, report):
    text = path.read_text(encoding="utf-8-sig")
    body = re.sub(r"<\?xml[^>]*\?>", "", text)
    try:
        return ET.fromstring(f"<root>{body}</root>")
    except ET.ParseError as exc:
        report.error(rel, f"XML parse error: {exc}")
        return None


def split_tokens(value):
    return [t.strip() for t in re.split(r"[,\s]+", value or "") if t.strip()]


def python_compatible(pattern):
    """PCRE2 accepts inline flags such as (?i) mid-pattern; Python only at the start."""
    flags = set()

    def strip(match):
        flags.update(match.group(1))
        return ""

    body = re.sub(r"\(\?([imsx]+)\)", strip, pattern)
    return (f"(?{''.join(sorted(flags))})" if flags else "") + body


def shipped_lists():
    """Every extensionless file referenced as a CDB list must exist somewhere in the repo."""
    names = set()
    for path in ROOT.rglob("*"):
        if path.is_file() and not path.suffix and ".git" not in path.parts:
            names.add(path.name)
    return names


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--quiet", action="store_true", help="only print errors and the summary")
    args = ap.parse_args()

    builtin_ids, builtin_groups, techniques, wazuh_tag = load_reference()
    report = Report()
    rules = []  # (rel, rule_element, outer_group_name)
    repo_groups = set()
    file_count = 0

    for path, rel in rule_files():
        root = parse(path, rel, report)
        if root is None:
            continue
        if root.find("decoder") is not None and root.find(".//rule") is None:
            continue  # decoder-only file
        file_count += 1
        for group in root.iter("group"):
            name = group.get("name")
            if name is None:
                continue  # inner <group> text element
            if name and not name.endswith(","):
                report.error(rel, f'group name="{name}" must end with a comma (Wazuh concatenates it with inner groups)')
            repo_groups.update(split_tokens(name))
            for rule in group.findall("rule"):
                rules.append((rel, rule, name))
                for inner in rule.findall("group"):
                    repo_groups.update(split_tokens(inner.text))

    known_groups = builtin_groups | repo_groups
    lists_in_repo = shipped_lists()
    ids = defaultdict(list)
    for rel, rule, _ in rules:
        rid = rule.get("id", "")
        if not rid.isdigit():
            report.error(rel, f"rule with non-numeric id {rid!r}")
            continue
        ids[int(rid)].append((rel, rule))

    repo_ids = set(ids)
    for rid, defs in sorted(ids.items()):
        if len(defs) > 1:
            report.error(", ".join(d[0] for d in defs), f"rule id {rid} defined {len(defs)} times")
        for rel, rule in defs:
            where = f"{rel} rule {rid}"
            if rid in builtin_ids and rule.get("overwrite") != "yes":
                report.error(where, f"collides with Wazuh {wazuh_tag} built-in rule; add overwrite=\"yes\" or renumber")
            level = rule.get("level", "")
            if not level.isdigit() or not 0 <= int(level) <= 16:
                report.error(where, f"invalid level {level!r}")
            desc = rule.find("description")
            if desc is None or not (desc.text or "").strip():
                report.error(where, "missing description")

            for tag in ("if_sid", "if_matched_sid"):
                for el in rule.findall(tag):
                    for parent in split_tokens(el.text):
                        if not parent.isdigit():
                            report.error(where, f"{tag} {parent!r} is not numeric")
                        elif int(parent) not in repo_ids and int(parent) not in builtin_ids:
                            report.error(where, f"{tag} {parent} does not exist in the repo or Wazuh {wazuh_tag}")
            for tag in ("if_group", "if_matched_group"):
                for el in rule.findall(tag):
                    for grp in split_tokens(el.text):
                        if grp not in known_groups:
                            report.error(where, f"{tag} {grp!r} is not defined in the repo or Wazuh {wazuh_tag}")

            for mid in rule.findall("mitre/id"):
                tid = (mid.text or "").strip()
                tech = techniques.get(tid)
                if tech is None:
                    report.error(where, f"MITRE id {tid!r} is not an ATT&CK Enterprise technique")
                elif tech["status"] != "active":
                    repl = tech.get("replaced_by")
                    hint = f" (use {repl})" if repl else ""
                    report.error(where, f"MITRE id {tid} is {tech['status']}{hint}")

            for field in rule.findall("field"):
                fname = field.get("name", "")
                if CAMEL_CASE_FIELD.match(fname):
                    report.error(where, f"field {fname!r} should be camelCase (Wazuh decodes Windows fields that way)")
                if field.get("type") == "pcre2" and field.text:
                    try:
                        re.compile(python_compatible(field.text.strip()))
                    except re.error as exc:
                        report.warn(where, f"pcre2 pattern on {fname} not compilable by Python ({exc}); verify with wazuh-logtest")

            for lst in rule.findall("list"):
                ref = (lst.text or "").strip()
                short = re.sub(r"^etc/lists/", "", ref)
                if short not in WAZUH_DEFAULT_LISTS and Path(short).name not in lists_in_repo:
                    report.error(where, f"list {ref!r} is not shipped in this repo nor a Wazuh default list")

    if not args.quiet:
        for w in report.warnings:
            print(f"WARNING {w}")
    for e in report.errors:
        print(f"ERROR   {e}")
    print(
        f"\n{file_count} rule files, {len(rules)} rules, {len(repo_ids)} unique IDs; "
        f"{len(report.errors)} error(s), {len(report.warnings)} warning(s) "
        f"[reference: Wazuh {wazuh_tag}, ATT&CK {len(techniques)} techniques]"
    )
    return 1 if report.errors else 0


if __name__ == "__main__":
    sys.exit(main())
