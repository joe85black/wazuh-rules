#!/usr/bin/env python3
"""Regenerate the reference data the repo tooling validates against.

Writes two compact JSON files next to this script:

  wazuh_builtin_ruleset.json  - rule IDs and group names shipped with a pinned
                                Wazuh release (used to resolve if_sid/if_group
                                parents that live outside this repo).
  attack_techniques.json      - every MITRE ATT&CK Enterprise technique ID with
                                its name, status (active/revoked/deprecated) and
                                the technique it was revoked in favour of.
  sysmon_modular_rule_names.json
                              - every RuleName ever emitted by the sysmon-modular
                                sysmonconfig.xml (whole git history), so
                                reanchor_sysmon.py can tell sysmon-modular rules
                                apart from rules written for other configs.

All files are committed so validation runs offline and deterministically.
Re-run this script when bumping the Wazuh version or ATT&CK release:

    python tools/refresh_reference_data.py --wazuh-tag v4.14.8
"""
import argparse
import json
import re
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

HERE = Path(__file__).resolve().parent
ATTACK_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
WAZUH_API = "https://api.github.com/repos/wazuh/wazuh/contents/ruleset/rules?ref={tag}"
WAZUH_RAW = "https://raw.githubusercontent.com/wazuh/wazuh/{tag}/ruleset/rules/{name}"


def fetch(url):
    req = urllib.request.Request(url, headers={"User-Agent": "wazuh-rules-tooling"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        return resp.read()


def build_wazuh(tag):
    listing = json.loads(fetch(WAZUH_API.format(tag=tag)))
    ids, groups = set(), set()
    for entry in listing:
        name = entry["name"]
        if not name.endswith(".xml"):
            continue
        text = fetch(WAZUH_RAW.format(tag=tag, name=name)).decode("utf-8", "replace")
        ids.update(int(i) for i in re.findall(r'<rule\s+id="(\d+)"', text))
        for g in re.findall(r'<group\s+name="([^"]*)"', text) + re.findall(r"<group>([^<]*)</group>", text):
            groups.update(t.strip() for t in g.split(",") if t.strip())
    return {"wazuh_tag": tag, "rule_ids": sorted(ids), "groups": sorted(groups)}


def build_attack():
    bundle = json.loads(fetch(ATTACK_URL))
    objs = {o["id"]: o for o in bundle["objects"]}

    def ext_id(o):
        for ref in o.get("external_references", []):
            if ref.get("source_name") == "mitre-attack":
                return ref.get("external_id")
        return None

    revoked_by = {}
    for o in bundle["objects"]:
        if o["type"] == "relationship" and o.get("relationship_type") == "revoked-by":
            revoked_by[o["source_ref"]] = o["target_ref"]

    techniques = {}
    for o in bundle["objects"]:
        if o["type"] != "attack-pattern":
            continue
        tid = ext_id(o)
        if not tid:
            continue
        status = "revoked" if o.get("revoked") else "deprecated" if o.get("x_mitre_deprecated") else "active"
        entry = {"name": o.get("name", ""), "status": status}
        target = revoked_by.get(o["id"])
        if target and target in objs:
            entry["replaced_by"] = ext_id(objs[target])
        techniques[tid] = entry

    version = next((o.get("x_mitre_version") for o in bundle["objects"] if o["type"] == "x-mitre-collection"), None)
    modified = max((o.get("modified", "") for o in bundle["objects"] if o["type"] == "attack-pattern"), default="")
    return {"attack_version": version, "latest_modified": modified, "techniques": dict(sorted(techniques.items()))}


def build_sysmon_names():
    """Collect RuleNames from every historical sysmonconfig.xml in sysmon-modular.

    Prebuilt configs moved to GitHub Releases in 2026, so the newest release
    config is added on top of the git history.
    """
    names = set()
    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp) / "smm"
        subprocess.run(["git", "clone", "-q", "--filter=blob:none", "--no-checkout",
                        "https://github.com/olafhartong/sysmon-modular.git", str(repo)], check=True)
        commits = subprocess.run(["git", "-C", str(repo), "log", "--format=%H", "--", "sysmonconfig.xml"],
                                 check=True, capture_output=True, text=True).stdout.split()
        for sha in commits:
            blob = subprocess.run(["git", "-C", str(repo), "show", f"{sha}:sysmonconfig.xml"],
                                  capture_output=True, text=True, encoding="utf-8", errors="replace")
            names.update(re.findall(r'name="(technique_id=[^"]*)"', blob.stdout))
    latest = fetch("https://github.com/olafhartong/sysmon-modular/releases/latest/download/sysmonconfig.xml")
    names.update(re.findall(r'name="(technique_id=[^"]*)"', latest.decode("utf-8", "replace")))
    return {"source": "olafhartong/sysmon-modular sysmonconfig.xml history + latest release",
            "commits_scanned": len(commits), "names": sorted(names)}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--wazuh-tag", default="v4.14.8")
    ap.add_argument("--skip-wazuh", action="store_true")
    ap.add_argument("--skip-attack", action="store_true")
    ap.add_argument("--skip-sysmon", action="store_true")
    args = ap.parse_args()

    if not args.skip_sysmon:
        data = build_sysmon_names()
        (HERE / "sysmon_modular_rule_names.json").write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")
        print(f"sysmon-modular: {len(data['names'])} rule names from {data['commits_scanned']} commits")

    if not args.skip_wazuh:
        data = build_wazuh(args.wazuh_tag)
        (HERE / "wazuh_builtin_ruleset.json").write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")
        print(f"wazuh {args.wazuh_tag}: {len(data['rule_ids'])} rule IDs, {len(data['groups'])} groups")
    if not args.skip_attack:
        data = build_attack()
        (HERE / "attack_techniques.json").write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")
        print(f"attack: {len(data['techniques'])} techniques (latest modified {data['latest_modified']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
