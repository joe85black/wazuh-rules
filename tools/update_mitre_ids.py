#!/usr/bin/env python3
"""Rewrite revoked or deprecated ATT&CK IDs in every rule's <mitre> block.

Uses tools/attack_techniques.json (revoked-by relationships) plus the manual
map in reanchor_sysmon.py for deprecated techniques that have no successor.
Line endings and formatting are preserved; only <id> values inside <mitre>
change. Run after `refresh_reference_data.py` or after syncing upstream:

    python tools/update_mitre_ids.py [--dry-run]
"""
import argparse
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from reanchor_sysmon import ROOT, current_id, load_attack  # noqa: E402

MITRE_BLOCK = re.compile(r"<mitre>.*?</mitre>", re.S)
MITRE_ID = re.compile(r"<id>\s*([^<\s]+)\s*</id>")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    techniques = load_attack()
    changes = Counter()

    def fix_block(block):
        def fix_id(m):
            old = m.group(1)
            new = current_id(old, techniques)
            if new != old:
                changes[f"{old} -> {new}"] += 1
            return f"<id>{new}</id>" if new != old else m.group(0)

        fixed = MITRE_ID.sub(fix_id, block.group(0))
        # Remapping can turn two IDs into the same one; keep the first.
        seen = set()

        def dedupe(m):
            if m.group(1) in seen:
                return ""
            seen.add(m.group(1))
            return m.group(0)

        return re.sub(r"[ \t]*<id>([^<]+)</id>[ \t]*\r?\n?", lambda m: dedupe(m), fixed) if fixed != block.group(0) else fixed

    for path in sorted(ROOT.rglob("*.xml")):
        if any(part.startswith(".") for part in path.relative_to(ROOT).parts):
            continue
        with open(path, encoding="utf-8", newline="") as fh:
            text = fh.read()
        new_text = MITRE_BLOCK.sub(fix_block, text)
        if new_text != text:
            print(f"updated {path.relative_to(ROOT).as_posix()}")
            if not args.dry_run:
                with open(path, "w", encoding="utf-8", newline="") as fh:
                    fh.write(new_text)

    for change, count in sorted(changes.items()):
        print(f"  {change}: {count}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
