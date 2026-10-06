# Contributing

## Before you open a PR

```bash
python tools/validate_rules.py          # must report 0 errors
python tools/test_emerging_threats.py   # if you touched Emerging Threats
```

CI runs the same checks, plus the Sysmon re-anchor drift check, Python compilation and `bash -n` on shell scripts. If you can, also load the rules on a test manager (`/var/ossec/bin/wazuh-analysisd -t`) and confirm the expected rule fires in `wazuh-logtest`.

## Rule IDs

- Use the range of the folder you're working in (see the README's rule ID map). A new integration gets a new block in the 200000–201999 range.
- Don't reuse IDs below 100000 unless you are deliberately overwriting a Wazuh built-in with `overwrite="yes"`. In that case keep the built-in's parent, event ID and group.
- Wazuh 4.14 ships rules at 150100–150103, 150150, 184665–185013 and 500000–500102. The linter knows the full built-in list (`tools/wazuh_builtin_ruleset.json`).

## How Wazuh picks a rule

Sibling rules (children of the same parent) are evaluated **highest level first**, then in load order, and the first match wins. So:

- A low-level catch-all next to a higher-level specific rule is fine.
- A level-3 catch-all added as a sibling of a level-0 built-in hides every child of that built-in. Raise the built-in's level with an overwrite instead (see `Sysmon New Events`).

## Fields and regexes

- Windows eventchannel fields are camelCase: `win.eventdata.commandLine`, `win.eventdata.targetFilename`, `win.system.eventID`. The linter rejects PascalCase.
- Decoded Windows values keep backslashes doubled. In `type="pcre2"` patterns:
  - Use `\\` to anchor a file name (`\\cmd\.exe$`).
  - Use `\\+` between path components in the middle of a pattern (`\\+Temp\\+`), so it matches either representation.
- Fields without `type` use Wazuh's OS_Regex: no character classes, no `?`; `\.` means "any character".
- Use one `<field>` per field name. To combine conditions on one field, use a single PCRE2 pattern (for example a negative lookahead).

## MITRE ATT&CK

- Every detection rule (level 7 or higher) should have a `<mitre>` block with the most specific current technique.
- The linter rejects revoked and deprecated IDs. `python tools/update_mitre_ids.py` remaps them automatically after an ATT&CK update (`python tools/refresh_reference_data.py --skip-wazuh --skip-sysmon` first).

## Threat-intel lists

Don't edit files in `Threat Intel/lists/` by hand; the weekly job regenerates them. Put false positives in `Threat Intel/allowlist.txt`, or change the filters in `tools/update_threat_intel.py`.

## Sysmon rules

`Windows_Sysmon` rules key on the `RuleName` that sysmon-modular writes. After changing the pinned config (`Windows_Sysmon/sysmon_install.ps1`) or refreshing ATT&CK data, run `python tools/reanchor_sysmon.py` and commit the result together with `Windows_Sysmon/COVERAGE.md`.

## Syncing upstream

```bash
git fetch upstream && git merge upstream/main
python tools/update_mitre_ids.py && python tools/reanchor_sysmon.py && python tools/validate_rules.py
```

Upstream re-introduces the old field casing and IDs from time to time. The tools above fix most of it, and the linter flags the rest.
