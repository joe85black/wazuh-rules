# Windows Sysmon

MITRE ATT&CK-mapped rules for [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) events on Windows agents, plus an installer that deploys Sysmon with a pinned config. Original ruleset by [SOCFortress](https://www.socfortress.co/).

| File | Purpose |
|---|---|
| `100100-…EVENT1.xml` … `121201-…EVENT6.xml` | One rule file per Sysmon event type (1, 2, 3, 6, 7, 10–15, 17, 18, 22) |
| `200070-sysmon_reload.xml` | Alerts when the Sysmon config is reloaded |
| `sysmon_install.ps1` | Installs Sysmon, or updates its config, using the pinned sysmon-modular config |
| `agent.conf` | Agent `localfile` block to collect `Microsoft-Windows-Sysmon/Operational` |
| `common-ports` | CDB list used by the Event 3 rules |
| `COVERAGE.md` | Generated report: which rules match the pinned config |

## Sysmon config

Most rules match the `RuleName` field that the Sysmon config writes into each event (`technique_id=T1218,technique_name=…`). `sysmon_install.ps1` installs [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular) from release `configs-082cba578667` (balanced profile, Sysmon 15.x) and checks its SHA256.

sysmon-modular now publishes prebuilt configs only as release assets. The old `raw.githubusercontent.com/.../master/sysmonconfig.xml` URL returns 404.

Rules written for older sysmon-modular rule names are re-keyed on the technique ID, so ATT&CK renames don't silently break them. About 690 Event 1 conditions match descriptive names (`Rubeus Pass-the-Ticket`, `Hashcat Password Cracking`, …) that come from SOCFortress's own Sysmon config, which isn't public. **Those rules never fire with sysmon-modular.** [`COVERAGE.md`](COVERAGE.md) has the per-file numbers.

## Changing the pinned config

1. Update `$sysmonconfig_release` and `$sysmonconfig_sha256` in `sysmon_install.ps1`. The hash is in the release's `SHA256SUMS`.
2. Set `SYSMON_CONFIG_TAG` in [`tools/reanchor_sysmon.py`](../tools/reanchor_sysmon.py) to the same release.
3. Run `python tools/reanchor_sysmon.py` and review the diff and `COVERAGE.md`.
4. Run `python tools/validate_rules.py`.

## Collecting the logs

Add the Sysmon channel to the agent (or use `agent.conf` through centralized configuration):

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```
