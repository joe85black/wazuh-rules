# Duo

Rules for [Cisco Duo](https://duo.com/) MFA authentication logs. They raise second-factor denials, fraud reports, bypasses and push-bombing, so MFA anomalies correlate with the rest of your telemetry.

| Rule | Level | Fires when | ATT&CK |
|---|---|---|---|
| 200930 | 3 | Any Duo authentication event (base rule) | |
| 200931 | 7 | `result` is `denied` | T1078 |
| 200932 | 12 | `reason` is `user_marked_fraud` (user rejected a push as fraudulent) | T1621 |
| 200933 | 10 | Success via `bypass_user` or `allow_unenrolled_user` (second factor skipped) | T1556.006 |
| 200934 | 10 | `locked_out`, `frequent_attempts` or `anonymous_ip` | T1110 |
| 200935 | 12 | 5+ denials for the same `user.name` within 10 minutes (MFA fatigue) | T1621 |

**Prerequisites:**

- A poller for the Duo Admin API (`/admin/v2/logs/authentication`) that writes one JSON event per line to a file the manager reads with `<location>duo_auth_logs</location>` (rule 200930 matches on that location).
- Deploy [`Suricata/100002-suricata.xml`](../Suricata) too. Duo's JSON has `timestamp` and `event_type` fields, so Wazuh's Suricata base rule 86600 claims it first and 100002 becomes the parent. Field names follow [Duo's Admin API docs](https://duo.com/docs/adminapi).
