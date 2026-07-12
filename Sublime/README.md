# Sublime (Email Phishing)

Rules for [Sublime Security](https://sublime.security/), the email security platform. Sublime's phishing verdicts become Wazuh alerts so mailbox-level detections correlate with endpoint activity from the same user.

| File | Purpose |
|---|---|
| `200970-phishing.xml` | Rules (group `phishing`) alerting on Sublime "Phishing Detected" events — rule IDs 200970+ |

**Prerequisite:** Sublime webhook/API output forwarded to the manager as JSON.
