# Active Response

Wazuh [Active Response](https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html) lets the manager trigger a script on an agent when a rule fires — block an IP, disable an account, isolate a host.

## Contents

| Path | Purpose |
|---|---|
| [`600000-active_response.xml`](600000-active_response.xml) | Rules that alert on Active Response executions themselves (Windows Firewall block triggered, automation events, Sysmon config steps), so every automated action leaves an audit trail |
| [`Windows/`](Windows) | Ready-made response scripts for Windows agents — disable a user account, sinkhole a domain, add a Windows Firewall block — each provided as `.cmd` + `.ps1`, with `ar.conf` snippets showing how to register them. See the [folder README](Windows/README.md) for setup |

## Notes

- This folder consolidates the former `Active_Response` folder (which held only the ruleset XML) into the scripts folder — one place for both the actions and the rules that audit them.
- Test any response command against a lab agent first; an over-broad trigger on a `disableuseraccount` response can lock out real users.
