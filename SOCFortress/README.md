# SOCFortress (Custom Detections)

SOCFortress's grab-bag of hand-written Windows detections that don't fit a single integration — e.g. ETW tampering techniques (disabling Event Tracing for Windows to blind logging, per the well-known [Palantir research](https://blog.palantir.com/tampering-with-windows-event-tracing-background-offense-and-defense-4be7ac62ac63)).

| File | Purpose |
|---|---|
| `800100-socfortress_added.xml` | Custom rules (group `socfortress`) — rule IDs 800100+ |

Requires Sysmon on Windows agents (rules chain off Sysmon process/registry events).
