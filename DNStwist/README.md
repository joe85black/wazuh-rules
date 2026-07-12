# DNStwist

Rules for [dnstwist](https://github.com/elceef/dnstwist), which generates typosquatted permutations of your domains and checks whether they are registered — early warning for phishing infrastructure impersonating your brand.

| File | Purpose |
|---|---|
| `200920-dnstwist.xml` | Rules (group `dnstwist`) — one set indexing newly registered lookalike domains, one flagging likely phishing candidates — rule IDs 200920+ |

**Prerequisite:** dnstwist run on a schedule with JSON output forwarded to the manager.
