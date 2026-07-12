# Tetragon (eBPF Runtime Security)

Rules for [Cilium Tetragon](https://tetragon.io/), the eBPF-based Kubernetes/Linux runtime security tool. Tetragon's process-execution and kernel-probe events flow into Wazuh, including rootkit indicators like `insmod` kernel-module loads.

| File | Purpose |
|---|---|
| `700000-tetragon.xml` | Rules (group `tetragon`) — process execution, kernel probes, potential rootkit activity via `insmod` — rule IDs 700000+ |

**Prerequisite:** Tetragon deployed on Linux/Kubernetes nodes with its JSON event export forwarded to Wazuh.
