# Node operations

## Role and requirements

The Linux node agent loads `xdrop_main.elf` and `xdrop_gate.elf`, attaches XDP and serves its management API. Supported deployment architectures are little-endian x86-64 and arm64, with kernel ≥ 6.4 and BPF JIT enabled; see the separate version/JIT checks in [Getting started](../GETTING_STARTED.md).

Build on Linux with Go satisfying `go 1.24.0` / `toolchain go1.24.4`, clang supporting the BPF target, make and Python 3. Run management as root. Only one Fast Forward interface pair is supported; use a dedicated management path when changing data interfaces.

## Build

```bash
./scripts/build-node.sh all
# Or: ./scripts/build-node.sh bpf
# Or: ./scripts/build-node.sh agent
```

Run from the repository root. BPF uses `make -C node/bpf clean` then `make -C node/bpf all`; both ELF objects are required. The agent is built from `node/agent` into `node/xdrop-agent`, with a version string from `git describe --tags --always --dirty`; protocol 11 is a separate constant. No dependency tidy runs during build.

## Configuration

Copy `node/config.example.yaml` to `node/config.yaml` and edit it before starting. The placeholder `CHANGE_ME_NODE_KEY` is deliberately rejected: `auth.node_api_key still contains a placeholder value ...; generate a real key before starting`. Use a nonempty key matching the controller registration.

| Setting | Meaning |
|---|---|
| `server.port` | HTTP port, default 8080; listener binds all host addresses |
| `server.interface` | Traditional-mode interface, default eth0 |
| `server.hits_rate_limit` | Integer 1..1000; default 20 requests/s and burst |
| `bpf.main_path`, `bpf.gate_path` | Required ELF locations; sample is relative to node/ |
| `bpf.pinning` | auto (default), require or disable |
| `bpf.xdp_mode` | auto (default), native or generic |
| `bpf.rate_limit_divisor` | Startup CPU divisor, described below |
| `bpf.ipv6_deep_chain_drop` | Boolean, default true; drop chains beyond 6 IPv6 extension headers; restart after changes. Startup drops until the agent writes the setting, even when false. |
| `auth.node_api_key` | Required X-API-Key; empty values (including whitespace) or placeholders reject startup |
| `fast_forward.enabled`, `fast_forward.pairs` | Optional FF mode, default disabled; exactly one pair when enabled |

`bpf.rate_limit_divisor` accepts 0 (online CPU count, possible CPU count on read failure) or an integer override 1..4096. X7: the receiving CPU set must be fixed and no larger than the override; a divisor that is too small amplifies the aggregate rule limit. For example, keep one RX queue, fixed IRQ affinity and no RPS when using a divisor of one.

## Operating modes

Traditional mode attaches to `server.interface`; accepted packets pass to the host stack. `-iface <name>` overrides that interface only in traditional mode.

Fast Forward ignores `server.interface`. Its pair has distinct `inbound` and `outbound` names and `filter_on: inbound|outbound|both` (default inbound). The agent programs both forwarding directions before attachment, brings interfaces UP, enables promiscuous mode and disables GRO/LRO/TSO. The non-filtering direction bypasses policy filtering.

`xdp_mode: native` requires driver XDP, `generic` requests SKB, and `auto` accepts the kernel result. Inspect `xdp_info.interfaces[].attach_mode` for actual modes; an FF pair can have different modes. The startup log warns when they differ.

## Start, stop and restart

Use `sudo ./scripts/manage-node.sh start|stop|restart|status|logs`. The script starts `node/xdrop-agent -config <file>` from `node/`, so example ELF paths resolve correctly. Absolute `XDROP_CONFIG` and `XDROP_RUN_DIR` override `node/config.yaml` and `node/run`. It uses the same PID-file and exact-command verification as the controller manager, records `service.exit`, and waits up to 30 seconds after SIGTERM without SIGKILL. Status is process status only (0 running, 3 stopped).

SIGTERM stops samplers and closes BPF/link descriptors; pinned XDP links can remain attached. `restart` keeps those pins; `stop` removes `/sys/fs/bpf/xdrop/link_*` after a managed process exits. A stop with no managed live PID does not remove orphan pins. This agent uses the shared `/sys/fs/bpf/xdrop` namespace; do not treat separate processes as isolated installations.

Pin reuse can preserve attachment, but startup clears policy and logical state. Empty policy is fail-open until full rules and whitelist recovery; restart does not guarantee uninterrupted filtering. FF shutdown restores interface settings only when XDP is no longer attached; after stop removes surviving pins, settings can still remain changed. Inspect UP/PROMISC/offloads before restoring the previous configuration manually.

## API and recovery

`GET /` reports the build version and synchronization protocol 11. `GET /api/v1/health` is public and returns HTTP 200 even while degraded. Healthy means successful full rules and whitelist snapshots have both been received since startup; it does not prove every submitted rule was accepted.

The controller pushes state; the node does not pull it. Register the node URL and matching key in the controller and inspect per-side status. The [node API](API.md) has eight protected routes; they require `X-API-Key`. Do not send controller machine credentials to the node.

## Troubleshooting and upgrades

| Symptom | Check |
|---|---|
| Placeholder credential error | Replace the example node key before restart |
| ELF load or verifier failure | Both ELF paths, kernel requirement and JIT separately |
| Pinning failure with require | bpffs at /sys/fs/bpf and permissions; auto can fall back |
| Native attach failure | NIC driver support and actual attachment errors |
| Degraded health | Controller reachability, matching node key, protocol and both full snapshots |
| Hits HTTP 429 | Shared hits request rate; do not retry immediately |

Keep a matching agent/ELF set for rollback; replacing only one ELF is not a complete build. Stop before replacing files and check node health plus delivery after restart. Map schema changes can recreate pinned maps; pinning is not a policy backup. Validate each node before upgrading the next.

Unknown configuration keys reject startup and report the key name; deprecated `auth.controller_url` / `auth.controller_sync_key` are accepted with a warning. `auth.node_api_key` is required. Empty values (including whitespace), leading or trailing whitespace, or placeholders reject startup; generate a real key before starting. Source: [`config.Config.Validate`](agent/config/config.go).
