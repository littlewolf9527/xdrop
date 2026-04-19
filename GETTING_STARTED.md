# Getting Started

This guide covers everything you need to set up before building XDrop.

[中文文档](GETTING_STARTED.zh.md)

---

## Overview

XDrop has two components with different build and runtime requirements:

| Component | Build Host | Runtime Host |
|-----------|-----------|--------------|
| **Controller** | Any OS (Linux / macOS / Windows) | Any OS |
| **Node Agent** | **Linux only** | **Linux only**, requires root |

The Node Agent uses BPF/XDP, which is a Linux kernel feature. It cannot be built or run on macOS or Windows.

---

## Controller Prerequisites

### Go ≥ 1.21

```bash
# Install from https://go.dev/dl/ or via your package manager
go version
# Expected: go version go1.21.x ...
```

### Node.js ≥ 18

Required only to build the Vue 3 frontend. The compiled frontend is embedded into the Go binary, so Node.js is not needed at runtime.

```bash
# Install from https://nodejs.org or via nvm
node --version
# Expected: v18.x.x or higher

npm --version
```

**That's all for the Controller.** It can be built and run on Linux, macOS, or Windows.

---

## Node Agent Prerequisites

The Node Agent must be built and run on a **Linux host**.

### 1. Linux Kernel ≥ 5.9

The node agent uses `BPF_LINK_TYPE_XDP` for XDP attach, which landed in
Linux 5.9 (October 2020). On older kernels the agent refuses to start
with a clear error message pointing to this requirement.

```bash
uname -r
# Expected: 5.9.x or higher
```

> **Kernel 5.9–5.10**: XDP works but typically only in generic (SKB) mode — lower performance.
> **Kernel 5.10+**: Native XDP mode available on most drivers — recommended.
>
> **Running an older kernel?** Pin to xdrop **v2.4.2**, the last release
> that uses the netlink-based attach path and supports kernels down to
> 5.4. See the Phase 2 migration note in
> `docs/proposals/goebpf-to-cilium-migration.md` §Phase 4.a for why a
> pre-5.9 fallback was intentionally not implemented in v2.5+.

### 2. clang and llvm ≥ 11

Required to compile the BPF/C program.

```bash
# Ubuntu / Debian
apt install clang llvm

# RHEL / CentOS / Fedora
dnf install clang llvm

# Verify
clang --version
# Expected: clang version 11.x.x or higher
```

### 3. make

Required to run the BPF Makefile.

```bash
# Ubuntu / Debian
apt install make

# RHEL / CentOS / Fedora
dnf install make

which make
```

### 4. Linux kernel headers

Required for BPF compilation. The headers must match the **running kernel version**.

```bash
# Ubuntu / Debian
apt install linux-headers-$(uname -r)

# RHEL / CentOS
dnf install kernel-devel-$(uname -r)

# Verify headers exist
ls /usr/src/linux-headers-$(uname -r)/
```

> If the exact version is unavailable, install the closest available version and create a symlink. Alternatively, most BPF programs compile fine with the generic `linux-headers-generic` package.

### 5. Go ≥ 1.24

Bumped from 1.21 in v2.5 because `github.com/cilium/ebpf@v0.21.0`
(used by the node agent for BPF loader + link management) requires
Go 1.24. The Controller still targets 1.21+ — only the node agent
build needs the newer toolchain.

```bash
go version
# Expected: go version go1.24.x linux/amd64
```

### 6. Root access at runtime

The node agent must run as root (or with `CAP_NET_ADMIN`) to load BPF programs and attach them to network interfaces.

```bash
# Check current user
whoami

# The start script enforces this:
sudo ./scripts/node.sh start
```

### 7. bpffs mounted at /sys/fs/bpf (optional but recommended)

v2.5+ pins its BPF objects under `/sys/fs/bpf/xdrop/` so state
survives across `systemctl restart xdrop-agent`:

- **16 map files** (Phase 3): `blacklist`, `whitelist`, the four
  LPM tries, etc. Stable map IDs for `bpftool map dump pinned
  /sys/fs/bpf/xdrop/<name>` and external BPF tooling.
- **1 XDP link file per interface** (Phase 4): `link_<ifname>`
  (e.g. `link_ens38`). Agent restart does `LoadPinnedLink +
  Link.Update(newProg)` — zero-gap kernel attachment swap. Without
  link pinning, restart leaves a ~1.5–3 s window with no filter.

Both require `/sys/fs/bpf` to be mounted as a `bpf` filesystem.

```bash
# Verify — f_type should be "bpf_fs" (magic 0xcafe4a11)
stat -f -c '%T' /sys/fs/bpf
# Expected: bpf_fs
```

Most modern distros mount bpffs automatically via systemd's
`sys-fs-bpf.mount` unit. If the check above returns something else
(e.g. `sysfs`), mount it manually:

```bash
mount -t bpf bpf /sys/fs/bpf

# Persist via /etc/fstab:
echo 'bpf /sys/fs/bpf bpf defaults 0 0' >> /etc/fstab
```

If you cannot mount bpffs for any reason, the agent falls back to
non-pinned mode automatically under the default `bpf.pinning: auto`
policy — rules still load, you just lose restart-survival of map
fds AND zero-gap XDP attach (Phase 2-equivalent ~1.5 s detach-reattach
window on every restart).

---

## Verify Your Node Build Environment

Run this checklist on your Linux host before building:

```bash
echo "=== Kernel ===" && uname -r
echo "=== Go ===" && go version 2>/dev/null || echo "NOT FOUND"
echo "=== clang ===" && clang --version 2>/dev/null | head -1 || echo "NOT FOUND"
echo "=== llvm-strip ===" && llvm-strip --version 2>/dev/null | head -1 || echo "NOT FOUND"
echo "=== make ===" && make --version 2>/dev/null | head -1 || echo "NOT FOUND"
echo "=== kernel headers ===" && ls /usr/src/linux-headers-$(uname -r) &>/dev/null && echo "OK" || echo "NOT FOUND"
```

All items should show a version or "OK" before proceeding to build.

---

## Network Interface Requirements

### Check XDP support

Not all drivers support native XDP mode. To check whether your NIC supports it:

```bash
# Using ethtool (kernel 5.3+)
ethtool -i <interface>
# Look for "driver" field — check driver documentation for XDP support

# Attempt native XDP attach (the agent will log the mode used)
# If native mode is unavailable, it falls back to generic (SKB) mode automatically
```

**Drivers with native XDP support** (partial list): `mlx5`, `i40e`, `ice`, `ixgbe`, `virtio_net`, `veth`, `tun`, common cloud VM drivers (AWS ENA, GCP virtio, etc.)

**Generic (SKB) mode** works on any driver but runs after the kernel allocates `sk_buff`, so performance is lower. It is sufficient for moderate traffic.

### Identify the correct interface

```bash
ip link show
# or
ip addr show

# Note the interface name you want to attach XDP to (e.g., eth0, ens3, enp3s0)
# You will set this in node/config.yaml under server.interface
```

> **Important:** Do not attach XDP to your SSH management interface unless you are certain your rules will not block SSH traffic. Use a dedicated data-plane interface when possible.

---

## Recommended Setup

For a typical deployment:

```
Controller host:  any Linux server or VM (Go + Node.js for build)
Node Agent host:  Linux server with kernel ≥ 5.10, dedicated NIC for XDP
```

For a lab / single-host setup, the Controller and Node Agent can run on the same machine. Just ensure the Node Agent is attached to the correct interface and that your rules do not accidentally block controller traffic.

---

## Quick Environment Setup (Ubuntu 22.04 / 24.04)

```bash
# Update package lists
apt update

# Go (replace with latest version from https://go.dev/dl/)
wget https://go.dev/dl/go1.21.13.linux-amd64.tar.gz
tar -C /usr/local -xzf go1.21.13.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# Node.js 20 LTS (controller build only)
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt install -y nodejs

# BPF build tools
apt install -y clang llvm make linux-headers-$(uname -r)

# Verify
go version && node --version && clang --version | head -1
```

---

## Next Steps

Once your environment is ready:

1. **Build** — see [Quick Start](README.md#quick-start) in the root README
2. **Configure** — copy `config.example.yaml` for each component and edit the required fields
3. **Run** — use the scripts in `scripts/` to start, stop, and check status

For detailed configuration options, see:
- [Controller README](controller/README.md)
- [Node Agent README](node/README.md)
