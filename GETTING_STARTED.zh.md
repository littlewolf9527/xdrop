# 准备工作

本文档介绍编译 XDrop 之前需要准备的所有环境依赖。

[English](GETTING_STARTED.md)

---

## 概述

XDrop 的两个组件对编译和运行环境的要求不同：

| 组件 | 编译环境 | 运行环境 |
|------|---------|---------|
| **Controller** | 任意系统（Linux / macOS / Windows） | 任意系统 |
| **Node Agent** | **仅限 Linux** | **仅限 Linux**，需要 root |

Node Agent 使用 BPF/XDP，这是 Linux 内核特性，无法在 macOS 或 Windows 上编译和运行。

---

## Controller 环境准备

### Go ≥ 1.21

```bash
# 从 https://go.dev/dl/ 下载，或通过包管理器安装
go version
# 期望输出：go version go1.21.x ...
```

### Node.js ≥ 18

仅编译 Vue 3 前端时需要。前端编译产物会嵌入 Go 二进制，**运行时不需要 Node.js**。

```bash
# 从 https://nodejs.org 或通过 nvm 安装
node --version
# 期望输出：v18.x.x 或更高

npm --version
```

**Controller 的环境就这些。** 它可以在 Linux、macOS 或 Windows 上编译和运行。

---

## Node Agent 环境准备

Node Agent 必须在 **Linux 主机**上编译和运行。

### 1. Linux 内核 ≥ 5.9

Node Agent 使用 `BPF_LINK_TYPE_XDP` 挂载 XDP 程序，该特性 2020-10 在
Linux 5.9 落地。在更老的内核上 agent 会直接拒绝启动，并返回指向此
要求的明确错误信息。

```bash
uname -r
# 期望输出：5.9.x 或更高
```

> **内核 5.9–5.10**：XDP 可用，但通常只支持 Generic（SKB）模式，性能较低。
> **内核 5.10+**：大多数驱动支持 Native XDP 模式，**推荐使用**。
>
> **跑着老内核？** 请 pin 在 xdrop **v2.4.2** —— 那是最后一版走
> netlink attach 路径的发布，支持 5.4 起的内核。v2.5+ 为什么不实现
> pre-5.9 fallback 详见 `docs/proposals/goebpf-to-cilium-migration.md`
> §Phase 4.a。

### 2. clang 和 llvm ≥ 11

编译 BPF/C 程序所需。

```bash
# Ubuntu / Debian
apt install clang llvm

# RHEL / CentOS / Fedora
dnf install clang llvm

# 验证
clang --version
# 期望输出：clang version 11.x.x 或更高
```

### 3. make

运行 BPF Makefile 所需。

```bash
# Ubuntu / Debian
apt install make

# RHEL / CentOS / Fedora
dnf install make

which make
```

### 4. Linux 内核头文件

BPF 编译依赖内核头文件，且版本必须与**当前运行的内核**一致。

```bash
# Ubuntu / Debian
apt install linux-headers-$(uname -r)

# RHEL / CentOS
dnf install kernel-devel-$(uname -r)

# 验证头文件存在
ls /usr/src/linux-headers-$(uname -r)/
```

> 若找不到精确匹配的版本，可安装最接近的版本并创建软链接。大多数情况下，安装通用的 `linux-headers-generic` 包即可正常编译 BPF 程序。

### 5. Go ≥ 1.24

v2.5 起从 1.21 升到 1.24，因为 Node Agent 依赖的
`github.com/cilium/ebpf@v0.21.0`（负责 BPF loader + link 生命周期管理）
要求 Go 1.24。Controller 仍保持 1.21+ —— **只有 Node Agent 构建需要
新工具链**。

```bash
go version
# 期望输出：go version go1.24.x linux/amd64
```

### 6. 运行时需要 root 权限

Node Agent 必须以 root 运行（或具备 `CAP_NET_ADMIN` 权限），才能加载 BPF 程序并挂载到网卡。

```bash
# 查看当前用户
whoami

# 启动脚本会强制检查此条件：
sudo ./scripts/node.sh start
```

### 7. bpffs 挂载在 /sys/fs/bpf（可选但推荐）

v2.5+ 把 BPF 对象 pin 到 `/sys/fs/bpf/xdrop/`，让状态跨
`systemctl restart xdrop-agent` 存活：

- **16 个 map 文件**（Phase 3）：`blacklist`、`whitelist`、4 个 LPM
  trie 等。map ID 稳定，`bpftool map dump pinned
  /sys/fs/bpf/xdrop/<name>` 可跨重启观察，外部 BPF 工具也继续指向
  同一份对象。
- **每个接口 1 个 XDP link 文件**（Phase 4）：`link_<ifname>`
  （如 `link_ens38`）。Agent 重启通过 `LoadPinnedLink +
  Link.Update(newProg)` 原子替换 XDP 程序 —— 内核层面零空窗切换。
  没有 link pinning 的话，每次重启有约 1.5–3 秒的无过滤窗口。

两者都需要 `/sys/fs/bpf` 挂载为 `bpf` 类型文件系统。

```bash
# 检查 —— f_type 应为 "bpf_fs"（magic 0xcafe4a11）
stat -f -c '%T' /sys/fs/bpf
# 期望输出：bpf_fs
```

现代发行版通常由 systemd 的 `sys-fs-bpf.mount` unit 自动挂载。
如果上面的检查返回 `sysfs` 或其他值，手动挂载：

```bash
mount -t bpf bpf /sys/fs/bpf

# 持久化到 /etc/fstab：
echo 'bpf /sys/fs/bpf bpf defaults 0 0' >> /etc/fstab
```

如果因任何原因无法挂载 bpffs，默认 `bpf.pinning: auto` 策略下 agent
会自动降级到非 pinned 模式 —— 规则仍然能加载，只是丢失 map fd 的
重启保活 和 XDP 零空窗切换（降级为 Phase 2 等价行为，每次重启约
1.5 秒 detach-reattach 窗口）。

---

## 验证 Node 编译环境

在 Linux 主机上编译之前，运行以下检查清单：

```bash
echo "=== 内核版本 ===" && uname -r
echo "=== Go ===" && go version 2>/dev/null || echo "未安装"
echo "=== clang ===" && clang --version 2>/dev/null | head -1 || echo "未安装"
echo "=== llvm-strip ===" && llvm-strip --version 2>/dev/null | head -1 || echo "未安装"
echo "=== make ===" && make --version 2>/dev/null | head -1 || echo "未安装"
echo "=== 内核头文件 ===" && ls /usr/src/linux-headers-$(uname -r) &>/dev/null && echo "OK" || echo "未安装"
```

所有项目均显示版本号或"OK"后，方可开始编译。

---

## 网卡要求

### 确认 XDP 支持情况

并非所有驱动都支持 Native XDP 模式。可通过以下方式确认：

```bash
# 查看网卡驱动
ethtool -i <网卡名>
# 查看 driver 字段，参考对应驱动文档确认 XDP 支持情况

# Agent 启动时会在日志中打印实际使用的 XDP 模式
# 若不支持 Native 模式，会自动回退到 Generic（SKB）模式
```

**支持 Native XDP 的常见驱动**（不完整列表）：`mlx5`、`i40e`、`ice`、`ixgbe`、`virtio_net`、`veth`、`tun`，以及主流云平台的虚拟网卡（AWS ENA、GCP virtio 等）。

**Generic（SKB）模式**在任意驱动上均可工作，但在内核分配 `sk_buff` 之后才运行，性能低于 Native 模式。中等流量场景下足够使用。

### 确认网卡名称

```bash
ip link show
# 或
ip addr show

# 记录需要挂载 XDP 的网卡名称（如 eth0、ens3、enp3s0）
# 在 node/config.yaml 的 server.interface 字段中填写
```

> **注意：** 除非确认规则不会阻断 SSH 流量，否则不要将 XDP 挂载到 SSH 管理接口上。条件允许时，请使用专用的数据平面网卡。

---

## 推荐部署拓扑

标准生产部署：

```
Controller 主机：任意 Linux 服务器或虚拟机（编译时需要 Go + Node.js）
Node Agent 主机：内核 ≥ 5.10 的 Linux 服务器，配备用于 XDP 的专用网卡
```

实验室或单机部署：Controller 和 Node Agent 可以运行在同一台机器上。确保 Node Agent 挂载到正确的网卡，并且规则不会意外阻断 Controller 的通信流量。

---

## 快速环境安装（Ubuntu 22.04 / 24.04）

```bash
# 更新包列表
apt update

# Go（请从 https://go.dev/dl/ 获取最新版本）
wget https://go.dev/dl/go1.21.13.linux-amd64.tar.gz
tar -C /usr/local -xzf go1.21.13.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc

# Node.js 20 LTS（仅 Controller 编译需要）
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt install -y nodejs

# BPF 编译工具
apt install -y clang llvm make linux-headers-$(uname -r)

# 验证
go version && node --version && clang --version | head -1
```

---

## 下一步

环境准备完成后：

1. **编译** — 参见根目录 README 的[快速开始](README.zh.md#快速开始)
2. **配置** — 为每个组件复制 `config.example.yaml` 并填写必要字段
3. **启动** — 使用 `scripts/` 目录下的脚本启动、停止和查看状态

详细配置说明请参见：
- [Controller 文档](controller/README.zh.md)
- [Node Agent 文档](node/README.zh.md)
