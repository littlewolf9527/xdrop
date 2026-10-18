# 节点运维

## 职责与要求

Linux 节点 agent 加载 `xdrop_main.elf`、`xdrop_gate.elf`，挂载 XDP 并提供管理 API。部署支持小端 x86-64 和 arm64，要求内核 ≥ 6.4 且开启 BPF JIT；版本与 JIT 的分别检查见[部署指南](../GETTING_STARTED.zh.md)。

在 Linux 构建，准备满足 `go 1.24.0` / `toolchain go1.24.4` 的 Go、支持 BPF target 的 clang、make 和 Python 3；以 root 管理进程。Fast Forward 只支持一对接口；变更数据接口时保留独立管理通道。

## 构建

```bash
./scripts/build-node.sh all
# Or: ./scripts/build-node.sh bpf
# Or: ./scripts/build-node.sh agent
```

从仓库根目录执行。BPF 先运行 `make -C node/bpf clean`，再运行 `make -C node/bpf all`；两个 ELF 都必需。agent 从 `node/agent` 构建为 `node/xdrop-agent`，版本字符串取自 `git describe --tags --always --dirty`；协议 11 是独立常量。构建不执行依赖 tidy。

## 配置

复制 `node/config.example.yaml` 为 `node/config.yaml`，编辑后再启动。占位符 `CHANGE_ME_NODE_KEY` 会被有意拒绝：`auth.node_api_key still contains a placeholder value ...; generate a real key before starting`。使用与控制器登记项一致的非空密钥。

| 设置 | 含义 |
|---|---|
| `server.port` | HTTP 端口，默认 8080；监听主机所有地址 |
| `server.interface` | 传统模式接口，默认 eth0 |
| `server.hits_rate_limit` | 整数 1..1000；默认每秒 20 次且 burst 为 20 |
| `bpf.main_path`, `bpf.gate_path` | 必需 ELF 路径；样例相对于 node/ |
| `bpf.pinning` | auto（默认）、require 或 disable |
| `bpf.xdp_mode` | auto（默认）、native 或 generic |
| `bpf.rate_limit_divisor` | 启动时 CPU 除数，见下文 |
| `auth.node_api_key` | 必填 X-API-Key；空值（含全空白）或占位符拒绝启动 |
| `fast_forward.enabled`, `fast_forward.pairs` | 可选 FF 模式，默认关闭；启用时必须恰有一对接口 |

`bpf.rate_limit_divisor` 接受 0（在线 CPU 数，读取失败时回退到 possible CPU 数）或 1..4096 的整数覆盖值。X7：实际收包 CPU 集合必须固定且不多于覆盖值，除数过小会放大规则总上限。例如，除数为一时保持单收包队列、固定中断亲和且不启用 RPS。

## 运行模式

传统模式挂载到 `server.interface`，放行报文进入主机协议栈。`-iface <name>` 只在传统模式覆盖该接口。

Fast Forward 忽略 `server.interface`。接口对包含不同的 `inbound` 和 `outbound` 名称，`filter_on` 为 inbound、outbound 或 both，默认 inbound。agent 在挂载前配置双向转发，使接口 UP、开启混杂模式并关闭 GRO/LRO/TSO；未选为过滤方向的一侧绕过策略过滤。

`xdp_mode: native` 要求驱动 XDP，`generic` 请求 SKB，`auto` 接受内核选择。通过 `xdp_info.interfaces[].attach_mode` 查看实际模式；FF 两侧可能不同，启动日志会对此告警。

## 启动、停止与重启

使用 `sudo ./scripts/manage-node.sh start|stop|restart|status|logs`。脚本从 `node/` 启动 `node/xdrop-agent -config <file>`，使样例 ELF 相对路径正确解析。绝对路径 `XDROP_CONFIG`、`XDROP_RUN_DIR` 可覆盖默认 `node/config.yaml`、`node/run`。它与控制器管理器采用相同的 PID 文件及精确命令校验，记录 `service.exit`，发送 SIGTERM 后最多等待 30 秒，不发送 SIGKILL。status 只报告进程状态（运行 0、停止 3）。

SIGTERM 停止采样并关闭 BPF/link 描述符；已 pin 的 XDP link 可能继续挂载。`restart` 保留这些 pin；`stop` 在受管进程退出后删除 `/sys/fs/bpf/xdrop/link_*`。没有受管存活 PID 时，stop 不清理孤立 pin。agent 使用共享 `/sys/fs/bpf/xdrop` 命名空间，不能把多个进程视为相互隔离的安装。

复用 pin 可保持挂载，但启动会清空策略及逻辑状态。规则与白名单完整恢复之前，空策略放行流量；重启不保证过滤连续。FF 退出仅在 XDP 已无挂载时恢复接口设置；stop 随后移除残留 pin 时，接口设置仍可能保持改变。手工恢复原配置前检查 UP/PROMISC/offloads。

## API 与恢复

`GET /` 报告构建版本与同步协议 11。`GET /api/v1/health` 公开可读，降级时仍返回 HTTP 200。healthy 表示本次启动后规则与白名单都收到过成功完整快照，不证明提交的每条规则都被接受。

状态由控制器推送，节点不主动拉取。在控制器登记节点 URL 和匹配密钥，再检查两侧状态。[节点 API](API.zh.md) 有八条受保护路由；每次请求都要求 `X-API-Key`。不要向节点发送控制器机器凭证。

## 排障与升级

| 现象 | 检查项 |
|---|---|
| 占位密钥错误 | 重启前替换样例节点密钥 |
| ELF 加载或校验器失败 | 两个 ELF 路径，分别检查内核要求与 JIT |
| require 模式 pin 失败 | /sys/fs/bpf 的 bpffs 与权限；auto 可回退 |
| native 挂载失败 | 网卡驱动支持与实际挂载错误 |
| 健康状态降级 | 控制器可达性、匹配密钥、协议和两份完整快照 |
| Hits HTTP 429 | 共享 hits 请求速率；不要立即重试 |

回滚保留配套 agent/ELF 组合；只替换一个 ELF 不是完整构建。替换文件前停止，重启后检查健康与下发结果。map 结构变化可能重建已 pin 的 map；pinning 不是策略备份。每台恢复确认后再升级下一台。

`auth.node_api_key` 必填；空值（含全空白）或占位符拒绝启动，启动前须生成真实密钥。出处：[`config.Config.Validate`](agent/config/config.go)。
