# 部署指南

## 1. 准备主机

准备一台控制器主机和至少一台 Linux 过滤节点；除特别说明外，命令从仓库根目录执行。

节点清单：需内核 ≥ 6.4（x86-64 / arm64），小端架构；需开启 BPF JIT，配备用于 XDP 的专用网卡及 root 权限。内核版本与 sysctl 分别查：`uname -rm`；`sysctl net.core.bpf_jit_enable` 必须为非零。`bpf.xdp_mode: auto` 下 native/generic 的选择由网卡驱动决定，并以实际内核挂载结果为准；`native` 拒绝回退，`generic` 明确请求 SKB。

按 [README](README.zh.md)准备构建工具；修改过滤接口时保持管理通道可达。

## 2. 构建控制器

```bash
./scripts/build-controller.sh all
```

已有完整依赖时，离线构建可先设置 `XDROP_SKIP_NPM_CI=1`；这会跳过 `npm ci`，仍执行 `npm run build`。产物为 `controller/xdrop-controller`，通过 `-tags webui` 嵌入控制台。

控制台和节点的版本号取自 `git describe`。从源码包（没有 `.git` 目录）构建时，请先设置 `XDROP_VERSION`，例如 `export XDROP_VERSION=v3.0.0-rc1`；否则版本号显示为 `unknown`。

## 3. 准备控制器配置

```bash
export STATE_DIR="${STATE_DIR:-$PWD/controller-state}"
export CTL_LISTEN="${CTL_LISTEN:-127.0.0.1:8000}"
mkdir -p "$STATE_DIR"
export XDROP_CONFIG="$STATE_DIR/controller.example.yaml"
export XDROP_RUN_DIR="$STATE_DIR/run"
cp controller/config.example.yaml "$XDROP_CONFIG"
python3 - <<'PY'
import os
from pathlib import Path
p = Path(os.environ['XDROP_CONFIG'])
values = {'listen': os.environ['CTL_LISTEN'],
          'database': str(Path(os.environ['STATE_DIR']) / 'controller.db'),
          'secret_key_file': str(Path(os.environ['STATE_DIR']) / 'master.key')}
import json
lines = []
for line in p.read_text().splitlines():
    key = line.split(':', 1)[0]
    lines.append(key + ': ' + json.dumps(values[key]) if key in values else line)
p.write_text('\n'.join(lines) + '\n')
PY
```

`STATE_DIR` 必须为绝对路径。上述命令只修改样例中的三个有效值。配置没有默认值，未知键会被拒绝。`listen` 保持在回环地址：浏览器通过第 6 节的 HTTPS 反向代理访问控制台，下面的 curl 检查则直接使用本机监听地址。

## 4. 初始化主密钥与管理员

```bash
./controller/xdrop-controller -config "$XDROP_CONFIG" secret-key init
read -r -s -p 'Administrator password: ' ADMIN_PASSWORD; printf '\n'
printf '%s\n' "$ADMIN_PASSWORD" | ./controller/xdrop-controller -config "$XDROP_CONFIG" user add admin
```

密码长度为 10..72 字节。主密钥文件以 0600 权限创建，init 拒绝覆盖已有文件。CLI 创建管理员；备份时配套保存数据库与主密钥。下面使用密码变量但不打印它。

## 5. 启动并检查控制器

```bash
./scripts/manage-controller.sh start
export BASE_URL="http://$CTL_LISTEN"
curl --fail --silent --show-error "$BASE_URL/api/v1/health"
curl --fail --silent --show-error --output /dev/null --write-out '%{http_code}\n' "$BASE_URL/"
```

健康检查返回 `{"status":"ok"}`，静态入口返回 HTTP 200。该健康检查表示控制器 API 可用，不代表节点已经同步。

## 6. 通过 HTTPS 打开控制台

会话 cookie 始终带 `Secure`，浏览器用纯 HTTP 无法保持登录。在回环监听前放一个 HTTPS 反向代理：

- 代理运行在控制器主机上。控制器只信任来自回环地址的 `X-Forwarded-For`，因此只有代理从 `127.0.0.1` 或 `::1` 连入时，审计记录才会显示真实的客户端地址。
- 转发 `/` 下的全部路径：控制台、`/api/v1/` 和事件流 `/api/v1/events`。控制器会为事件流关闭代理缓冲（`X-Accel-Buffering: no`），并每 15 秒发送一次保活，代理用默认超时即可。

nginx（替换域名和证书路径；上游为第 3 节的 `CTL_LISTEN` 地址）：

```nginx
server {
    listen 443 ssl;
    server_name xdrop.example.com;

    ssl_certificate     /etc/ssl/xdrop/fullchain.pem;
    ssl_certificate_key /etc/ssl/xdrop/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

Caddy（域名解析到本机且 80/443 端口可达时，自动申请并续期证书；否则在块内加一行 `tls <cert-file> <key-file>`）：

```
xdrop.example.com {
    reverse_proxy 127.0.0.1:8000
}
```

打开 `https://xdrop.example.com/`，用第 4 节设置的密码以 `admin` 登录。控制台有总览、黑名单、白名单、节点、审计和设置页面。第 9、10 节先写控制台操作，再写命令行操作。

## 7. 命令行登录

```bash
umask 077
printf '%s' "$ADMIN_PASSWORD" | python3 -c 'import json,sys; print(json.dumps({"username":"admin","password":sys.stdin.read()}))' > "$STATE_DIR/login.json"
curl --fail --silent --show-error -D "$STATE_DIR/login.headers" -o "$STATE_DIR/login.response" \
  -H 'Content-Type: application/json' --data-binary @"$STATE_DIR/login.json" "$BASE_URL/api/v1/auth/login"
python3 - "$STATE_DIR" <<'PY'
import sys
from pathlib import Path
from http.cookies import SimpleCookie
d = Path(sys.argv[1]); cookies = SimpleCookie()
for line in (d / 'login.headers').read_text().splitlines():
    if line.lower().startswith('set-cookie:'):
        cookies.load(line.split(':', 1)[1].strip())
token = cookies['xdrop_session'].value
(d / 'session.header').write_text('Cookie: xdrop_session=' + token + '\n')
print('session_length=' + str(len(token)))
PY
curl --fail --silent --show-error -H @"$STATE_DIR/session.header" "$BASE_URL/api/v1/auth/me"
rm -f "$STATE_DIR/login.json" "$STATE_DIR/login.headers"
unset ADMIN_PASSWORD
./scripts/manage-controller.sh status
```

只读响应标识 `kind: user`、`name: admin`、`role: admin`。妥善保护 `session.header`，使用完毕后删除。第 9、10 节的命令行操作会用到它。

## 8. 构建并配置节点

在 Linux 节点运行以下命令，然后编辑配置副本再启动。必须替换 `CHANGE_ME_NODE_KEY`：否则校验报告 `auth.node_api_key still contains a placeholder value ...; generate a real key before starting` 并退出。将 `server.interface` 设为过滤接口，保持密钥非空。

`bpf.rate_limit_divisor` 接受 0（在线 CPU 数，读取失败时回退到 possible CPU 数）或 1..4096 的整数覆盖值。X7：实际收包 CPU 集合必须固定且不多于覆盖值，除数过小会放大规则总上限。例如，除数为一时保持单收包队列、固定中断亲和且不启用 RPS。

```bash
./scripts/build-node.sh all
unset XDROP_CONFIG XDROP_RUN_DIR
cp node/config.example.yaml node/config.yaml
# Edit node/config.yaml before continuing.
sudo ./scripts/manage-node.sh start
curl --fail --silent --show-error http://127.0.0.1:8080/
curl --fail --silent --show-error http://127.0.0.1:8080/api/v1/health
```

欢迎响应报告 `sync_protocol: 11`；初始健康状态为 `degraded`，原因为 `awaiting_full_sync`。节点 API 请求不会发起到控制器的反向连接。请在主机或网络边界限制节点管理监听的访问范围。

## 9. 登记节点

控制台：设置 → 节点 → 添加节点。填入名称、节点地址（例如 `http://192.0.2.10:8080`）和与 `auth.node_api_key` 相同的节点密钥。保存前可点「测试连接」检查可达、兼容和密钥。暂时连不上的节点保存后显示为离线，节点应答后恢复。

命令行：

```bash
read -r -s -p 'Node API key: ' NODE_API_KEY; printf '\n'
printf '%s' "$NODE_API_KEY" | python3 -c 'import json,sys; print(json.dumps({"name":"node-01","base_url":"http://192.0.2.10:8080","api_key":sys.stdin.read()}))' > "$STATE_DIR/node.json"
curl --fail --silent --show-error -H @"$STATE_DIR/session.header" -H 'Content-Type: application/json' \
  --data-binary @"$STATE_DIR/node.json" "$BASE_URL/api/v1/nodes"
rm -f "$STATE_DIR/node.json"
unset NODE_API_KEY
curl --fail --silent --show-error -H @"$STATE_DIR/session.header" "$BASE_URL/api/v1/nodes"
```

将文档地址 `192.0.2.10` 换为实际节点地址，输入与 `auth.node_api_key` 相同的密钥。登记需要管理员会话。等待节点在线、协议兼容且健康，规则与白名单两侧都已恢复；即使内容为空，两侧也分别需要完整快照。控制器不会返回节点密钥。

## 10. 创建并确认第一条规则

控制台：黑名单 → 新建规则。命令行：

```bash
curl --fail --silent --show-error -H @"$STATE_DIR/session.header" -H 'Content-Type: application/json' \
  --data '{"dst_ip":"192.0.2.20","protocol":"udp","dst_port":9999,"action":"drop","expires_in":"10m","comment":"first rule"}' \
  "$BASE_URL/api/v1/rules" > "$STATE_DIR/rule.json"
python3 - "$STATE_DIR/rule.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
print('/api/v1/rules/' + r['id'] + '/delivery?gen=' + str(r['gen']) + '&epoch=' + r['epoch'])
PY
```

创建前应按测试流量选择目标地址和端口。用 `curl -H @"$STATE_DIR/session.header" "$BASE_URL<printed-path>"` 读取打印的下发路径；等待目标节点为 `confirmed`，同时检查创建响应的 `enabled`。创建成功不是实际丢包测量。让匹配的测试流量经过该节点并检查规则计数器；没有匹配流量时计数可能保持零。通过 `DELETE /api/v1/rules/{id}` 删除规则，或等待明确设置的有效期结束。

## 11. 停止控制器

```bash
./scripts/manage-controller.sh stop
./scripts/manage-controller.sh status
```

`stop` 发送 SIGTERM，最多等待 30 秒且不发送 SIGKILL；监督进程记录实际退出码。`status` 在运行时返回 0、已停止时返回 3。节点使用 `sudo ./scripts/manage-node.sh stop` 停止；`restart` 保留 link pin，但每次 agent 启动仍需经历策略恢复阶段。备份与恢复见组件指南。

`auth.node_api_key` 必填；空值（含全空白）或占位符拒绝启动，启动前须生成真实密钥。出处：[`config.Config.Validate`](node/agent/config/config.go)。
