# Getting started

## 1. Prepare the hosts

Use one controller host and at least one Linux filtering node. Run commands from the repository root unless stated otherwise.

Node checklist: kernel ≥ 6.4 (x86-64 / arm64), little-endian, BPF JIT enabled, dedicated NIC and root access. Check the kernel version and sysctl separately: `uname -rm`; `sysctl net.core.bpf_jit_enable` must be non-zero. In `bpf.xdp_mode: auto`, native/generic selection is decided by the NIC driver and kernel attachment result; `native` refuses fallback, while `generic` explicitly requests SKB.

Use the build requirements in [README](README.md). Keep management traffic reachable while changing the filtering interface.

## 2. Build the controller

```bash
./scripts/build-controller.sh all
```

For an offline build with dependencies already installed, export `XDROP_SKIP_NPM_CI=1` before that command; it skips `npm ci` and still runs `npm run build`. The executable is `controller/xdrop-controller` and embeds the console with `-tags webui`.

The console and node builds take their version from `git describe`. When building from a source archive (no `.git` directory), set `XDROP_VERSION` first, for example `export XDROP_VERSION=v3.0.0-rc1`; otherwise the version is reported as `unknown`.

## 3. Prepare controller configuration

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

Choose an absolute `STATE_DIR`. Only the three active example values are changed above. There are no default configuration values; unknown keys are rejected. Keep `listen` on loopback: browsers reach the console through the HTTPS reverse proxy in section 6, while the curl checks below use the local listener directly.

## 4. Initialize the master key and administrator

```bash
./controller/xdrop-controller -config "$XDROP_CONFIG" secret-key init
read -r -s -p 'Administrator password: ' ADMIN_PASSWORD; printf '\n'
printf '%s\n' "$ADMIN_PASSWORD" | ./controller/xdrop-controller -config "$XDROP_CONFIG" user add admin
```

Use a password of 10..72 bytes. The master file is created with mode 0600 and is never overwritten by init. The CLI creates an administrator; keep the database and master key together when backing up. The password variable is used below without printing it.

## 5. Start and check the controller

```bash
./scripts/manage-controller.sh start
export BASE_URL="http://$CTL_LISTEN"
curl --fail --silent --show-error "$BASE_URL/api/v1/health"
curl --fail --silent --show-error --output /dev/null --write-out '%{http_code}\n' "$BASE_URL/"
```

Health returns `{"status":"ok"}`; the static entry returns HTTP 200. This health check reports controller API availability, not node synchronization.

## 6. Open the console over HTTPS

The session cookie is always `Secure`, so a browser does not stay signed in over plain HTTP. Put an HTTPS reverse proxy in front of the loopback listener:

- Run the proxy on the controller host. The controller trusts `X-Forwarded-For` only from loopback, so audit records show the real client address only when the proxy connects from `127.0.0.1` or `::1`.
- Rate-limit sign-in at the proxy. The controller delays repeated failures for each user name and never locks an account, but it does not limit attempts per client, including attempts with user names that do not exist. The nginx example below allows 10 sign-in requests per minute per client address, with a burst of 5.
- Forward everything under `/`: the console, `/api/v1/` and the event stream `/api/v1/events`. The controller turns off proxy buffering for the event stream (`X-Accel-Buffering: no`) and sends a keepalive every 15 seconds, so default proxy timeouts are enough.

nginx (replace the server name and certificate paths; the upstream is the `CTL_LISTEN` address from section 3):

```nginx
# limit_req_zone belongs in the http context; files in /etc/nginx/conf.d/ are already inside it.
limit_req_zone $binary_remote_addr zone=xdrop_login:10m rate=10r/m;

server {
    listen 443 ssl;
    server_name xdrop.example.com;

    ssl_certificate     /etc/ssl/xdrop/fullchain.pem;
    ssl_certificate_key /etc/ssl/xdrop/privkey.pem;

    location = /api/v1/auth/login {
        limit_req zone=xdrop_login burst=5 nodelay;
        limit_req_status 429;
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
    }
}
```

Caddy (obtains and renews a certificate automatically when the name resolves to this host and ports 80/443 are reachable; otherwise add `tls <cert-file> <key-file>` inside the block). The standard Caddy build has no request rate limiter, so limit `POST /api/v1/auth/login` with a rate-limit module or a firewall rule, or use nginx:

```
xdrop.example.com {
    reverse_proxy 127.0.0.1:8000
}
```

Open `https://xdrop.example.com/` and sign in as `admin` with the password from section 4. The console has Overview, Blocklist, Allowlist, Nodes, Audit and Settings pages. Sections 9 and 10 give the console steps first and the command-line steps after them.

## 7. Log in from the command line

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

The read-only reply identifies `kind: user`, `name: admin`, `role: admin`. Keep `session.header` private and delete it after use. The command-line steps in sections 9 and 10 use it.

## 8. Build and configure a node

On the Linux node, run the commands below, then edit the copied configuration before starting. Replace `CHANGE_ME_NODE_KEY`: otherwise validation reports `auth.node_api_key still contains a placeholder value ...; generate a real key before starting` and the agent exits. Set `server.interface` to the intended filtering interface; keep the key nonempty.

`bpf.rate_limit_divisor` accepts 0 (online CPU count, possible CPU count on read failure) or an integer override 1..4096. X7: the receiving CPU set must be fixed and no larger than the override; a divisor that is too small amplifies the aggregate rule limit. For example, keep one RX queue, fixed IRQ affinity and no RPS when using a divisor of one.

```bash
./scripts/build-node.sh all
unset XDROP_CONFIG XDROP_RUN_DIR
cp node/config.example.yaml node/config.yaml
# Edit node/config.yaml before continuing.
sudo ./scripts/manage-node.sh start
curl --fail --silent --show-error http://127.0.0.1:8080/
curl --fail --silent --show-error http://127.0.0.1:8080/api/v1/health
```

The welcome response reports `sync_protocol: 11`; health is initially `degraded` with `reason: awaiting_full_sync`. Node API requests do not initiate a connection back to the controller. Restrict access to the node management listener at the host/network boundary.

## 9. Register the node

In the console: Settings → Nodes → Add. Enter a name, the node address (for example `http://192.0.2.10:8080`) and the same key as `auth.node_api_key`. Test checks reachability, compatibility and the key before you save. A node saved while it cannot be reached shows as Offline until it answers.

From the command line:

```bash
read -r -s -p 'Node API key: ' NODE_API_KEY; printf '\n'
printf '%s' "$NODE_API_KEY" | python3 -c 'import json,sys; print(json.dumps({"name":"node-01","base_url":"http://192.0.2.10:8080","api_key":sys.stdin.read()}))' > "$STATE_DIR/node.json"
curl --fail --silent --show-error -H @"$STATE_DIR/session.header" -H 'Content-Type: application/json' \
  --data-binary @"$STATE_DIR/node.json" "$BASE_URL/api/v1/nodes"
rm -f "$STATE_DIR/node.json"
unset NODE_API_KEY
curl --fail --silent --show-error -H @"$STATE_DIR/session.header" "$BASE_URL/api/v1/nodes"
```

Replace the documentation address `192.0.2.10` with your node address and enter the same key as `auth.node_api_key`. Registration requires an administrator session. Wait for the node to be online, compatible and healthy, with both rules and whitelist sides recovered; an empty full snapshot is still required on each side. Node keys are never returned by the controller.

## 10. Create and confirm the first rule

In the console: Blocklist → Create. From the command line:

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

Choose a test destination and port appropriate to your traffic before creating the rule. Read the printed delivery path using `curl -H @"$STATE_DIR/session.header" "$BASE_URL<printed-path>"`; wait until the target node reports `confirmed`, and also inspect `enabled` in the create reply. A successful create is not a packet-drop measurement. Send matching test traffic through that node and inspect its rule counters; no matching traffic means counters may stay zero. Delete the rule through `DELETE /api/v1/rules/{id}` or let its explicit expiry elapse.

## 11. Stop the controller

```bash
./scripts/manage-controller.sh stop
./scripts/manage-controller.sh status
```

`stop` sends SIGTERM and waits up to 30 seconds without SIGKILL; the supervisor records the process exit code. `status` returns 0 when running and 3 when stopped. Stop the node with `sudo ./scripts/manage-node.sh stop`; use `restart` to retain link pins, but expect a policy recovery interval after every agent start. See the component guides for backups and recovery.

`auth.node_api_key` is required. Empty values (including whitespace) or placeholders reject startup; generate a real key before starting. Source: [`config.Config.Validate`](node/agent/config/config.go).
