# 控制器 API · c5b-1

本文件是新合同（G1）。controller/API.zh.md 是 README 链接的对外摘要，描述的是同一套 v3 接口；TestCtlCut3API/API-doc 对拍中英两种语言、两份文档的路由表（含权限、成功码两列）与错误码表。API 路径位于 /api/v1，除事件流与审计导出外采用 JSON。规则与白名单写接口入库即回，不等节点（G3）。xSight 跨仓适配后续另立项，本刀只交合同（G9）。

用户以密码和服务端会话认证；机器使用具名凭证。用户有 admin（管理员）与 operator（运维）两种角色；“仅 UI”含两者，“仅管理员”只接受 admin 会话，否则 403 admin_required。schema v4 将 v3 既有用户全部升为 admin；CLI user add 也建 admin。只有健康与登录公开。

## 路由

| 方法 | 路径 | 谁可调 | 成功码 |
|---|---|---|---|
| GET | /api/v1/health | 免身份 | 200 |
| GET | /api/v1/events | 仅 UI | 200 |
| POST | /api/v1/rules | UI / 机器 | 201 / 200 |
| POST | /api/v1/rules/batch | UI / 机器 | 200 |
| GET | /api/v1/rules | UI / 机器 | 200 |
| GET | /api/v1/rules/{id} | UI / 机器 | 200 |
| GET | /api/v1/rules/{id}/delivery | UI / 机器 | 200 |
| PATCH | /api/v1/rules/{id} | 仅 UI | 200 |
| PUT | /api/v1/rules/{id}/enabled | 仅 UI | 200 |
| DELETE | /api/v1/rules/{id} | UI / 机器 | 204 |
| GET | /api/v1/whitelist | UI / 机器 | 200 |
| POST | /api/v1/whitelist | 仅 UI | 201 / 200 |
| DELETE | /api/v1/whitelist/{id} | 仅 UI | 204 |
| GET | /api/v1/capacity | UI / 机器 | 200 |
| GET | /api/v1/system | UI / 机器 | 200 |
| GET | /api/v1/traffic/history | UI / 机器 | 200 |
| GET | /api/v1/traffic/top | UI / 机器 | 200 |
| GET | /api/v1/nodes | UI / 机器 | 200 |
| POST | /api/v1/nodes | admin | 201 |
| PATCH | /api/v1/nodes/{name} | admin | 200 |
| DELETE | /api/v1/nodes/{name} | admin | 204 |
| POST | /api/v1/nodes/{name}/test | admin | 200 |
| POST | /api/v1/nodes/test | admin | 200 |
| POST | /api/v1/nodes/{name}/sync | 仅 UI | 202 |
| POST | /api/v1/nodes/{name}/reconcile | 仅 UI | 202 |
| POST | /api/v1/auth/login | 免身份 | 200 |
| POST | /api/v1/auth/logout | 仅 UI | 204 |
| GET | /api/v1/auth/me | UI / 机器 | 200 |
| PUT | /api/v1/auth/me/password | 仅 UI | 204 |
| GET | /api/v1/users | 仅 UI | 200 |
| POST | /api/v1/users | 仅管理员 | 201 |
| DELETE | /api/v1/users/{name} | 仅管理员 | 204 |
| PUT | /api/v1/users/{name}/password | 仅管理员 | 204 |
| GET | /api/v1/credentials | 仅管理员 | 200 |
| POST | /api/v1/credentials | 仅管理员 | 201 |
| DELETE | /api/v1/credentials/{id} | 仅管理员 | 204 |
| GET | /api/v1/audit | 仅 UI | 200 |
| GET | /api/v1/audit/export | 仅管理员 | 200 |
| GET | /api/v1/settings | 仅 UI | 200 |
| PUT | /api/v1/settings | 仅管理员 | 200 |
| PUT | /api/v1/users/{name}/role | 仅管理员 | 204 |
| GET | /api/v1/auth/me/prefs | 仅 UI | 200 |
| PUT | /api/v1/auth/me/prefs | 仅 UI | 204 |
| GET | /api/v1/templates | 仅 UI | 200 |
| POST | /api/v1/templates | 仅管理员 | 201 |
| PUT | /api/v1/templates/{id} | 仅管理员 | 200 |
| DELETE | /api/v1/templates/{id} | 仅管理员 | 204 |

## 事件与静态入口

`GET /events` 使用 `ui` 权限（两种界面角色均可）；机器凭证返回 403，未认证返回 401。实际路径为 `/api/v1/events`。声明请求体（含 chunked）返回 400 bad_request。响应头为 `Content-Type: text/event-stream`、`Cache-Control: no-cache`、`X-Accel-Buffering: no`；首包为 `retry: 3000` 加空行；事件为 `event: <类>` 与 `data: <JSON>` 加空行。

| 类 | JSON |
|---|---|
| rules | `{seq,gen}` |
| nodes | `{epoch,nodes,reconcile}` |
| traffic | `{overview:{dropped_pps,passed_pps,dropped_bytes_ps,passed_bytes_ps,nodes_online,nodes_total},top}` |

seq 为进程内成功改动规则 / 白名单行的提交计数，包括期限续期，以及释放认领引起的期限变化；批次部分成功只加一次。失败、零行、纯审计、只改认领不增加；释放最后认领并删规则会增加。gen 保持节点同步语义，续期不增加。
epoch / nodes 与 GET /nodes 完整回包同形。reconcile 按节点名给出 `{rules,whitelist}`，取同一 Status 快照，投影与 /system 的 `{last_at,result}` 相同。overview 速率为该快照各节点 Rates 求和，缺失按零；节点总数 / 在线数按合并后的节点列表计算，含库有 orch 无的行。top 与 GET /traffic/top?n=5 同形、共用缓存。Top 占比分母为规则 Hits 速率之和，overview dropped 为节点 Stats 合计；两者口径与缓存采样不同。

每次连接前三条依次为 rules、nodes、traffic 全量快照。热缓存是 hub 最近一拍的值，至多落后一拍；冷连接等下一拍现取。订阅者归零清空三类缓存；重连重新收全量，无重放缓冲、事件 ID 或 Last-Event-ID 续传。每订阅者每类只保留一个最新待发值；已取出正在写的值属于在途发送。

| 来源 | 采样 | 事件 | hub 检查 | 新鲜度 |
|---|---|---|---|---|
| 在线 / 同步 / 告警 | Health 2 s / worker 即时 | nodes | 1 s | 下一拍；离线判定需连续两次探测失败 |
| 包 / 字节速率 | Stats 5 s | traffic | 1 s | 新样本在一个 hub 周期内推出 |
| 容量、CPU、内存 | Stats 5 s | nodes | 1 s | 新样本在一个 hub 周期内推出 |
| Top 5 | Hits 5 s | traffic | 1 s | 新样本在一个 hub 周期内推出；新命中另晚一拍 |
| 规则 / 白名单 / 续期 | 提交即时 | rules | 1 s | 下一拍 |
| 对账 | 15 min，可配置 | nodes | 1 s | 完成后的下一拍 |

5 s 是刷新粒度；数字最大年龄为 5 s + 一个 hub 周期 + 采样请求耗时。traffic 只在 Top 完整 Key（含库外节点集合）变化时推送，overview 单独变化等下一统计周期。每拍至多一次 Status，与订阅者数无关；无订阅者不取数据快照。

每 15 s 发 `: ping` 加空行。hub 每拍复核各流身份，handler 每条事件 / 心跳写前再次复核。注销只断本会话；改密（含另一 CLI 进程）、删用户、会话时长缩短和自然到期也会断开失效流。关流时限为一个 hub 周期加复核耗时；认证与取数耗时计入整拍。吊销提交前已复核成功的发送属于获准在途发送；提交后才开始的复核必须失败。
普通写截止为 10 s；关流同时取消上下文并立即到期写截止。停机先关全部流并等待 hub 退出，再 HTTP 排空、停 manager、关库。关闭态的新连接返回 200、只写 retry 后结束，写截止 1 s；拒绝有体请求也使用 1 s 写截止。
任一快照读取失败，该拍不发布任何类别，关闭当前全部流并清空三类缓存，hub 继续工作。失败期间新连接照常收到 retry，下一失败拍关闭；恢复后新连接收到当前快照。每失败拍只记录 `hub snapshot read failed; closed_streams=<实际关闭数>`，不增加错误事件或拍内读库重试。

单二进制嵌入 `controller/core/webui/dist`，占位页标题为「xdrop console」、正文「前端未构建」。`/api/` 开头的路径交原鉴权 API，保留 JSON 404 行为；其余路径无须认证，存在的文件直接服务，不存在且无扩展名回退 index.html，有扩展名则返回纯文本 404。静态只接受 GET / HEAD，否则 405；所有静态响应都有 `X-Content-Type-Options: nosniff` 与 `X-Frame-Options: DENY`，index.html（含 SPA 回退）另有 `Cache-Control: no-cache`。组合入口不限制 API 原有写方法。

## 身份、解码与错误

会话 cookie `xdrop_session` 固定 `HttpOnly; Secure; SameSite=Strict; Path=/api/v1`，Max-Age 为当前 session_hours × 3600。服务端按「建立时间 + 当前时长」验票，默认 24 h 绝对有效期、不设闲置超时；设置修改即时影响存量票。登出删除票并按相同属性、Max-Age=-1 清 cookie。改密与删用户使其全部会话作废。

单条请求体最多 1 MiB，批量最多 8 MiB。未知字段、类型错误、尾随数据均为 bad_request。RulePatch 字段 null 等于省略，不等于清除。规则校验唯一出口是 rules 服务层。

错误统一为 `{"code":"invalid_rule","message":"...","field":"dst_port"}`，可选字段为 field、rule_id、rule_ids、table。冲突点名占位 rule_id；条件容量和前缀重叠点名 rule_ids；table_full 点名 logical_id / sv4 / dv4 / sv6 / dv6 / blacklist / cidr_blacklist / cond / cidr_cond / whitelist / logical_state / templates。internal 的 message 固定为 `internal error`，底层消息只进服务端日志；批量项内也采用同一形状和脱敏。

| code | HTTP |
|---|---|
| invalid_rule | 400 |
| empty_value | 400 |
| invalid_expires_in | 400 |
| mapped_ipv6 | 400 |
| address_family_mismatch | 400 |
| bad_request | 400 |
| batch_too_large | 400 |
| unauthenticated | 401 |
| forbidden | 403 |
| admin_required | 403 |
| not_found | 404 |
| node_not_found | 404 |
| route_not_found | 404 |
| method_not_allowed | 405 |
| rule_conflict | 409 |
| condition_capacity | 409 |
| cidr_overlap | 409 |
| table_full | 409 |
| gen_epoch_mismatch | 409 |
| internal | 500 |
| invalid_credentials | 401 |
| login_throttled | 429 |
| invalid_field | 400 |
| user_exists | 409 |
| user_not_found | 404 |
| last_user | 409 |
| last_admin | 409 |
| credential_not_found | 404 |

## 规则写入与读取

POST /rules 体 = RulePatch 加顶层可选 claim_ref。RulePatch 字段为：
`src_ip, dst_ip, src_cidr, dst_cidr, src_port, dst_port, protocol, ttl, dscp, icmp_type, icmp_code, fragment, pkt_len, tcp_flags, match_anomaly, action, rate_limit, enabled, comment, expires_in`。
端口、速率与异常掩码为整数，enabled 为布尔，其余为字符串。默认 action=drop、protocol=all、enabled=true；drop 的速率归零，rate_limit 动作要求正速率。精确地址与 CIDR 不混用；通配地址规范化为空值，CIDR 规范化为网络地址。

规则 DTO 包含全部规范匹配字段，加 id、logical_id、kind、group_key、cond_key、enabled、comment、created_at、updated_at、expires_at、created_by、updated_by。缺省条件及永久期限为 null；时间为 RFC 3339 UTC。id 为不可变且路径安全的 rule_ + 32 位随机十六进制（G6）；logical_id 为非零、不可变、永不复用整数。认领明细留刀五。

POST 成功回包为平铺的规则 DTO，加 existing、gen、epoch、nodes；nodes 是缓存摘要，每项 name、online、incompatible、rules_state。新建返回 201；同规范身份同动作/速率返回 200 existing=true 和库存行。重复推送在认领事务内续到 max(旧期限, 新期限)，永久视为最晚，任一方永久则结果永久。续期和单纯认领不通知节点，不改变 gen；启用状态、备注、匹配不变。**停用同配置再建不自动启用，看回包 enabled。**同身份异动作/速率返回 rule_conflict。

expires_in 是显式正 Go duration，例如 2h；创建不带则永久（G8）。PATCH 省略/null 保留旧值，`""` 清除字符串字段，expires_in 的空串清为永久；创建显式空串除 comment 外拒绝。PATCH 返回规则 DTO。PUT /enabled 必须提供非 null 布尔，返回 `{"enabled":false}`。这两种写操作不回 gen。

批量体为 `{"claim_ref":"incident","items":[RulePatch,...]}`，1..500 项，0 或超过 500 项整请求返回 400 batch_too_large，一条不写；调用方须按每片 ≤ 500 项分片顺序重发。逐项独立事务，允许部分成功。回包为 `{"epoch":"...","results":[{"index":0,"rule":规则DTO,"existing":false,"gen":1},{"index":1,"error":错误体}]}`。每个成功项必须含 gen（含 0），没有整批 gen；通知后在锁内按各项当前组键回填。

POST /rules/batch?validate=1 复用提交的解码、500 上限、规范化、身份/冲突、到期投影与准入，规则、认领、审计、高水位均不写，也不通知节点。每项看到本批此前成功项的最终投影；同动作/速率即 existing（跨认领方也一样），不同即 rule_conflict。到期取 max，永久最晚，连续 existing 同样累计。容量与逻辑 ID 耗尽计入前项模拟消耗；logical_id 仅是模拟结果，不代表已持久分配。

只校验有两类 ID 合同例外：新建成功及命中批内新项的 existing 均回 rule.id=""（空串表示尚未分配）并省略 gen；库内 existing 保留真实 ID，也省略 gen。错误的 rule_id/rule_ids 指向本批项时回 `batch:<原始零基 index>`，指向库内规则仍是真实 ID；任何临时内部 ID 都不外露。
真提交遇 condition_capacity/cidr_overlap 时，单条新建的 rule_ids 去掉被拒候选自身；批量真提交以 `batch:<原始零基 index>` 代替该候选，同批此前已提交项保留真实 ID。更新与启停错误保留已入库候选的 ID。

UI 建规则带 (ui, 空认领号)；机器带 (cred:name, claim_ref)，未带认领号为空串。同一三元组幂等，不同名字/认领号加一份（G4）。机器 DELETE 的 claim_ref 放 query，只撤自己的份额，最后一份撤掉才删；UI DELETE 强删全部。释放非最后一份认领时，规则期限重算为剩余认领中最晚的期限；剩余认领里有永久的，规则保持永久。不存在或已撤同样返回 204（G5）。启停、删除与白名单删除不回 gen，可看 /nodes；机器撤认领没有逐条下发查询。

## 分页与白名单

规则、白名单列表均回 `{"items":[DTO,...],"next_after":null}`。limit 缺省 100，范围 1..1000。规则 after 为非负 logical_id，缺省 0，按 logical_id 升序；尚有下一页时 next_after 为本页最后 logical_id，否则 null。翻页期间新增规则 logical_id 更大，可出现在后页。写入完成后的新读立即可见，各请求不共享长事务。
GET /rules 可带 `q`：去首尾空白后依次判为 rule_ 加 32 位小写十六进制规则号、含 `/` 的网段、否则 IP；IP 搜精确源/目标地址及覆盖它的网段，网段搜规范化网络地址后只含同族的本网段、其内网段和 IP，不含更短的覆盖网段。空 q 视同不带；映射 IPv6 与通配 IP 非法，两族 `/0` 网段合法。
可选 `state=drop|rate_limit|disabled` 分别选启用的丢弃、启用的限速、全部停用规则，不带则全部；筛选后仍按 logical_id 升序，确有后续命中行才回非 null 的 next_after。
可选 `counts=1` 增加 `counts:{all,drop,rate_limit,disabled}`，按当前 q 统计、忽略 state 和分页，与 items 来自同一快照；不带则无 counts 键。非法 q/state/counts 统一回 400 bad_request 及对应 field；三参数都不带时回包不变，白名单查询不变。

白名单 after 为字符串 ID，缺省空串，按 id 升序。随机 ID 分页只保证游标无重复和固定初始集合不遗漏，不保证纳入翻页期间新增项。POST 字段为 src_ip、dst_ip、src_port、dst_port、protocol、comment；DTO 加 id、created_at、created_by。POST 返回平铺 DTO 加 existing，新建 201 / 已有 200；DELETE 幂等 204。白名单没有逐项 gen。

## 条件语义（V4）

六键为 ttl（0..255）、dscp（0..63）、icmp_type（0..255）、icmp_code（0..255）、pkt_len（0..65535）、fragment。数值表达式支持无符号十进制单值、闭区间、逗号并集与整个表达式前的一个补集符号 !，如 `64,128-130`、`!0-31`。除单个 0 外不接受前导零；可用 ASCII 空格/tab。拒绝空集、全集、倒序区间、矛盾组合；规范化排序并合并区间。ICMP 两键要求 icmp/icmpv6。fragment 要有 IPv4 锚点，支持不区分大小写的 nofrag、first、middle、last、frag、nonfirst，逗号并集和前置 !；frag=first/middle/last，nonfirst=middle/last。

同一规范五元组下，启用的多候选按“更具体的赢”，平手按 logical_id 创建顺序。每组最多四个物理候选，一条表达式可能展开为多候选；上限错误点名已有规则，不静默篡改条件。

match_anomaly 在 0x0F 内任一位匹配：0x01 bad fragment，0x02 invalid，**0x04 长度不一致**，**0x08 IPv4 TCP 分片 offset 恰为 1（8 字节）**。须有有界地址/前缀目标，IPv6 拒绝 0x01/0x08。不同异常条件仍为独立规则。异常 + 端口照收，但有 D2 例外：match_anomaly 恰为 0x08（单独此位），或 fragment 的允许集只含非首片时，不能同时约束端口、TCP flags 或 ICMP，否则返回 invalid_rule（D2）。其他异常掩码，包括 0x04、0x0c（0x08 与其他位组合），可与端口组合，除非 fragment 条件本身触发 D2。drop 与 rate_limit 均接受；tcp_flags 如 SYN,!ACK 要求 TCP，在不触发 D2 时可与异常共存。映射 IPv6 返回 mapped_ipv6 并提示改用 IPv4，不自动改写；源目的混族返回 address_family_mismatch。

## 节点与下发状态

GET /nodes 返回 epoch 和 nodes。每个节点新增 overload（数组，每项 dim/limit/used）；其余包含 name、online、incompatible、rules、whitelist、health_at、health、stats_at、stats、rates。两侧字段为 state/reason/since/confirmed_gen/confirmable/rejected；拒收仅 key/id/code/error/rule_ids，排除 Fingerprint 和密钥。health 含 status/rules_synced/whitelist_synced；统计与速率只来自采样缓存，HTTP 不现场扇出。sync/reconcile 已知名回 202 `{"status":"accepted"}`，未知名回 node_not_found。公开 GET /health 只回 `{"status":"ok"}`。

GET /rules/{id}/delivery 必须带回执 gen 与 epoch。epoch 不符一律 409 gen_epoch_mismatch。gen 是进程内按组水位，重启换 16 字节随机 hex epoch，启动后没变过的组 gen=0；可由 GET /nodes 取得 epoch，或重写取得新回执。keyGen 保留自启动以来变过的不同组键，不删除；白名单或无关组变化不会推高本规则回执。

返回 rule_id、请求 gen、target_gen、epoch、nodes（每项 name/state，可选 code/error）。持服务写锁读取当前规则与当前组 target_gen，并在同一锁内取一次节点 Status 快照；阈值 T=max(请求 gen,target_gen)。不存在返回 404。逐节点按以下顺序：
1. 停用规则为 disabled；节点离线为 offline；版本不兼容为 incompatible。
2. 超载节点先返回 overloaded。Rules.Confirmable 为假或缓存健康 RulesSynced 为假，返回 pending。Confirmable 同时要求无需全量、已完成过全量、无未恢复的健康异常且未超载。
3. 拒收项 Key 等于当前 GroupKey、ID 等于当前规则 ID，或 RuleIDs 含该 ID，返回 rejected 并附 code/error。
4. ConfirmedGen ≥ T 返回 confirmed，否则 pending。

**confirmed 表示控制器对该规则当前目标的推送获节点成功回执，且最近健康采样为已同步，是控制器侧确认水位。**这不是实时读回，两次对账之间的节点漂移由对账发现。节点重启到下次健康采样（默认 2s）间可能仍报旧 confirmed；全量成功到下次健康采样间保守报 pending。锁内 Status 深拷贝可能短暂阻塞写入；HTTP 读池没有并发连接数上限，两项开销由 lab 记录。

## 部署

命令：`xdrop-controller -config /absolute/path/xdrop-controller.example.yaml`。必填 listen（host:port）、database（绝对路径）、secret_key_file（绝对路径）。未知键、重复键、多文档及空/不可读配置文件均拒绝。主密钥文件权限必须为 0600，内容为恰好 32 字节随机数的 base64；失败点名 secret_key_file，不输出内容。任何形态的 nodes 键均拒绝，固定消息为 `nodes moved to database; use the web UI or "node add"`。

节点名必须唯一。所有节点操作都以原有报错拒绝空名与含 `/` 的名称；创建另须遵守下方用户名规则，更新与删除接受已存名称。

启动序：加载配置 → 开库 → Prepare（列全违规并拒启动）→ 读主密钥 → 读库并解密节点 → 读设置 → 构造 manager/service → Prime 复用 Prepare 账本并接上 Limits → 启动 manager → API → HTTP。SIGINT/SIGTERM：关闭事件 hub 与全部流 → HTTP Shutdown 最多 10s 排空 → manager Stop 并等待 → db.Close；错误记日志并继续清理。Shutdown 和 Close 均无错才退出 0；中途失败逆序清理。Shutdown 超时是异常退出，不证明排空或单文件。

库目录必须可写，备份拷 `<db>*`，崩溃后连 WAL 一起拷；长读可使 WAL 增至约库大小，预留磁盘。正常成功停止后为单个库文件。访问白名单在基础设施层。 应用层只记录来源 IP、不拦。



## 容量与系统

GET /capacity 与 GET /system 均允许 UI / 机器调用，数据来自内存账本与采样缓存，不现场扇出到节点。

| 维度名（与节点键相同） | 启用规则口径 | 内置上限 | table_full.table |
|---|---|---|---|
| blacklist | exact 不同 group_key 数 | 500000 | blacklist |
| cidr_blacklist | cidr 不同 group_key 数 | 500000 | cidr_blacklist |
| cond | exact 组内启用成员 ≥ 2 或任一有条件的组数 | 500000 | cond |
| cidr_cond | cidr 同上 | 500000 | cidr_cond |
| whitelist | 白名单条目数 | 50000 | whitelist |
| sv4_cidr_trie | 源 IPv4 不同前缀数 | 50000 | sv4 |
| dv4_cidr_trie | 目的 IPv4 不同前缀数 | 50000 | dv4 |
| sv6_cidr_trie | 源 IPv6 不同前缀数 | 50000 | sv6 |
| dv6_cidr_trie | 目的 IPv6 不同前缀数 | 50000 | dv6 |
| logical_state | 启用规则条数（目标口径） | 1000000 | logical_state |

已到期但尚未清理的启用规则照计，清理周期 30 s；停用只计 rules.total。每键物理候选最多 4，full_keys=4 候选的键数，near_keys=3 候选的键数。logical_id 仍指逻辑 ID 空间耗尽，与 logical_state 占用不同。节点下发拒收中的前缀树名仍为节点键；例如 sv4 ↔ sv4_cidr_trie。新增全局维度满时没有可点名的 rule_ids。

每个未超载节点逐维取合法正整数 limit，否则回退 builtin；不兼容/未上报/缺键回退，离线保留最后缓存。逐节点有效上限取最小值并点名来源；全部节点超载或无节点时回退 builtin。节点 used 不用于准入。只有占用增量 > 0 且结果超过 admission_limit 才拒收；备注、停用、删除等中性/缩减写放行。批量逐项看到此前已提交结果。

dimensions 每项为 name/used/limit/admission_limit/limit_source/free/ratio/exhausted。limit 是节点最紧原始上限；仅 logical_state 的 admission_limit=limit−预留（默认 1000），其余同 limit。free=admission_limit−used，为有符号数；exhausted=(free≤0)。admission_limit>0 时 ratio=used/admission_limit，否则为 null。tightest 含 name/limit_source/free/ratio/exhausted：先耗尽者按 free 升序，耗尽且同 free 时按维度表序（不比较 ratio）；未耗尽按 ratio 降序，同值按表序。另有 candidates{limit,full_keys,near_keys}、rules{enabled,total}、overloaded_nodes[]{name,dims[]{name,limit,used}}。一次请求读取账本一次、Limits 一次。

任一有效原始上限小于账本占用即超载：两侧 overloaded/capacity，停止写入与对账，Confirmable=false，脏键保留，超载节点不参与最紧者。能装下后 capacity_recovered，两侧全量重推。采到新 limit 后的 worker 重判才更新状态；上限变更与下发间的窗口仍可能被节点拒收，回码不统一，下一次采样后的重判兜底。超载不因 full/dirty 空转，按 CheckInterval 唤醒。

预留只保证节点付债后残留 pending + 本提交退出 owners ≤ 1000；不防同一窗口删加超过预留或回收失败积债超过余量。节点可进入 capacity_retry，三次后按 CheckInterval 全量重试，直到并集可准入。Prepare 始终按内置原始上限检查，超载恢复也不减预留；若未来节点允许库长到内置上限之上，重启可能被拒，需重审。

GET /system 的 controller 含 started_at/uptime_seconds/db_bytes/rules_enabled/rules_total/whitelist/go_mem{alloc_bytes,sys_bytes}。db_bytes 为主文件、-wal、-shm 之和，缺文件按 0。nodes 每项含 name/online/incompatible/overloaded/rules_state/whitelist_state/stats_at/host_uptime_seconds/cpu_percent/mem_percent/load_avg_1/load_avg_5/load_avg_15/counters/rates/agent_state/capacity/rule_reconcile/whitelist_reconcile。host_uptime_seconds 取节点 system.uptime_seconds，是主机开机时长。capacity[]{name,limit,node_used,controller_used} 原样并列；不作正确/错误判词。两项 reconcile 均为 last_at/result/extra/missing/different。缺失节点指标为 null；缓存保留上次成功样本。一次请求只取一次 Status 缓存及一次账本。

batch_too_large（400）在超过 500 项时整请求拒收且一条不写；调用方按 ≤ 500 项顺序分片。message 固定为：
`items must contain 1..500 rules; split larger batches into sequential requests of at most 500 items`。

## 认证与账户合同

机器头为 `Authorization: Bearer <key>`；钥匙格式 `xdk_<id>_<secret>`，id 为 16 位小写 hex，secret 为 43 字符无填充 base64url。每次请求从读池查库验票或钥匙。方案名不分大小写，钥匙区分大小写；恰一个 Authorization 头。HTTP 解析会去除头值首尾空白；值内须为 `Bearer` + 恰一个空格 + 钥匙，钥匙内不许有空白。头出现（包括空值）与会话 cookie 同带、多个 Authorization 或同名会话 cookie 均返回 401。缺失、过期、吊销或退役身份也返回 401；机器访问仅 UI 路由返回 403。命中但未登记权限的路由返回 403，处理器不执行；启动自检缺权限即失败。已认证请求的未知路由 / 错方法仍为 404 / 405。

用户名、钥匙名与节点名均匹配 `^[A-Za-z0-9._-]{1,64}$`，且不能是 `.` 或 `..`（浏览器会折叠这种路径段），只在创建时校验；密码为 10…72 字节，采用 bcrypt DefaultCost，不截断。登录连续失败后，下一次须等待 1、2、4、8、16、32、60、60…秒；未到时刻或同用户名已有验证进行中，返回 login_throttled（429）及向上取整的 Retry-After 秒数。成功清零；延迟不持久化。错误密码与不存在用户返回逐字节相同的 invalid_credentials（401）。

PUT /auth/me/password 两种 UI 角色均可用，输入 `{current_password,password}`；未知字段回 400，旧密码错误与登录共享节流与失败审计；成功回 204、清 cookie，即吊销该用户全部会话。

POST /auth/login 输入 `{username,password}`，回 `{username,expires_at}` 与会话 cookie；POST /auth/logout 返回 204；GET /auth/me 回 `{kind:"user"或"machine",name,role}`（机器 role 为空串）。GET /users 回数组 `[{username,role,created_at,created_by,password_changed_at}]`；POST /users 必须输入 `{username,password,role}`，role 显式取 admin 或 operator（缺失或非法回 invalid_field） 返回 201；DELETE /users/{name} 返回 204；PUT /users/{name}/password 输入 `{password}` 返回 204。PUT /users/{name}/role 输入 `{role}` 返回 204；改角色不踢会话，下一请求即生效。删除先判最后一个用户（409 last_user）；删除或降级最后一个管理员回 409 last_admin。

凭证管理仅管理员可用，已发钥匙仍照常可用。GET /credentials 回数组 `[{id,name,created_at,created_by,retire_at,revoked_at,revoked_by,active}]`，不回钥匙或哈希。POST /credentials 输入 `{name}`，返回 `{id,name,key,created_at,retired:[{id,retire_at}]}`，key 仅此次显示。同名再发总是新钥匙；仍有效且未有更早退役期限的旧钥匙设为 24 h 后退役；认领身份跨轮换仍是 cred:name。DELETE /credentials/{id} 即刻吊销，认领保留；重复吊销 204，不存在 404 credential_not_found。

GET /settings 回 `{session_hours,audit_retention_days,reconcile_interval_minutes,default_language,history_retention_days}`；PUT 局部更新，空对象或值未变化不记审计。四个整数范围/默认值分别为 1…720/24 小时、1…3650/180 天、1…1440/15 分钟、1…90/30 天；default_language 收发 zh-CN、ja-JP、en-US，出厂 en-US，入库分别为 1、2、3。任一字段非法回 400 invalid_field（field 为键名），五键都不写；回包恒含五字段。未知字段仍拒绝。对账间隔提交后运行中生效；缩短会提前过远的既有排程，延长保留已排任务。已删除的配置键出现即固定拒绝：`reconcile_interval moved to settings`。非法名称、密码长度也回 invalid_field；重名 user_exists（409），找不到用户 user_not_found（404）。

界面语言优先级：用户偏好已存语言 → 三种支持语言内的浏览器语言 → 当前系统默认语言。管理员修改默认值后，回退用改后值；英文只是出厂值。

GET /auth/me/prefs 回当前 JSON 对象，无行回 {}；PUT 整份替换，成功 204，仅接受 ≤ 8 KiB 的 JSON 对象，否则 invalid_field。偏好归当前用户，删用户连删，不记审计；机器凭证 403。

GET /templates 回 `[{id,name,body,created_at,created_by,updated_at,updated_by}]`，两角色均可读。管理员 POST /templates、PUT /templates/{id} 输入 `{name,body}`，回同一模板形状；DELETE 回 204。ID 为 tpl_ 加 32 位随机十六进制；name 为 1…64 字符且唯一，body 原文存储、不解析、≤ 64 KiB，总数 ≤ 100。尺寸非法 invalid_field，重名 409 rule_conflict，满额 409 table_full 且 table="templates"，不存在 404 not_found。模板审计 before/after 只含 name 与 body，body 的值是正文 SHA256 前 16 位十六进制，绝不存全文。

created_by / updated_by 为 `user:<用户名>` 或 `cred:<钥匙名>`；历史行可能为 ui。人的认领仍是 `(ui,空认领号)`，用户删除规则仍为强删。吊销凭证不删除规则或认领。 CLI 新建用户的 created_by 为 `system:cli`（历史 `cli` 保留）。

部署**必须让控制器只监听本机**（listen 用 127.0.0.1 或 ::1），由反代终结 TLS 并对外提供 HTTPS。Secure cookie 需要 HTTPS。配置层不强制监听地址，以供私有 lab 命名空间测试；生产部署必须遵守本限制。

首个账号与忘密码通过主机 CLI：`xdrop-controller -config /absolute/path/controller.example.yaml user add <name>` 或 `user passwd <name>`。`-config` 必须在子命令之前。CLI 复用 config.Load，须有完整配置、可读的节点 key 文件，不联网。终端输入密码两次且不回显；管道读取一行并去尾 CR/LF。只有事务提交成功才退出 0；重名、不存在、非法密码或数据库忙退出 1；未知子命令、缺名或多余参数退出 2。运行中执行 passwd 对服务下一次查票立即生效。

## 审计

26 个动作闭集：`rule.create`, `rule.claim`, `rule.update`, `rule.release`, `rule.delete`, `rule.expire`, `whitelist.create`, `whitelist.delete`, `auth.login`, `auth.login_failed`, `auth.logout`, `user.create`, `user.delete`, `user.password`, `credential.issue`, `credential.revoke`, `settings.update`, `node.sync`, `node.reconcile`, `user.role`, `template.create`, `template.update`, `template.delete`, `node.create`, `node.update`, `node.delete`。

操作者为 `user:<名>`、`cred:<名>`、`system:cli` 或 `system:expiry`；登录失败为空串。目标分别为 `rule:<id>`、`whitelist:<id>`、`user:<名>`、`credential:<id>`、`settings`、`node:<名>`、`template:<id>`。不存在用户的失败目标为空，绝不记录输入的用户名。

业务改动与审计行同一事务提交；审计插入失败即回滚业务并回 500 internal。登录失败、手动节点动作各自开审计事务；同步/对账先提交审计再触发。批量仍每项一事务。读操作、被拒请求（401/403/429）、限流登录、未变化设置、重复建白名单/吊销、撤不存在认领/删不存在白名单、同一认领方纯续期均不记。真比对失败记 reason=password；不存在用户做哑比对后记 unknown_user；比对后会话插入因陈旧失败记 stale。首次认领与撤认领仍记；最后撤认领 after=null。白名单改动为删与建。

每项为 `{id,at,actor,source,action,target,before,after}`。前后内容为专用 JSON 视图或 null：规则含 id/logical_id/match/enabled/comment/expires_at/created_by/updated_by/claimants[{claimant,claim_ref}]；白名单含 id/src_ip/dst_ip/src_port/dst_port/protocol/comment；用户含 username/created_at/created_by/password_changed_at；钥匙含 id/name/retire_at/revoked_at。发钥匙 after={issued,retired:[]}；设置含五键；user.role 含 role；模板只含 name 与 body 摘要；登录失败 after={reason}；改密码不带内容。密码、哈希、钥匙、会话票均不记。

仅连接对端在 127.0.0.0/8 或 ::1/128 时采信 X-Forwarded-For，否则记连接地址。只读取第一个头的值，从右向左扫描，遇非回环 IP 即返回，扫到最左项即使为回环也返回；扫描中遇非法项或缺头则回连接地址，已选定地址左侧不再扫描。其他转发头不采信。CLI 与到期事件 source 为空。

GET /audit 可带 from/to（UTC `2006-01-02T15:04:05Z`）、limit（1…1000，默认 100）、不透明 cursor。from 含、to 不含，按 (at,id) 降序；回 `{items:[],next_cursor}`，末页 cursor 为空串。GET /audit/export 必填 from、to、format=csv|json，按 (at,id) 升序。GET /audit 两角色均可读，export 仅管理员；运维能看不能下载，机器钥匙两路由均 403；参数非法回 400 invalid_field，field 为参数名。
两路由均可带单个 action（精确等值；空或缺省不筛；未知动作回空）。游标不记筛选，换筛选从头翻。

导出每页 1000 行独立读查询。JSON 为单个数组；CSV 表头恰为 `id,at,actor,source,action,target,before,after`。单元格首字符为 =、+、-、@、制表或回车时前置单引号；before/after 内 JSON 原文不改写。Content-Disposition 为 `attachment; filename="xdrop-audit-<from>-<to>.<ext>"`。中途读写失败记日志并断开连接，截断下载不得呈现完整成功；部署须验证反代透传上游断连。

到期删除与保留期清理同一 30 s 周期；到期事务提交并释放规则锁后另开清理事务，每轮最多删 5000 条严格早于 now−audit_retention_days×24h 的记录，清理本身不记审计。清理失败沿用 local_read_failed 事件。分页/导出非快照，并发写入和清理可能可见；表清空后 id 可重起。

反代必须与控制器同机并经回环连接，把转发链合并为单个 X-Forwarded-For 头并追加客户端地址（nginx：`proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for`）；否则审计只记反代地址，多个分离头不能构成可信转发链。建议反代对 `/api/v1/auth/login` 做 limit_req。

协议 11 的 nodeclient 只接受 11，10 与 12 不兼容。system.counters 与缓存 rates 保留原八键，并加 total_bytes、dropped_bytes、passed_bytes；对应 rates 为字节/秒，界面乘 8 得 bps，始终与 pps 成对。
Hits 拉取器遵循下文流量数据合同，浏览器只读控制器缓存。
先升级控制器，再逐台升级节点。协议混合期不同步；未重启节点仍用已有内核规则。节点重启会清空策略，直到匹配控制器下一次协议探测（默认 CheckInterval 60 秒）、全量同步、健康与规则恢复前有过滤空窗。确认恢复后才升级下一台。

## 节点入库（schema v5）

五条节点管理路由均为 admin 档（UI 管理员）；运维与机器凭证返回 403 admin_required。POST /nodes 接收 `{name,base_url,api_key}`；名字唯一；所有操作拒绝空名与含 `/` 的名字，创建另须遵守用户名规则，重名返回 409 rule_conflict。URL 仅 http/https，必须有 host，不能带 user、query、fragment。api_key 长度为 1…4096 字节；非法输入返回 400 invalid_field。密钥只提交一次、永不回显。

PATCH /nodes/{name} 接收 `{base_url?,api_key?}`，至少一项，不能改名。只改地址时保留原密文。更新停旧建新，两侧回到 pending 并重新全量 atomic。DELETE 删除管理关系并等待该节点协程退出，不联系节点、不清空远端规则；原规则保留，其他节点继续运行。

POST /nodes/test 测试未保存的 `{base_url,api_key}`，POST /nodes/{name}/test 测试已存节点。两者返回 `{reachable,compatible,key_accepted,message}`，先做无密钥协议 Probe，再做带密钥 Stats。不跟随跳转，3xx 返回 reachable=false；message 脱敏且只回给管理员。已存节点测试从读行到两次调用完成一直持节点写锁，写操作可能等待两条路由超时之和（每次约 8 秒，不是排队上界）。

GET /nodes 权限不变，NodeDTO 新增 base_url 与 key_unreadable。保留 Status 原顺序，再按名去重追加库有、运行中无的行；追加行其余状态为零值。key_unreadable 以实际解密结果为准。单行解密失败不阻断启动，该节点不发请求；PATCH 重贴 api_key 即修复。

nodes 表以 AES-256-GCM 加密密钥，每次新密钥写入生成随机 12 字节 nonce，AAD 为节点名；主密钥只在内存。审计新增 node.create、node.update、node.delete，before/after 仅 name、base_url、key_changed，不含密钥、nonce、密文。

启动前执行 `xdrop-controller -config <f> secret-key init`，生成配置指定的 0600 主密钥文件，拒绝覆盖，且不开库、不迁移。随后可用 `xdrop-controller -config <f> node add|update|delete <name> [--url U] [--key-stdin]`。add 必须有地址和密钥，update 至少一项，delete 两者均不接收。--key-stdin 从标准输入读一行，不接受命令行密钥；只改地址或删除不读标准输入。CLI 审计操作者为 system:cli。

运行中修改节点用网页/API；CLI 供启动前使用，在线 CLI 修改到下次启动才生效，混用时 API 操作可能返回 500。API 写锁跨读旧值、事务与审计、提交、orch 增停；提交后若遇停机返回 500，下次启动从库收敛。

主密钥丢失：将 secret_key_file 指向新的绝对路径，执行 secret-key init，重启，再逐个 PATCH 重贴节点密钥；修复前旧行保留并显示 key_unreadable。不提供主密钥轮换或自动生成。

## 流量数据（schema v6）

两条路由均为 `all` 权限：两种界面会话与 API 密钥都可读。
`n=all` 返回节点 Hits 正速率规则并集与库交集中的全部规则及其目标；all 只给界面规则列表用，回包可达数 MB。
`targets_total` 为截断之前的目标分组数（整数），所有 n 与 /events 的 Top 5 均带此字段。
`GET /traffic/top[?n=5]` 回 `{rules:[],targets:[],targets_total,updated_at,incomplete,total_dropped_pps,total_dropped_bytes_ps}`；n 为 1…20 或 all，非法值回 400 invalid_field。空榜为数组。updated_at 为当前节点最近收到的不同 Hits 成功快照时刻（RFC 3339 UTC），尚无快照为 null。
规则行：`{rule_id,target,dropped_pps,dropped_bytes_ps,share,nodes}`；nodes 是该规则本拍正包速率的贡献节点个数（整数）。
目标行：`{target,dropped_pps,dropped_bytes_ps,share,rules}`；rules 是汇入目标的贡献规则个数（整数）。两个数量均不暴露名单。
按丢弃包速率降序，并列按 rule_id / target 升序。目标取 dst_ip，否则取规范 dst_cidr 原串；精确地址与覆盖它的前缀分行。无目标规则只进规则榜，控制器库里已不存在的规则两榜都剔除。
share 的分母为全部规则 Hits 正包速率之和，含无 target 规则与刚删除但仍在节点最近有效样本中的规则；仅分母为零时为 null，节点缺报不使占比置空，比例不截断。total 字段与占比分母不同源，仍为当前节点可用 Stats 速率合计；缺覆盖由 incomplete 表示。
incomplete 原因：Hits 截断、尚无成功快照或正在失败退避、Stats 速率缺失、库有节点而 orch 无。单条规则速率未知本身不置位。
规则速率仅由相邻两次不同成功快照差分；同 now_ns 整包忽略，即使行集变化也保留基线和速率。now_ns 下降或包/字节计数下降重建基线。首次、缺席、缺席后恢复拍均未知并从榜中省略；新命中通常晚一拍 5 秒上榜，扫描交错可晚两拍。超过 60 秒未见的基线删除；按最大回包估算每节点约 12–13 万项，并非固定分配保证。
结果按 Hits/Stats/状态序号、规则 gen、节点集合与 n 缓存；无成功新快照时的失败退避状态变化也失效。重复浏览器读取不增加节点请求或目标查询批次。

`GET /traffic/history?range=15m|1h|6h|24h|7d|30d[&node=名称]` 回 `{range,step_s,node,capped,points:[]}`。range 必填，无效/缺失回 400 invalid_field；node 缺省为合计空串，未知节点名回 404 node_not_found。
点为 `{t,dropped_pps,passed_pps,dropped_bytes_ps,passed_bytes_ps}`；t 为桶起点 Unix 秒，包速率单位包/秒，字节速率单位字节/秒，界面乘 8 得 bps。
15m / 1h 读内存 720 桶环，step_s=5、不带最大值。6h / 24h 读 traffic_1m，step_s=60；7d / 30d 读 traffic_1h，step_s=3600。库点另带 dropped_pps_max、passed_pps_max、dropped_bytes_ps_max、passed_bytes_ps_max，普通字段为平均值。
点按 t 升序、查询时窗两端包含；缺桶不补零。同序列同 5 秒桶后到覆盖先到；合计桶仅加当前成员该桶已有点，合计峰值由合计序列求，绝不把节点峰值相加。
只写已结束分钟：n 为已有 5 秒点数，avg 为其均值，max 为最大值；小时 avg 按分钟 n 加权、n 求和、max 取分钟 max 的最大。启动首个不完整分钟、停机未落分钟、被内存环覆盖的未落分钟均丢弃。Rates 为 nil 不写点。失败下周期重试，提交成功（或配额主动丢弃）才推进位置。
历史维护复用 expiry 周期，在规则锁之外运行；完成小时先汇总（重启可补做），再按保留期清理。触发上限时小时输入可能已删，按实有分钟汇总，n 反映实有点数。
第五个整数设置 history_retention_days 缺省 30、范围 1…90，同管两层；GET/PUT /settings 与 settings.update before/after 均含五键，修改后下周期生效。
每周期每表最多删 5000 条严格早于 now−保留期的行，恰在边界保留。两表硬上限独立：traffic_1m 为 1,800,000 行，traffic_1h 为 200,000 行。写前最多预删最旧 5000 行，再按实际剩余配额接纳，合计优先、其余按节点名字典序；预删与后段上限清理共享 5000 额度。超额新汇总丢弃不排队，满额时删旧写新。发生上限删除或拒收的周期只记一条无节点名 history_capped 事件，随后一小时 capped=true。
两表满载约 0.3 GB 仅为估算，不是文件硬上界：删除页复用、数据库不自动缩小，WAL 保留也影响磁盘量。历史仅用原数据库。删节点后库内历史自然到期，同名重建接续；删除/PATCH 清空该节点内存环、Hits 基线和落库位置。

Stats 缺省 5 秒、Health 2 秒。Hits 独立串行协程，每节点最多一个在途、超时 5 秒，首次启动等 5 秒；后续按上次开始时刻对齐并跳过占用拍，成功耗时 4 秒则每 5 秒开始、耗时 7 秒则每 10 秒开始。失败（含 429、超时、传输和形状错误）翻倍退避 10、20、40、60、60 秒，成功回 5 秒；since_ns 取上次成功 now_ns，首次为零。删节点取消请求并等待三个节点协程退出。
每次进入 sampler select 前先检查 Stats 到期。请求开始最多被当时正在进行的一个请求推迟；成功数据在回包后才更新，持续失败保留旧 Rates、无成功数据新鲜度上界。
