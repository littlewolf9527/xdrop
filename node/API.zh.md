# 节点 API — 协议 11

## 传输与鉴权

HTTP 端口由配置决定，默认 8080；请求体使用 JSON，Content-Type: application/json。请求体里的未知字段返回 400，`error` 写出字段名。仅欢迎与健康检查公开。八条受保护路由每次请求都要求 `X-API-Key: <node-api-key>`。`auth.node_api_key` 必填；空值（含全空白）或占位符拒绝启动（`node/agent/config/config.go` 的 `config.Config.Validate`）。若直接以空密钥调用中间件，`node/agent/api/middleware.go` 的 `api.AuthMiddleware` 以 503 拒绝受保护请求。缺失或错误密钥返回 401，带 error/message 字段。未知路由返回路由器的纯文本 404。

控制器机器凭证与节点 API 密钥是不同凭证。节点不主动拉取策略；启动后由控制器分别推送规则与白名单完整快照，两者不是一个事务。

## 全部路由

| 方法 | 路径 | 鉴权 | 成功码 |
|---|---|---|---|
| GET | / | 公开 | 200 |
| GET | /api/v1/health | 公开 | 200 |
| GET | /api/v1/rules | 密钥 | 200 |
| GET | /api/v1/rules/hits | 密钥 | 200 |
| POST | /api/v1/rules/commit | 密钥 | 200 |
| GET | /api/v1/whitelist | 密钥 | 200 |
| POST | /api/v1/sync/atomic | 密钥 | 200 |
| POST | /api/v1/sync/whitelist | 密钥 | 200 |
| GET | /api/v1/stats | 密钥 | 200 |
| GET | /api/v1/stats/cpu | 密钥 | 200 |

## 欢迎与健康检查

`GET /` 无请求体，返回 `{name:"XDrop Agent",version,sync_protocol:11}`。直接源码构建的 version 为 dev，构建脚本注入 git describe 输出；协议号独立于该字符串。

健康检查始终返回 HTTP 200。两份完整快照均成功前返回 `{status:"degraded",reason:"awaiting_full_sync",rules_synced,whitelist_synced}`，之后返回 `{status:"healthy"}`。标志保持到重启；带拒绝项的成功 atomic 同步也可能设置 rules_synced，commit 不设置该标志。启动清空策略/逻辑状态，因此仅凭健康状态不能证明每条请求规则都存在。

## 规则对象与匹配

| 字段 | 含义 |
|---|---|
| id, logical_id | 字符串 ID 与非零 uint32 逻辑 ID，所有权唯一 |
| src_ip, dst_ip, src_cidr, dst_cidr | 地址/前缀字符串，精确地址不能与前缀混用 |
| src_port, dst_port, protocol | uint16 端口，协议 all/tcp/udp/icmp/icmpv6/igmp/gre/esp |
| action, rate_limit | drop 或 rate_limit；rate_limit 要求正 uint32 包/秒 |
| tcp_flags, pkt_len_min, pkt_len_max | TCP 标志；兼容 uint16 长度闭区间，零表示未指定 |
| ttl, dscp, icmp_type, icmp_code, fragment, pkt_len | 可选条件表达式 |
| match_anomaly | uint8 任意位掩码：1 异常分片、2 无效、4 长度不一致、8 IPv4 TCP 分片偏移为一。IPv6 上 bit 2（invalid）只检查紧跟 IPv6 固定头的 TCP（数据偏移 < 5）；扩展头之后的 TCP 不检查。IPv6 包在 6 个扩展头内到不了传输层、扩展头读不全、或为非首分片时，视为没有传输层：端口与 TCP 标志条件不命中，地址 / 网段 / 包长 / 异常规则照常生效。超深链缺省丢、开关关闭时才如此。 |
| comment, stats | comment 不持久化/读回；stats 包含 match_count,drop_count,match_bytes,drop_bytes,drop_pps |

至少需要一个受支持的五元组维度；拒绝 mapped IPv6 写法与混合地址族。前缀规范化为网络地址，端口须与协议兼容。不同字段条件按 AND 组合；同一规范五元组形成一组，最多四个物理候选，每候选最多两个长度区间。异常条件要求有界目标，IPv6 不允许位 1 或 8。

数字条件接受逗号分隔的值/区间及可选前导 !；ttl/dscp/icmp_type/icmp_code/pkt_len 域为 0..255/0..63/0..255/0..255/0..65535。分片名称为 nofrag,first,middle,last,frag,nonfirst，要求 IPv4；ICMP 条件要求 ICMP/ICMPv6。限速桶属于逻辑 ID 与 CPU，使用启动时除数，而非单个全局桶。

## 读取规则与白名单

Rules 接受 page（正数，默认 1）、limit（1..1000，默认 50）和对 ID/地址/前缀不区分大小写的 search。返回 `{rules,count,pagination:{page,limit,total,pages}}`，按 ID 排序；没有查询参数时也只返回第一页。非法 page/limit 和不支持的 sort/order/enabled/action 返回 400 与 error；统计读取失败时计数为零。

Whitelist 无分页，返回 `{entries,count}`；条目包含 id 和规范化精确五元组字段，顺序未规定。两条路由均适用公共 401 错误。

## 提交规则组

POST commit 接受 `{groups:[{key,rules:[Rule,...]},...]}`。规范 key 含 kind=exact/cidr、src_port、dst_port、protocol 及已提供的地址/前缀字段；每个成员必须匹配该 key。键本身也必须是合法规则能有的键（例如只有 all / tcp / udp 能带端口），否则整批返回 400 `validation_rejected`，不写任何表。Commit 要求明确 ID，不能更改已有 ID 的逻辑身份。空 rules 删除该组，未声明组保持；移动规则需同时声明旧组与新组。

成功为 `{code:"committed",groups:[{index,result}],receipt:"confirmed"}`，result 为 created/replaced/deleted/unchanged。receipt=deferred 表示已发布但回收尚未完成。无变更响应 code=unchanged 且不含 receipt。错误包含 code、error、groups，可带局部规则/键/容量信息。传输或发布结果不确定时，读取并对账确认。

## 规则与白名单完整快照

POST atomic 接受 `{rules:[Rule,...]}`，通过影子代次替换全部规则；空或省略 rules 会清空规则。全局预检冲突拒绝发布，普通非法项可能被排除而其余合法项仍发布。成功返回 `{success,added,failed,rules,cidr_rules,rejected}`；HTTP 200 也必须检查 failed/rejected。拒绝项含 id、reason，原 ID 为空时含 index；白名单不变。

POST sync/whitelist 接受 `{entries:[{id,src_ip?,dst_ip?,src_port?,dst_port?,protocol?},...]}`。空或省略 entries 清空全部白名单。ID 和规范键必须唯一，发布前完整校验输入。成功返回 `{total,failed:0}` 并设置白名单健康标志；格式/条目非法返回 400，map/配置失败返回 500；规则不变。

## 统计与最近命中

Stats 返回包计数 total_packets,dropped_packets,passed_packets,whitelisted_packets,rate_limited_packets,mapped_v6_dropped；字节计数 total_bytes,dropped_bytes,passed_bytes；诊断 cond_row_missing,tailcall_fail；rules_count,whitelist_count；total_pps,dropped_pps,passed_pps；以及 system,agent_state,xdp_info,capacity。独立读取不是单一原子快照；字节统计为不含 FCS 的 XDP 二层帧长度。
`ipv6_deep_chain_dropped`：IPv6 扩展头链超过 6 层被丢弃的包数（`bpf.ipv6_deep_chain_drop`，缺省开启）；也计入 dropped_packets / dropped_bytes。

Capacity 报告 blacklist,cidr_blacklist,cond,cidr_cond,whitelist,sv4_cidr_trie,dv4_cidr_trie,sv6_cidr_trie,dv6_cidr_trie,logical_state，各含 limit/used。使用量是已发布内存状态，不是即时内核转储。已 pin 计数可跨 agent 重启保留，但策略不会保留；tailcall_fail 重新开始。

Stats/cpu 返回 `{per_cpu,rate_limit,divisor_in_map}`，每个 possible CPU 含原有五类包计数。rate_limit 含 divisor,source,online_cpus,possible_cpus。除数读取失败仍返回 200，值为 null 并附 divisor_in_map_error；统计读取失败返回 500、code=stats_read_failed。它不推进全局 PPS 基线。

Hits 必须提供 uint64 since_ns，返回 `{now_ns,truncated,scanned,hits}`；行含 rule_id,logical_id,match_count,drop_count,match_bytes,drop_bytes,last_hit_ns。时间戳使用 Linux 单调粗粒度时钟而非 Unix 时间。仅保留当前所有者且 last_hit_ns >= since_ns 的项，按累计 drop_count、再按 logical_id 排序，最多返回 10000 行。

候选快照缓存 2 秒，并发扫描合并。过滤后超过 10000 行或候选占用 >=8192 时 truncated 为 true。LRU 淘汰可能漏掉活跃规则，因此排名可能不完整。共享 hits 令牌桶默认每秒 20 次、burst 20；超量返回 429 `{error:"rate_limited"}`、Retry-After: 1；非法 since_ns 返回 400，map 读取失败返回 500。

## 变更错误码

| 操作 | HTTP | 错误码 / 正文 |
|---|---|---|
| Commit | 400 | validation_rejected |
| Commit | 409 | duplicate_id, duplicate_logical_id, group_undeclared, content_different, cidr_overlap, condition_capacity, table_full |
| Commit | 500 | quiescence_failed, commit_failed |
| Atomic | 400 | error（JSON 绑定） |
| Atomic | 409 | condition_group_invalid, table_full, duplicate_logical_id, duplicate_id, duplicate_key, cidr_overlap |
| Atomic | 500 | quiescence_failed 或不带 code 的 error |
| 白名单同步 | 400 / 500 | error；quiescence_failed（500） |

翻转后回执失败仍 200、旧表下次同步清理。
除 JSON 绑定错误外，Atomic 失败还含 added/failed；Commit 错误含 groups，局部组错误可带 rule_id,undeclared_key,rule_ids,table,excess。节点错误结构与控制器错误对象不同。condition_group_invalid 只表示写表前查出的条件组内容无效；条件组内的内核写入或 CIDR 预留失败与普通规则相同，返回不带 code 的 500；规则行或条件行因内核表满被拒时返回 409 table_full。
