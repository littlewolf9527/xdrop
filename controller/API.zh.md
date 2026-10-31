# 控制器 API

## 鉴权与传输

API 路径统一使用 `/api/v1`。除事件流和审计导出外使用 JSON；仅健康检查和登录公开。

用户携带登录获得的 `xdrop_session` cookie。它是服务端不透明会话，不是 JWT；cookie 带 HttpOnly、Secure、SameSite=Strict，Path=/api/v1。默认有效期为绝对 24 小时，由当前 `session_hours` 设置控制。修改密码会撤销用户会话。

机器使用 `Authorization: Bearer <machine-key>`；`X-API-Key` 不是控制器鉴权方式。不要同时提交会话 cookie 和 Authorization 请求头，否则拒绝请求。UI 表示 admin 或 operator 用户会话，admin 仅指管理员会话；机器和操作员不能调用 admin 路由。

普通 JSON 请求体上限 1 MiB，批量请求体上限 8 MiB。未知字段、错误类型及尾随 JSON 返回 `bad_request`。HTTP 204 响应没有正文。

## 全部路由

| 方法 | 路径 | 权限 | 成功码 | 请求 → 响应 |
|---|---|---|---|---|
| GET | /api/v1/events | UI | 200 | 无正文 → SSE，见事件流 |
| GET | /api/v1/health | 公开 | 200 | 无正文 → {status:ok} |
| POST | /api/v1/rules | UI / 机器 | 201 / 200 | RulePatch + 可选 claim_ref → Rule + existing,gen,epoch,nodes |
| POST | /api/v1/rules/batch | UI / 机器 | 200 | {items,claim_ref?}；可选 validate=1 → {epoch,results} |
| GET | /api/v1/rules | UI / 机器 | 200 | limit,after,q,state,counts → {items,next_after,counts?} |
| GET | /api/v1/rules/{id} | UI / 机器 | 200 | 无正文 → Rule |
| GET | /api/v1/rules/{id}/delivery | UI / 机器 | 200 | 必填 gen,epoch → {rule_id,gen,target_gen,epoch,nodes} |
| PATCH | /api/v1/rules/{id} | UI | 200 | RulePatch → Rule |
| PUT | /api/v1/rules/{id}/enabled | UI | 200 | {enabled:boolean} → {enabled} |
| DELETE | /api/v1/rules/{id} | UI / 机器 | 204 | 机器可带 claim_ref 查询参数；UI 强制删除 |
| GET | /api/v1/whitelist | UI / 机器 | 200 | limit,after → {items,next_after} |
| POST | /api/v1/whitelist | UI | 201 / 200 | WhitelistInput → Whitelist + existing |
| DELETE | /api/v1/whitelist/{id} | UI | 204 | 无正文；幂等 |
| GET | /api/v1/capacity | UI / 机器 | 200 | 无正文 → dimensions,tightest,candidates,rules,overloaded_nodes |
| GET | /api/v1/system | UI / 机器 | 200 | 无正文 → {controller,nodes} |
| GET | /api/v1/traffic/top | UI / 机器 | 200 | n=1..20 或 all，默认 5 → 排名 |
| GET | /api/v1/traffic/history | UI / 机器 | 200 | range 必填、node 可选 → {range,step_s,node,capped,points} |
| GET | /api/v1/nodes | UI / 机器 | 200 | 无正文 → {epoch,nodes} |
| POST | /api/v1/nodes/{name}/sync | UI | 202 | 无正文 → {status:accepted} |
| POST | /api/v1/nodes/{name}/reconcile | UI | 202 | 无正文 → {status:accepted} |
| POST | /api/v1/nodes | Admin | 201 | {name,base_url,api_key} → {name,base_url} |
| PATCH | /api/v1/nodes/{name} | Admin | 200 | {base_url?,api_key?} → {name,base_url} |
| DELETE | /api/v1/nodes/{name} | Admin | 204 | 无正文；解除管理，保留远端策略 |
| POST | /api/v1/nodes/{name}/test | Admin | 200 | 已存节点 → {reachable,compatible,key_accepted,message} |
| POST | /api/v1/nodes/test | Admin | 200 | {base_url,api_key} → 同上测试结果 |
| GET | /api/v1/audit | UI | 200 | from,to,limit,cursor,action → {items,next_cursor} |
| GET | /api/v1/audit/export | Admin | 200 | from,to,format 必填；action 可选 → CSV/JSON |
| PUT | /api/v1/auth/me/password | UI | 204 | {current_password,password}；清除 cookie |
| POST | /api/v1/auth/login | 公开 | 200 | {username,password} → {username,expires_at} + Set-Cookie |
| POST | /api/v1/auth/logout | UI | 204 | 无正文；撤销会话并清除 cookie |
| GET | /api/v1/auth/me | UI / 机器 | 200 | 无正文 → {kind,name,role} |
| GET | /api/v1/users | UI | 200 | 无正文 → 用户数组 |
| POST | /api/v1/users | Admin | 201 | {username,password,role}；响应无正文 |
| DELETE | /api/v1/users/{name} | Admin | 204 | 无正文 |
| PUT | /api/v1/users/{name}/password | Admin | 204 | {password} |
| GET | /api/v1/credentials | Admin | 200 | 无正文 → 凭证元数据数组 |
| POST | /api/v1/credentials | Admin | 201 | {name} → {id,name,key,created_at,retired} |
| DELETE | /api/v1/credentials/{id} | Admin | 204 | 无正文；撤销凭证 |
| GET | /api/v1/settings | UI | 200 | 无正文 → 设置对象 |
| PUT | /api/v1/settings | Admin | 200 | 部分设置对象 → 完整设置 |
| PUT | /api/v1/users/{name}/role | Admin | 204 | {role:admin 或 operator} |
| GET | /api/v1/auth/me/prefs | UI | 200 | 无正文 → JSON 对象 |
| PUT | /api/v1/auth/me/prefs | UI | 204 | JSON 对象整体替换偏好，最多 8 KiB |
| GET | /api/v1/templates | UI | 200 | 无正文 → 模板数组 |
| POST | /api/v1/templates | Admin | 201 | {name,body} → 模板 |
| PUT | /api/v1/templates/{id} | Admin | 200 | {name,body} → 模板 |
| DELETE | /api/v1/templates/{id} | Admin | 204 | 无正文 |

## 规则、认领与下发

RulePatch 字段为 `src_ip,dst_ip,src_cidr,dst_cidr,src_port,dst_port,protocol,ttl,dscp,icmp_type,icmp_code,fragment,pkt_len,tcp_flags,match_anomaly,action,rate_limit,enabled,comment,expires_in`。端口、rate_limit、match_anomaly 为整数，enabled 为布尔，其余为字符串。默认 action=drop、protocol=all、enabled=true；rate_limit 动作要求正速率。精确地址不能与前缀混用；拒绝 mapped IPv6 写法和混合地址族。

Rule 包含规范化匹配字段及 `id,logical_id,kind,group_key,cond_key,enabled,comment,created_at,updated_at,expires_at,created_by,updated_by`。省略有效期表示永久；显式有效期使用 `10m` 等正 Go duration。PATCH 省略/null 保留原值，空 expires_in 清除到期时间。

新建返回 201；相同身份/动作/速率返回 200 且 existing=true。续期延长有效期，但不会启用已禁用规则或覆盖注释。动作/速率冲突返回 rule_conflict。写入确认数据库提交后才异步下发。

机器按凭证名称与 claim_ref 认领；机器 DELETE 仅释放该认领，最后一份释放才删除规则。释放非最后一份认领时，规则期限重算为剩余认领中最晚的期限；剩余认领里有永久的，规则保持永久。UI DELETE 删除规则及全部认领。批量接受 1..500 项，每项独立事务，必须逐项检查结果。`validate=1` 模拟准入但不持久化；模拟新增 ID 为空且不含 gen。

下发查询要求创建返回的 gen 与进程 epoch。状态为 `pending,confirmed,disabled,offline,incompatible,overloaded,rejected`。进程重启会改变 epoch，旧值返回 gen_epoch_mismatch；重试前读取当前节点/创建状态。确认针对规则配置代次，不表示已测得匹配报文。

## 条件、分页与白名单

条件 `ttl,dscp,icmp_type,icmp_code,pkt_len` 使用逗号分隔的无符号十进制值或闭区间，可加前缀 `!`。取值域依次为 0..255、0..63、0..255、0..255、0..65535。fragment 表达式使用 nofrag、first、middle、last、frag、nonfirst，并要求 IPv4 锚点。ICMP 字段要求 ICMP/ICMPv6。条件组最多容纳四个物理候选，表达式展开可能占用多个候选。

match_anomaly 是任意位命中掩码：1 异常分片、2 无效报文、4 长度不一致、8 IPv4 TCP 分片偏移为一。仅接受这四个位；位 1 和 8 不支持 IPv6，并要求有界目标。 IPv6 上 bit 2（invalid）只检查紧跟 IPv6 固定头的 TCP（数据偏移 < 5）；扩展头之后的 TCP 不检查。IPv6 包在 6 个扩展头内到不了传输层、扩展头读不全、或为非首分片时，视为没有传输层：端口与 TCP 标志条件不命中，地址 / 网段 / 包长 / 异常规则照常生效。

规则与白名单分页返回 `{items,next_after}`。limit 默认 100、范围 1..1000。规则使用非负 logical_id 游标并按 logical_id 递增；白名单使用字符串 ID 游标。结束时 next_after 为 null。规则还接受 q（ID、IP 或前缀）、state=drop/rate_limit/disabled、counts=1；counts 忽略 state/分页但遵守 q。

白名单输入为 `src_ip,dst_ip,src_port,dst_port,protocol,comment`，结果增加 id、created_at、created_by、existing。新增 201，已存在 200，幂等删除 204。它匹配精确五元组，不支持 CIDR/条件表达式。

## 节点与运维数据

节点创建要求名称唯一，且遵守下方用户名规则；base_url 为带主机的 http/https URL，不能含用户信息、查询或 fragment；api_key 为 1..4096 字节。PATCH 至少包含 URL 或密钥，名称不可变；更新与删除不复核名称规则。密钥只写。更新会替换运行客户端并安排完整同步；删除停止该节点工作任务但不清除远端策略。未保存及已存节点测试返回可达性、协议兼容性、密钥接受情况和已脱敏消息，不跟随重定向。

节点列表项包含 `name,base_url,key_unreadable,online,incompatible,rules,whitelist,health,health_at,stats,stats_at,rates,overload`。每侧报告 `state,reason,since,confirmed_gen,confirmable,rejected`。通过 `/capacity` 查看准入维度/上限，通过 `/system` 查看控制器指标、节点计数与对账结果。

手动同步/对账响应仅确认已安排工作。自动对账检查执行资格并报告持续漂移；HTTP 成功不表示所有节点接受了所有规则。

## 用户、凭证、设置与模板

用户/凭证/节点名称使用 1..64 个 ASCII 字母、数字、点、下划线或连字符，且不能是 `.` 或 `..`（只在创建时校验）；密码为 10..72 字节。角色为 admin/operator。禁止删除或降级最后一名管理员。用户响应包含 username、role、created_at、created_by、password_changed_at。

新签发机器密钥仅显示一次。同名重新签发会创建新密钥，并使此前有效密钥最迟在 24 小时后退休；认领身份仍使用名称。撤销凭证不删除认领。列表仅含元数据，不含密钥明文。

| 设置 | 默认值 | 接受值 |
|---|---|---|
| session_hours | 24 | 1..720 |
| audit_retention_days | 180 | 1..3650 |
| reconcile_interval_minutes | 15 | 1..1440 |
| history_retention_days | 30 | 1..90 |
| default_language | en-US | en-US, zh-CN, ja-JP |

PUT settings 仅更新已提供字段。偏好整体替换一个不超过 8 KiB 的 JSON 对象。模板原样存储 name/body：名称 1..64 字符、正文最多 64 KiB、最多 100 个模板。模板响应包含 id、name、body、created_at、created_by、updated_at、updated_by。

## 流量、事件与审计

Top 返回 `rules,targets,targets_total,updated_at,incomplete,total_dropped_pps,total_dropped_bytes_ps`，排名项包含包/字节速率和占比。首次或计数重置样本尚无速率；incomplete 表示覆盖缺失或截断。浏览器读取控制器缓存。

History 必须提供 range=15m/1h/6h/24h/7d/30d，可选 node=name。15m/1h 步长 5 秒，6h/24h 为 60 秒，7d/30d 为 3600 秒。点包含 t 和丢弃/放行的包/字节速率；持久化窗口还包含最大值。缺失桶省略，字节速率单位为字节/秒，乘八才是位/秒。

Events 使用 text/event-stream，包含 rules、nodes、traffic 三类事件。开头为 `retry: 3000`，连接接收完整快照而非历史重放。每 15 秒发送 `: ping` 心跳；会话失效会关闭流。

审计事件包含 id、at、actor、source、action、target、before、after。列表接受 UTC from/to、limit 1..1000（默认 100）、不透明 cursor 和 action。导出必须提供 from/to 与 format=csv 或 json，可选 action。导出错误会中断连接，下载中断时应视为不完整。仅信任回环来源提交的转发客户端地址。业务变更与对应审计记录在同一事务提交。

## 错误

错误格式为 `{"code":"invalid_rule","message":"...","field":"dst_port"}`。可选上下文字段为 field、rule_id、rule_ids、table；批量项错误采用相同格式。内部失败仅返回 `internal error`，登录限流包含 Retry-After。rule_conflict 也用于 POST /nodes 的节点重名，以及 POST /templates、PUT /templates/{id} 的模板重名。

| code | HTTP |
|---|---|
| admin_required | 403 |
| last_admin | 409 |
| invalid_credentials | 401 |
| login_throttled | 429 |
| invalid_field | 400 |
| user_exists | 409 |
| user_not_found | 404 |
| last_user | 409 |
| credential_not_found | 404 |
| invalid_rule | 400 |
| empty_value | 400 |
| invalid_expires_in | 400 |
| mapped_ipv6 | 400 |
| address_family_mismatch | 400 |
| bad_request | 400 |
| batch_too_large | 400 |
| unauthenticated | 401 |
| forbidden | 403 |
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

轮换节点密钥时，已存 api_key 必须匹配节点设置 `auth.node_api_key`。修改节点设置后重启节点，再以同一密钥 PATCH 已存节点；控制器 API 替换运行客户端，无须重启控制器。
