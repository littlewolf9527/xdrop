# Controller API — c5b-1

This is the new controller contract (G1). The legacy controller/API.md stays frozen until retirement of the old implementation. API paths are under /api/v1; responses use JSON except the events stream and audit export. Rule and whitelist writes acknowledge committed storage and never wait for nodes (G3). Cross-repository xSight adaptation is a separate project; only this contract is delivered here (G9).

Users authenticate with passwords and server sessions; machines use named credentials. Users have two roles: admin and operator. UI permissions include both; administrator routes require an admin UI session and reject operators and machines with admin_required (403). Existing v3 users migrate to admin in schema v4; CLI user add also creates admin accounts. Only health and login are public.

## Routes

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

## Events and the static entry point

`GET /events` requires the `ui` permission (both UI roles); machine credentials receive 403 and unauthenticated requests receive 401. Use `/api/v1/events` on the wire. A declared request body, including chunked encoding, receives 400 bad_request. The response headers are `Content-Type: text/event-stream`, `Cache-Control: no-cache`, and `X-Accel-Buffering: no`. The prelude is `retry: 3000` followed by a blank line. Frames contain `event: <class>` and `data: <JSON>`, followed by a blank line.

| Class | JSON |
|---|---|
| rules | `{seq,gen}` |
| nodes | `{epoch,nodes,reconcile}` |
| traffic | `{overview:{dropped_pps,passed_pps,dropped_bytes_ps,passed_bytes_ps,nodes_online,nodes_total},top}` |

seq is a process-local successful rule/whitelist commit counter, including expiry renewal. A partially successful batch advances it once. Failed or zero-row writes, audit-only and claim-only changes do not advance it; releasing the final claim and deleting its rule does. gen retains its node-synchronization meaning and does not advance for renewal.
epoch and nodes have exactly the GET /nodes shape. reconcile maps each node name to `{rules,whitelist}`, using the same `{last_at,result}` projections as /system from the same Status snapshot. Overview rates sum that snapshot's node rates, missing values count as zero; node counts use the merged node list, including database-only nodes. top has exactly the GET /traffic/top?n=5 shape and shares its cache. Its share denominator sums rule Hits rates, while overview dropped rates sum node Stats; their scopes and cached samples differ.

Each connection begins with rules, nodes, traffic snapshots in that order. A warm snapshot is the hub's latest sampling cycle, at most one cycle behind; a cold connection waits for the next cycle. The hub clears all three caches when subscribers reach zero. Reconnecting receives full snapshots; there is no replay buffer, event ID or Last-Event-ID continuation. Each subscriber retains only the latest pending value of each class; an event already being written remains in flight.

| Source | Sampling | Event | Hub check | Freshness |
|---|---|---|---|---|
| Online/sync/alerts | Health 2 s / worker changes | nodes | 1 s | Next hub cycle; offline requires two failed probes |
| Packet/byte rates | Stats 5 s | traffic | 1 s | New sample within one hub cycle |
| Capacity, CPU, memory | Stats 5 s | nodes | 1 s | New sample within one hub cycle |
| Top 5 | Hits 5 s | traffic | 1 s | New sample within one hub cycle; new hits need another sample |
| Rules/whitelist/renewal | Commit | rules | 1 s | Next hub cycle |
| Reconciliation | 15 min, configurable | nodes | 1 s | Next hub cycle after completion |

Five seconds means refresh granularity; maximum displayed age is 5 s plus one hub cycle and sampling request time. traffic publishes only when the complete Top key changes (including database-only nodes); overview-only changes wait for the next statistics cycle. The hub takes at most one Status snapshot per cycle, independent of subscriber count, and takes no data snapshots without subscribers.

Every 15 s the stream writes `: ping` followed by a blank line. The hub reauthenticates each stream every cycle, and the handler reauthenticates before each event/heartbeat. Logout closes only its session; password changes (including another CLI process), user deletion, shortened session duration and natural expiry also close invalid streams. Revocation takes one hub cycle plus recheck time; authentication and snapshot work contribute to cycle duration. A send whose recheck succeeded before revocation committed is already authorized in flight; rechecks begun after that commit must fail.
Each ordinary write has a 10 s deadline. Closing a stream cancels its context and expires its write deadline. Shutdown closes all streams and waits for the hub before draining HTTP, stopping the manager and closing storage. New streams reaching the closed hub receive 200 with only the retry prelude and end, with a 1 s write deadline. Rejected body requests also have a 1 s write deadline.
If any snapshot read fails, that cycle publishes no class, closes all current streams and clears the three caches. The hub continues; new connections get the normal retry prelude and are closed on the next failed cycle, or receive current snapshots after recovery. Each failed cycle logs only `hub snapshot read failed; closed_streams=<actual count>`. No error event or extra database retry is emitted.

The binary embeds `controller/core/webui/dist`; its placeholder page has title “xdrop console” and body “前端未构建”. Paths beginning `/api/` go to the authenticated API, including its JSON 404 behavior. Other paths serve static files without authentication; missing extensionless paths fall back to index.html, and missing paths with an extension return plain-text 404. Static requests allow only GET/HEAD (otherwise 405), always send `X-Content-Type-Options: nosniff` and `X-Frame-Options: DENY`, and send `Cache-Control: no-cache` for index.html including SPA fallbacks. API write methods remain available through this combined handler.

## Identity, decoding and errors

The xdrop_session cookie always has HttpOnly, Secure, SameSite=Strict and Path=/api/v1; Max-Age is current session_hours × 3600. Server validity uses creation time plus the current duration: initially 24 absolute hours, without idle expiry. Settings changes affect existing sessions immediately. Logout deletes the session and clears the same cookie scope with Max-Age=-1. Password changes and user deletion revoke every session of that user.

Request bodies are limited to 1 MiB (8 MiB for batch). Unknown fields, incorrect types and trailing data return bad_request. A null RulePatch field is omitted; it does not clear a value. Rule validation has one authority in the rules service.

The single error shape is `{"code":"invalid_rule","message":"...","field":"dst_port"}`. Optional fields are `field`, `rule_id`, `rule_ids`, `table`. Conflict errors identify the occupying rule; condition_capacity and cidr_overlap identify rule_ids; table_full names the table (logical_id, sv4, dv4, sv6, dv6, blacklist, cidr_blacklist, cond, cidr_cond, whitelist, logical_state or templates). Internal errors always say `internal error`; details remain in server logs. Batch item errors use exactly the same shape and redaction.

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

## Rule requests and responses

POST /rules accepts RulePatch fields plus top-level optional `claim_ref`:
`src_ip, dst_ip, src_cidr, dst_cidr, src_port, dst_port, protocol, ttl, dscp, icmp_type, icmp_code, fragment, pkt_len, tcp_flags, match_anomaly, action, rate_limit, enabled, comment, expires_in`.
Ports are integers, rate_limit is an integer, enabled is a boolean, match_anomaly is an integer mask; other request fields are strings. Omitted action defaults to drop, omitted protocol to all, omitted enabled to true. drop canonicalizes rate_limit to zero; rate_limit action needs a positive rate. Exact addresses and prefixes cannot be combined. IP wildcards normalize to the empty canonical value; prefixes are masked to their network.

A Rule DTO includes all canonical match fields, `id, logical_id, kind, group_key, cond_key, enabled, comment, created_at, updated_at, expires_at, created_by, updated_by`. Missing conditions and a permanent expires_at are null. Times are RFC 3339 UTC. IDs are immutable URL-safe `rule_` plus 32 random hex digits (G6); logical_id is an immutable nonzero integer, never reused. Claim details are deferred to cut five.

POST returns the flattened Rule DTO plus `existing, gen, epoch, nodes`; nodes contain `name, online, incompatible, rules_state` from the cached Status snapshot. New rows return 201; an identical canonical identity and action/rate returns 200 existing=true. It returns the stored row, extending expiry to max(old,new); permanent is later than every finite expiry, so either permanent input makes the result permanent. Renewal and claim-only changes do not notify nodes or change gen. Enabled, comment and match fields stay unchanged. **Recreating a disabled configuration does not enable it; inspect enabled in the reply.** A different action/rate on the same identity returns rule_conflict.

Rule expiry comes only from explicit positive Go duration expires_in (for example 2h); omission means permanent (G8). On PATCH, omitted/null fields preserve the old value; `""` clears string fields, including clearing expires_in to permanent. Create rejects explicit empty strings except comment. PATCH returns a Rule DTO. PUT /enabled requires a non-null boolean and returns `{"enabled":false}`. These two operations do not return gen.

POST /rules/batch takes `{"claim_ref":"incident","items":[RulePatch,...]}`, 1..500 items. Zero or more than 500 rejects the entire request with 400 batch_too_large and writes nothing; callers must split larger batches into sequential requests of at most 500 items. Each item has its own transaction; success and failure may coexist. The reply is `{"epoch":"...","results":[{"index":0,"rule":RuleDTO,"existing":false,"gen":1},{"index":1,"error":Error}]}`. Every success explicitly includes gen, including zero; there is no batch-wide gen. Each gen belongs to that item's current group, filled after the batch notification.

POST /rules/batch?validate=1 uses the same decoding, 500-item limit, canonicalization, identity/conflict, expiry projection and admission rules as submission. It writes no rules, claims, audit, counters or notifications. Each item sees successful earlier projections in the batch; an identical action/rate is existing even across claimants, a different one is rule_conflict. Expiry takes the maximum, with permanent later than finite, including successive existing items. Capacity and logical ID exhaustion include simulated earlier new items; logical_id is only a simulated projection, not a persistent allocation.

Validation has two ID exceptions: new successes and batch-local existing results contain rule.id="" (empty means not yet allocated) and omit gen; database-existing results keep their real IDs and also omit gen. Error rule_id/rule_ids referring to batch items use `batch:<original zero-based index>`; database references remain real IDs. Internal temporary identifiers never appear in responses.
On submission, condition_capacity/cidr_overlap rule_ids omit the rejected single-create candidate; batch submission replaces that candidate with `batch:<original zero-based index>`, retaining real IDs for earlier committed items. Update/enabled errors retain the stored candidate's ID.

UI writes own the claim (ui, empty ref). Machines own (cred:name, claim_ref); omitted ref is the empty string. A repeated triple is idempotent; another name/ref adds a claim (G4). Machine DELETE takes claim_ref in the query and releases only its own claim; the last claim removes the row. UI DELETE force-deletes all claims. Missing rows or previously released claims return 204 too (G5). Deletions and toggles do not return gen; view /nodes for aggregate state. Removed claims have no per-rule delivery query.

## Pagination and whitelist

GET /rules and GET /whitelist return `{"items":[DTO,...],"next_after":null}`. limit defaults to 100 and accepts 1..1000. For rules, after is a nonnegative logical_id (default 0), results ascend by logical_id and next_after is the last returned logical_id when another page exists. Rows inserted while paging have larger IDs and appear on later pages. A fresh read sees a completed write; requests do not share long-lived snapshots.
GET /rules accepts optional `q`, trimmed and interpreted in order as `rule_` plus 32 lowercase hex digits, a prefix when it contains `/`, otherwise an IP: IP search includes exact source/destination addresses and covering prefixes; prefix search includes only equal/contained prefixes and addresses of the same family, after masking host bits. Empty q means no search; mapped IPv6 and wildcard IPs are invalid, but both families' `/0` prefixes are valid.
Optional `state=drop|rate_limit|disabled` selects enabled rules of that action or all disabled rules; omission selects all. Filtering preserves logical_id order and next_after is non-null only if another matching row exists.
Optional `counts=1` adds `counts:{all,drop,rate_limit,disabled}` for the current q, ignoring state and pagination, read in the same snapshot as items; omission adds no counts key. Invalid q/state/counts return 400 bad_request with the corresponding field. With all three parameters absent, the original response is unchanged; whitelist queries are unchanged.

Whitelist after is a string ID (default empty), sorted by ID. Its random IDs guarantee no cursor duplicates and complete traversal of a fixed set, but new inserts during pagination need not appear. An exhausted page returns next_after=null. POST /whitelist accepts `src_ip, dst_ip, src_port, dst_port, protocol, comment`; its DTO has these fields plus `id, created_at, created_by`. POST returns a flattened DTO plus existing, 201 new / 200 existing. DELETE is idempotent 204. There is no whitelist per-entry gen.

## Conditions (V4)

Six expression keys are supported: ttl 0..255, dscp 0..63, icmp_type 0..255, icmp_code 0..255, pkt_len 0..65535 and fragment. Numeric syntax is comma-separated unsigned decimal values or inclusive ranges with one optional leading complement `!`, e.g. `64,128-130` or `!0-31`. No leading zeroes except zero; ASCII space/tab are accepted. Empty/full sets, reversed ranges and contradictory combinations are rejected. Normalization sorts and merges ranges. ICMP fields need icmp/icmpv6. fragment needs an IPv4 anchor; values are `nofrag, first, middle, last, frag, nonfirst` (case insensitive); comma unions and leading complement are supported. frag expands to first/middle/last, nonfirst to middle/last.

A group contains the enabled candidates for the same canonical tuple. More specific candidates win; ties follow creation order via logical_id. Capacity is at most four physical candidates per group; one expression can expand into multiple physical candidates. Capacity errors identify the occupants rather than silently changing conditions.

match_anomaly is an any-bit mask within 0x0F: 0x01 bad fragment, 0x02 invalid, **0x04 length mismatch**, **0x08 IPv4 TCP fragment offset exactly one (8 bytes)**. It requires a bounded address/prefix; IPv6 rejects 0x01/0x08. Distinct anomaly conditions remain distinct rules. Anomaly plus ports is accepted subject to D2: when match_anomaly is exactly 0x08 (that bit alone), or fragment's allowed set contains only nonfirst fragments, combining it with a port, TCP flags or ICMP constraint returns invalid_rule (D2). Other anomaly masks, including 0x04 and 0x0c (0x08 together with another bit), can be combined with ports unless fragment independently triggers D2. Both drop and rate_limit actions are accepted. TCP flags such as SYN,!ACK require TCP and can coexist with anomaly subject to D2. IPv4-mapped IPv6 returns mapped_ipv6 with a suggestion to use IPv4, without automatic rewriting; mixed address families return address_family_mismatch.

## Delivery and node snapshots

GET /nodes returns `{"epoch":"...","nodes":[NodeDTO]}`. NodeDTO adds overload (an array of dim/limit/used); its other fields are name, online, incompatible, rules, whitelist, health_at, health, stats_at, stats, rates. Each side contains state/reason/since/confirmed_gen/confirmable/rejected. Rejected entries expose only key/id/code/error/rule_ids. Health contains status/rules_synced/whitelist_synced. Statistics and rates are cached samples, never on-demand node calls; credentials and rejection fingerprints are excluded. POST /nodes/{name}/sync or /reconcile returns 202 `{"status":"accepted"}`; unknown names return node_not_found. GET /health is public and returns only `{"status":"ok"}`.

GET /rules/{id}/delivery requires gen and epoch from a receipt. A mismatched epoch always returns 409 gen_epoch_mismatch. gen is a process-local group watermark; restart gives a new 16-byte random hex epoch and unmodified groups have gen=0. Recover via GET /nodes for epoch or by writing again for a new receipt. keyGen retains every changed group key until restart; unrelated groups and whitelist changes never advance a rule's receipt.

The reply contains rule_id, requested gen, target_gen, epoch and nodes with name/state and optional rejection code/error. Under the service write lock it reads the current rule, the current group's target_gen and one cached node Status snapshot. The threshold is max(requested gen, target_gen). A missing row returns 404. Per node, evaluate in this order:
1. Disabled rule → disabled; offline node → offline; incompatible node → incompatible.
2. An overloaded node returns overloaded first. Rules confirmable=false or latest health.rules_synced=false → pending. Confirmable means no full sync outstanding, a full sync has completed once, and no bad-health observation is outstanding, and the node is not overloaded.
3. Any rejection matching the current group key, rule ID or membership in rule_ids → rejected.
4. confirmed_gen >= threshold → confirmed; otherwise pending.

**confirmed is the controller's confirmation watermark for the rule's current target**, backed by a successful node acknowledgement and the latest sampled synchronized health. It is not a real-time readback; reconciliation detects drift between reconciliations. A restart can leave the previous confirmation visible until the next health sample (default 2s). After a full success, delivery conservatively remains pending until a synchronized health sample arrives. Status copying while holding the service lock can briefly delay writes; the HTTP read pool has no connection cap. Both costs are recorded by the lab fixture.

## Deployment

Run `xdrop-controller -config /absolute/path/xdrop-controller.example.yaml`. Required keys: listen (host:port), database (absolute path), secret_key_file (absolute path). Unknown keys, duplicate YAML keys, multiple documents and empty/unreadable configuration files fail startup. The master key file must have permissions 0600 and contain base64 encoding of exactly 32 random bytes; errors identify secret_key_file without its contents. A nodes key in any form is rejected with `nodes moved to database; use the web UI or "node add"`.

Node names must be nonempty, unique and must not contain `/`.

Startup: load config → open database → Prepare (print every violation and reject any violations) → read master key → read/decrypt database nodes → read settings → construct manager/service → Prime the Prepare ledger and connect Limits → start manager → build API → serve HTTP. SIGINT/SIGTERM: close the events hub and its streams → HTTP Shutdown with 10s drain → manager Stop and wait → database Close. Cleanup continues after errors. Exit 0 requires successful Shutdown and Close; startup failures unwind acquired components. A Shutdown timeout means abnormal exit and proves neither drain nor a single-file database.

The database directory must be writable. Back up `<db>*`, including WAL companions after a crash; a long reader can keep WAL near the database size, so reserve space. Normal successful shutdown leaves a single database file. Access restrictions belong in infrastructure. The application records source IP addresses and does not block them.



## Capacity and system

GET /capacity and GET /system allow UI and machine actors. Data comes from the in-memory ledger and cached samples, without node fan-out.

| Dimension (identical to node key) | Enabled-rule accounting | Builtin limit | table_full.table |
|---|---|---|---|
| blacklist | Distinct exact group_key values | 500000 | blacklist |
| cidr_blacklist | Distinct cidr group_key values | 500000 | cidr_blacklist |
| cond | Exact groups with at least two enabled members or any conditional member | 500000 | cond |
| cidr_cond | Same criterion for cidr groups | 500000 | cidr_cond |
| whitelist | Whitelist entries | 50000 | whitelist |
| sv4_cidr_trie | Distinct source IPv4 prefixes | 50000 | sv4 |
| dv4_cidr_trie | Distinct destination IPv4 prefixes | 50000 | dv4 |
| sv6_cidr_trie | Distinct source IPv6 prefixes | 50000 | sv6 |
| dv6_cidr_trie | Distinct destination IPv6 prefixes | 50000 | dv6 |
| logical_state | Enabled rules, counting the controller target | 1000000 | logical_state |

Expired enabled rules still count until the 30 s cleanup. Disabled rows count only toward rules.total. Each key allows four physical candidates; full_keys counts keys with four, near_keys those with three. logical_id still means ID-space exhaustion, distinct from logical_state occupancy. Node rejection messages retain node prefix names; for example sv4 maps to sv4_cidr_trie. New global dimensions have no occupying rule_ids to name.

For each non-overloaded node and dimension, use its valid positive integer limit or builtin fallback. Incompatible, never-reported and missing dimensions fall back; offline nodes retain the last cache. Take the minimum effective limit across nodes and name its source. No nodes or all nodes overloaded yields builtin. Node used never drives admission. Reject only positive occupancy increments whose result exceeds admission_limit; comments, disabling, deletion and other neutral/reducing writes remain possible. Each batch item sees earlier committed items.

Each dimensions entry has name/used/limit/admission_limit/limit_source/free/ratio/exhausted. limit is the tightest raw node limit; only logical_state subtracts a reserve (default 1000) for admission_limit. free=admission_limit−used is signed; exhausted=(free≤0). ratio=used/admission_limit when admission_limit>0, otherwise null. tightest contains name/limit_source/free/ratio/exhausted: exhausted entries first by ascending free, ties by dimension order without comparing ratio; other entries by descending ratio, then dimension order. Also returned: candidates{limit,full_keys,near_keys}, rules{enabled,total}, overloaded_nodes[]{name,dims[]{name,limit,used}}. Each request reads the ledger once and Limits once.

Any effective raw limit below controller occupancy overloads the node: both sides become overloaded/capacity, writes and reconciliation stop, Confirmable=false, dirty keys accumulate, and its limits leave the minimum. Once everything fits, capacity_recovered forces full synchronization on both sides. State changes follow a worker reevaluation after sampling the new limit; a limit change between evaluation and sending can still be rejected by the node, with varying error codes. Reevaluation after the next sample is the fallback. Overload waits use CheckInterval, without spinning on full/dirty work.

The reserve guarantees only remaining pending after reclamation plus owners exiting in the same submission ≤1000. Larger delete/add windows or accumulated reclamation failures are outside that guarantee. The node may enter capacity_retry and, after three failures, retry full sync every CheckInterval until the union fits. Prepare always checks builtin raw limits; overload recovery also uses raw limits. Future larger node limits can let a database grow past builtin limits and then fail Prepare on restart; that needs reassessment.

GET /system returns controller{started_at,uptime_seconds,db_bytes,rules_enabled,rules_total,whitelist,go_mem{alloc_bytes,sys_bytes}}. db_bytes sums the main file, -wal and -shm, counting absent files as zero. Each nodes entry contains name/online/incompatible/overloaded/rules_state/whitelist_state/stats_at/host_uptime_seconds/cpu_percent/mem_percent/load_avg_1/load_avg_5/load_avg_15/counters/rates/agent_state/capacity/rule_reconcile/whitelist_reconcile. host_uptime_seconds is the host's system.uptime_seconds. capacity[]{name,limit,node_used,controller_used} presents both counts without judging correctness. Each reconcile object contains last_at/result/extra/missing/different. Missing node metrics are null; cache values retain the last successful sample. Each request reads Status once and the ledger once.

batch_too_large (400) rejects an entire batch over 500 without writes; callers send sequential slices of at most 500. The exact message is:
`items must contain 1..500 rules; split larger batches into sequential requests of at most 500 items`.

## Accounts and deployment

Machines send `Authorization: Bearer <key>`, with `xdk_<id>_<secret>`: 16 lowercase hex id characters and 43 unpadded base64url secret characters. Authentication queries the read pool on every request. Scheme names are case-insensitive; keys are case-sensitive. Exactly one Authorization header is required. HTTP parsing strips leading and trailing whitespace from header values; within the value, use `Bearer` followed by exactly one space and the key, with no whitespace inside the key. An Authorization header, even empty, together with a session cookie returns 401, as do multiple Authorization headers or duplicate session cookies. Missing, expired, revoked or retired identities return 401. Machines on UI-only routes return 403. Matched routes missing permissions return 403 without running the handler; startup checks reject missing entries. Authenticated unknown routes and wrong methods remain 404 and 405.

User and credential names match `^[A-Za-z0-9._-]{1,64}$`. Passwords have 10..72 bytes and use bcrypt DefaultCost, without truncation. Consecutive login failures impose waits of 1,2,4,8,16,32,60,60... seconds before the next attempt. Early attempts and concurrent verification of the same user return login_throttled (429) with Retry-After seconds rounded up. Success resets the delay; restart clears it. Wrong passwords and nonexistent users have byte-identical invalid_credentials (401) responses.

POST /auth/login accepts `{username,password}` and returns `{username,expires_at}` plus the cookie; POST /auth/logout returns 204. GET /auth/me returns `{kind:"user" or "machine",name,role}` (machine role is an empty string). GET /users returns `[{username,role,created_at,created_by,password_changed_at}]`. POST /users requires `{username,password,role}` with an explicit admin or operator role (missing/invalid role returns invalid_field) and returns 201; DELETE /users/{name} returns 204; PUT /users/{name}/password accepts `{password}` and returns 204. PUT /users/{name}/role accepts `{role}` and returns 204; changes take effect on the next request without revoking sessions. Deleting the last user returns 409 last_user first; deleting or demoting the last administrator returns 409 last_admin.

PUT /auth/me/password accepts `{current_password,password}` for either UI role; unknown fields return 400, wrong current passwords share login throttling and failure auditing, and success returns 204, clears the cookie and revokes all sessions of that user.

Only administrators manage credentials; already issued keys remain valid. GET /credentials returns `[{id,name,created_at,created_by,retire_at,revoked_at,revoked_by,active}]`, without keys or hashes. POST /credentials accepts `{name}` and returns `{id,name,key,created_at,retired:[{id,retire_at}]}`; key is shown only once. Issuing the same name always creates a new key and sets still-active older keys to retire after 24 h unless an earlier deadline already applies. The claimant stays cred:name across rotation. DELETE /credentials/{id} revokes immediately and preserves claims: 204 also when already revoked, 404 credential_not_found when absent.

GET /settings returns `{session_hours,audit_retention_days,reconcile_interval_minutes,default_language,history_retention_days}`. PUT /settings updates only present fields; empty or unchanged updates produce no audit event. Numeric ranges/defaults are 1..720/24 hours, 1..3650/180 days, 1..1440/15 minutes and 1..90/30 history days. default_language is zh-CN, ja-JP or en-US (factory default en-US); storage uses integers 1, 2, 3 respectively. Any invalid field returns 400 invalid_field with its key and changes nothing; responses always contain all five fields. Unknown fields remain rejected. The interval takes effect after commit while running; shortening brings later scheduled reconciliations forward, lengthening preserves already scheduled work. The removed configuration key is explicitly rejected with `reconcile_interval moved to settings`. Invalid names/password lengths also return invalid_field; duplicate users return user_exists (409), missing users user_not_found (404).

Language priority for the UI: a language stored in user preferences, otherwise a supported browser language, otherwise the current system default. Administrators can change that fallback from factory English.

GET /auth/me/prefs returns the current JSON object ({} when absent). PUT replaces the complete object, returns 204 and accepts at most 8 KiB; non-objects and oversized bodies return invalid_field. Preferences belong to the authenticated user, cascade on user deletion and are never audited. Machines receive 403.

GET /templates returns `[{id,name,body,created_at,created_by,updated_at,updated_by}]`; both UI roles may read it. Administrator POST /templates and PUT /templates/{id} accept `{name,body}` and return the same template shape; DELETE returns 204. IDs are tpl_ plus 32 random hexadecimal digits. Names have 1..64 characters and are unique; body is stored verbatim without parsing, at most 64 KiB. At most 100 templates may exist. Invalid sizes return invalid_field, duplicate names rule_conflict (409), full storage table_full (409) with table="templates", missing IDs not_found (404). Template audit before/after contains only name and body, where body is the first 16 hexadecimal characters of its SHA256, never the template text.

created_by / updated_by use `user:<username>` or `cred:<credential-name>`; historical rows may contain ui. Human claims remain `(ui,empty-ref)` and human rule deletion is still forced deletion. Credential revocation never deletes rules or claims. CLI-created users use `system:cli` (historical `cli` remains valid).

The controller **must listen only on loopback** (listen uses 127.0.0.1 or ::1); a reverse proxy terminates TLS and exposes HTTPS. Secure cookies require HTTPS. Configuration validation does not enforce loopback, to support private lab namespaces; production deployment must enforce this requirement.

Bootstrap and reset through the host CLI: `xdrop-controller -config /absolute/path/controller.example.yaml user add <name>` or `user passwd <name>`. Put -config before the subcommand. CLI reuses config.Load, so it needs complete configuration and readable node key files, without network access. Terminal passwords are entered twice without echo; piped input is one line with trailing CR/LF removed. Exit 0 requires a committed change; duplicate/missing users, invalid passwords or a busy database yield 1. Unknown, missing or extra arguments yield 2. Running passwd against a live service invalidates that user's sessions on its next authentication query.

## Audit

The 26-event action set is: `rule.create`, `rule.claim`, `rule.update`, `rule.release`, `rule.delete`, `rule.expire`, `whitelist.create`, `whitelist.delete`, `auth.login`, `auth.login_failed`, `auth.logout`, `user.create`, `user.delete`, `user.password`, `credential.issue`, `credential.revoke`, `settings.update`, `node.sync`, `node.reconcile`, `user.role`, `template.create`, `template.update`, `template.delete`, `node.create`, `node.update`, `node.delete`.

Actors are `user:<name>`, `cred:<name>`, `system:cli`, or `system:expiry`; login failures have an empty actor. Targets are `rule:<id>`, `whitelist:<id>`, `user:<name>`, `credential:<id>`, `settings`, `node:<name>`, and `template:<id>` respectively. Unknown-user failures have an empty target and never store the submitted username.

Each business change and its audit row commit in the same transaction. Audit insertion failure rolls back the change and returns 500 internal. Login failures and manual node operations use their own audit transaction; sync/reconcile runs only after that transaction commits. Batch creation retains one transaction per item. Read operations, denied requests (401/403/429), throttled login attempts, unchanged settings, duplicate whitelist creation/revocation, missing whitelist/claim removal, and same-claimant renewal produce no audit row. Failed password comparisons are recorded with reason password; missing users use unknown_user after a dummy comparison; a stale comparison uses stale. First claims and removals remain recorded. The last release has after=null. Whitelist editing is delete plus create.

Events contain `{id,at,actor,source,action,target,before,after}`. Before/after are dedicated JSON views or null: rules contain id/logical_id/match/enabled/comment/expires_at/created_by/updated_by/claimants[{claimant,claim_ref}]; whitelist contains id/src_ip/dst_ip/src_port/dst_port/protocol/comment; users contain username/created_at/created_by/password_changed_at; credentials contain id/name/retire_at/revoked_at. Credential issuance has after={issued,retired:[]}; settings contain all five setting keys; user.role contains role; templates contain name and the body digest; login failures have after={reason}. Password changes have no content. No passwords, hashes, keys, or session tickets are recorded.

Only connections from 127.0.0.0/8 or ::1/128 may supply X-Forwarded-For. Other peers use their connection address. Only the first header value is considered, scanned right to left: return the first non-loopback IP or the leftmost IP. An invalid entry encountered during scanning, or a missing header, falls back to the connection address; entries left of an already selected address are not scanned. Other forwarding headers are ignored. CLI and expiry sources are empty.

GET /audit accepts optional from/to (UTC `2006-01-02T15:04:05Z`), limit (1..1000, default 100), and opaque cursor. from is inclusive, to exclusive; results descend by (at,id). Response is `{items:[],next_cursor}`; an empty cursor marks the last page. GET /audit/export requires from, to, and format=csv|json, ascending by (at,id). GET /audit requires UI permission; export requires admin permission. Operators may read audit but cannot export; machine keys receive 403 on both. Invalid parameters return 400 invalid_field naming the parameter.
Both endpoints accept a single optional action with exact equality: omitted or empty means no filter; unknown actions return no rows. Cursors do not store the filter; restart pagination when changing it.

Export reads independent pages of 1000 rows. JSON is one array; CSV headers are exactly `id,at,actor,source,action,target,before,after`. A CSV cell starting with =, +, -, @, tab or carriage return receives a leading apostrophe; JSON inside before/after is otherwise unchanged. Content-Disposition is `attachment; filename="xdrop-audit-<from>-<to>.<ext>"`. A read/write failure during export is logged and aborts the connection so a truncated download cannot appear complete. Proxy deployment must propagate upstream disconnects.

Expiry deletion and retention cleanup run on the same 30 s cycle. Cleanup runs after expiry commits and after the rule lock is released, deletes at most 5000 rows strictly older than now minus audit_retention_days times 24 h, and is not audited. Cleanup failures use the existing local_read_failed event. Lists/exports are not snapshots: concurrent writes and cleanup may be visible. IDs may restart after the table becomes empty.

The reverse proxy must run on the controller host, connect over loopback, and combine the forwarding chain into one X-Forwarded-For header while appending the client address (nginx: `proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for`). Otherwise audit records the proxy address; multiple separate headers do not form a trusted chain. Apply a reverse-proxy limit_req policy to `/api/v1/auth/login`.

Protocol 11 nodeclient accepts only 11; 10 and 12 are incompatible. system.counters and cached rates retain the existing eight keys and add total_bytes, dropped_bytes, passed_bytes. Rates for these keys are bytes/second; the UI multiplies by 8 for bps, always paired with pps.
The Hits poller follows the traffic contract below; browsers read the controller cache only.
Upgrade this controller first, then nodes individually. Protocol mismatch prevents synchronization. Unrestarted nodes retain kernel rules; restarting a node clears policy and creates a filtering gap until the compatible controller's next probe (default CheckInterval 60 seconds), full sync, and healthy rule recovery. Confirm recovery before upgrading the next node.

## Stored nodes (schema v5)

All five node management routes require admin (UI administrator); operators and machine credentials receive 403 admin_required. POST /nodes accepts `{name,base_url,api_key}`. Names must be nonempty, unique and contain no `/`; duplicate names return 409 rule_conflict. URLs must use http/https, with a host and without user information, query or fragment. api_key must contain 1..4096 bytes. Invalid input returns 400 invalid_field. Keys are accepted once and never returned.

PATCH /nodes/{name} accepts `{base_url?,api_key?}` with at least one field. Names cannot change. Address-only updates retain the encrypted key. An update stops the old client and creates a new one; both sides begin pending and receive a full atomic synchronization. DELETE removes management and waits for this node's workers to stop; it never clears or contacts the remote node. Existing node rules remain intact. Other nodes continue running.

POST /nodes/test accepts unsaved `{base_url,api_key}`. POST /nodes/{name}/test tests the stored row. Both return `{reachable,compatible,key_accepted,message}` using an unauthenticated protocol Probe and authenticated Stats. Redirects are never followed; 3xx yields reachable=false. Messages are scrubbed and available only to administrators. The stored-node test holds the node write lock until both calls finish, so writes may wait for their route timeouts (about 8 seconds per test, not a queue bound).

GET /nodes retains its permission and status order, adding base_url and key_unreadable to NodeDTO. Rows absent from the running manager are appended in name order without duplicates. key_unreadable reflects actual decryption failure; other status fields for these rows are zero. A bad key does not prevent startup and that node sends no requests. PATCH with a fresh api_key repairs it.

The nodes table stores AES-256-GCM ciphertext with a fresh 12-byte nonce and node name as authenticated data. The master key stays in memory. Node audit actions are node.create, node.update and node.delete; before/after contain only name, base_url and key_changed. No key, nonce or ciphertext appears in responses or audit records.

Initialize the configured master key before starting: `xdrop-controller -config <f> secret-key init`. It creates a 0600 file and refuses to overwrite an existing file, without opening or migrating the database. Then use `xdrop-controller -config <f> node add|update|delete <name> [--url U] [--key-stdin]`. Add requires URL and key; update requires one; delete accepts neither. --key-stdin reads one line from stdin, never a command-line key. URL-only updates and deletes do not read stdin. CLI audits use system:cli.

Use the web UI/API for changes while running. CLI writes are intended before startup and affect a running controller only at its next start; mixing CLI writes with API writes may cause a 500 until restart. API writes serialize database commit and manager removal/addition; a shutdown failure after commit returns 500 and startup converges from the database.

If the master key is lost, set secret_key_file to a new absolute file path, run secret-key init, restart, then PATCH each node with its API key again. Existing encrypted rows remain visible as key_unreadable until repaired. Master key rotation and automatic regeneration are not provided.

## Traffic data (schema v6)

Both routes allow UI sessions (both roles) and API credentials, using the `all` permission.
`GET /traffic/top[?n=5]` returns `{rules:[],targets:[],targets_total,updated_at,incomplete,total_dropped_pps,total_dropped_bytes_ps}`. n accepts 1..20 or all; invalid n returns 400 invalid_field. Empty rankings are arrays. updated_at is the latest successful distinct Hits snapshot receipt among current nodes, in RFC 3339 UTC, or null before any snapshot.
`n=all` returns all positive-rate rules known to the database and their targets, bounded by the union of node Hits responses; it is only for UI rule lists and the response may reach several MB.
`targets_total` is the integer number of target groups before truncation for every n, including the events Top 5.
A rules row is `{rule_id,target,dropped_pps,dropped_bytes_ps,share,nodes}`. nodes is the integer count of current nodes contributing positive packet rates to that rule.
A targets row is `{target,dropped_pps,dropped_bytes_ps,share,rules}`. rules is the integer number of contributing rules. Neither count exposes a membership list.
Rows are sorted by dropped_pps descending, ties by rule_id or target ascending. Rules use dst_ip, otherwise the unchanged canonical dst_cidr. Exact addresses and containing prefixes remain separate targets; targetless rules appear only in rules. Rules absent from the controller database appear in neither ranking.
share divides the row packet rate by the sum of all positive rule Hits packet rates, including targetless rules and deleted rules still present in the latest valid node samples. It is null only when that sum is zero; missing nodes do not null shares. Shares are never clamped. Total fields instead sum available current-node Stats rates; incomplete signals missing coverage.
incomplete means a truncated Hits snapshot, a node with no successful Hits snapshot or currently backing off after a failed pull, missing Stats rates, or a stored node absent from orchestration. An individual unknown rule rate alone does not set incomplete.
The controller differences adjacent successful, distinct node snapshots. Equal now_ns ignores the entire payload, including changed row membership; lower now_ns or decreasing packet/byte counters resets the baseline. First appearance, absence, and recovery after an absent snapshot are unknown and omitted. Newly active rules normally appear one 5-second interval later; scan overlap can add another interval. Baselines unseen for over 60 seconds expire; estimated steady-state storage is roughly 120,000–130,000 entries per node at the maximum response size, not a fixed allocation guarantee.
Top results are cached by Hits/Stats/state sequence, rule generation, node membership, and n. Failed-pull state transitions also invalidate the cache. Repeated browser reads do not trigger node calls or repeated target queries.

`GET /traffic/history?range=15m|1h|6h|24h|7d|30d[&node=name]` returns `{range,step_s,node,capped,points:[]}`. range is required; invalid/missing range returns 400 invalid_field. Omitted node selects the cluster total (`""`); an unknown node name returns 404 node_not_found.
Each point has `{t,dropped_pps,passed_pps,dropped_bytes_ps,passed_bytes_ps}`; t is the bucket start in Unix seconds. Packet rates are packets/second, byte rates bytes/second; the UI multiplies bytes/second by eight for bps.
15m and 1h read the 720-slot in-memory ring with step_s=5 and no maximum fields. 6h/24h read traffic_1m with step_s=60; 7d/30d read traffic_1h with step_s=3600. Database points additionally have dropped_pps_max, passed_pps_max, dropped_bytes_ps_max and passed_bytes_ps_max; their ordinary fields are averages.
Points are ascending within the inclusive requested time window. Missing buckets are omitted, never filled with zero. A later point in the same 5-second bucket replaces the earlier point. Cluster buckets sum only current-member contributions present in that bucket; their peaks are computed from the total series, never by adding node peaks.
Only finished minutes are persisted. Minute n counts existing 5-second points, avg is their mean and max their maximum. Hour averages are weighted by minute n, hour n is their sum, and hour maxima are the largest minute maxima. Startup's partial minute and unflushed minutes at shutdown are discarded. Unflushed minutes overwritten by the ring are also discarded. Nil Stats rates produce no point; failed writes retry next expiry cycle, with cursors advancing only after commit (or deliberate quota loss).
History maintenance follows rule expiry without holding the rule-service lock. Completed hours are summarized before retention cleanup, including backfill after restart. During capping, hour inputs may already have been removed; the remaining minute rows determine averages and n.
`history_retention_days` is the fifth integer setting, default 30 and range 1..90. It controls both tables, appears in GET/PUT /settings and all five-key settings.update before/after views, and takes effect on the next maintenance cycle.
Each cycle deletes at most 5000 expired rows per table with ts strictly less than now minus retention; boundary rows remain. Separate hard limits are 1,800,000 traffic_1m rows and 200,000 traffic_1h rows. Before writing, each table may remove up to 5000 oldest rows, then admit only its remaining quota, with cluster total first and other nodes in name order. The cap deletion allowance is shared with any later cap cleanup. Excess new summaries are discarded, not queued; full tables rotate oldest data out for newest data. Any cap deletion or rejection emits one manager history_capped event for that cycle, and capped stays true for the following hour.
Estimated full-table storage is roughly 0.3 GB, not a database-file bound: SQLite reuses deleted pages and does not automatically shrink the file; WAL retention can also affect disk size. History uses the existing database only. Deleted-node database history expires naturally; a recreated name continues that stored curve. Delete/PATCH discards that node's in-memory ring, Hits baselines and cursors.

Stats defaults to 5 seconds, Health to 2 seconds; Hits runs in a separate serial per-node coroutine with at most one request in flight and a 5-second timeout. The first Hits request starts after 5 seconds. Subsequent starts are anchored to the previous start, skipping occupied ticks; successful 4-second calls start every 5 seconds, 7-second calls every 10 seconds. Failures (including 429, timeout, transport and shape failures) double the interval to 10,20,40,60,60 seconds; success restores 5 seconds. since_ns is the previous successful now_ns, initially zero. Removing a node cancels its request and waits for all three node coroutines.
Before each sampler select, an already-due Stats tick takes priority over Health. Request-start delay is bounded by the one request already in flight. Successful data updates only on receipt; continuing failures preserve old Rates and have no completed-data freshness bound.
