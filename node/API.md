# Node API — protocol 11

## Transport and authentication

The configured HTTP port defaults to 8080. Use JSON bodies and Content-Type: application/json. Only welcome and health are public. The eight protected routes require `X-API-Key: <node-api-key>` on every request. `auth.node_api_key` is required; empty values (including whitespace) or placeholders reject startup (`config.Config.Validate` in `node/agent/config/config.go`). If called directly with an empty configured key, `api.AuthMiddleware` in `node/agent/api/middleware.go` refuses protected requests with 503. Missing and wrong keys return 401 with error/message fields. Unknown routes return the router plain-text 404.

Controller machine credentials and node API keys are different credentials. The node does not pull policy: the controller sends full rules and whitelist snapshots after startup. These are separate publications, not one transaction.

## All routes

| Method | Path | Authentication | Success |
|---|---|---|---|
| GET | / | Public | 200 |
| GET | /api/v1/health | Public | 200 |
| GET | /api/v1/rules | Key | 200 |
| GET | /api/v1/rules/hits | Key | 200 |
| POST | /api/v1/rules/commit | Key | 200 |
| GET | /api/v1/whitelist | Key | 200 |
| POST | /api/v1/sync/atomic | Key | 200 |
| POST | /api/v1/sync/whitelist | Key | 200 |
| GET | /api/v1/stats | Key | 200 |
| GET | /api/v1/stats/cpu | Key | 200 |

## Welcome and health

`GET /` has no body and returns `{name:"XDrop Agent",version,sync_protocol:11}`. Source builds use version=dev; the build script injects git describe output. Protocol is independent of that string.

Health always returns HTTP 200. Before both full snapshots succeed it returns `{status:"degraded",reason:"awaiting_full_sync",rules_synced,whitelist_synced}`; afterwards `{status:"healthy"}`. Flags are sticky until restart. Atomic sync with rejected items can still set rules_synced; commit does not set it. Startup clears policy/logical state, so health alone is not proof that every requested rule exists.

## Rule objects and matching

| Fields | Meaning |
|---|---|
| id, logical_id | String ID and nonzero uint32 logical ID; unique ownership |
| src_ip, dst_ip, src_cidr, dst_cidr | Address/prefix strings; exact and prefix fields cannot mix |
| src_port, dst_port, protocol | uint16 ports; protocol all/tcp/udp/icmp/icmpv6/igmp/gre/esp |
| action, rate_limit | drop or rate_limit; rate_limit requires positive uint32 packets/s |
| tcp_flags, pkt_len_min, pkt_len_max | TCP flags; legacy uint16 inclusive length bounds, zero unspecified |
| ttl, dscp, icmp_type, icmp_code, fragment, pkt_len | Optional condition expressions |
| match_anomaly | uint8 any-bit mask: 1 bad fragment, 2 invalid, 4 length mismatch, 8 IPv4 TCP fragment offset one |
| comment, stats | Comment is not persisted/read back; stats contains match_count,drop_count,match_bytes,drop_bytes,drop_pps |

At least one supported five-tuple dimension is needed. Reject mapped IPv6 spellings and mixed address families. Prefixes normalize to network addresses. Ports must agree with protocol. Conditions in different fields are ANDed; one canonical tuple is one group, with at most four physical candidates and two length spans per candidate. Anomaly conditions require bounded targets; IPv6 cannot use bits 1 or 8.

Numeric conditions accept comma-separated values/ranges and optional leading !; domains for ttl/dscp/icmp_type/icmp_code/pkt_len are 0..255/0..63/0..255/0..255/0..65535. Fragment names are nofrag,first,middle,last,frag,nonfirst and need IPv4. ICMP conditions need ICMP/ICMPv6. Rate-limit buckets belong to a logical ID and CPU, using the configured startup divisor rather than one global bucket.

## Read rules and whitelist

Rules accepts page (positive, default 1), limit (1..1000, default 50) and case-insensitive search on ID/address/prefix. It returns `{rules,count,pagination:{page,limit,total,pages}}`, ordered by ID; no query still returns only page one. Invalid page/limit and unsupported sort/order/enabled/action parameters return 400 with error. Stats read errors leave zero counters.

Whitelist returns `{entries,count}` without pagination; entries contain id and canonical exact five-tuple fields. Ordering is unspecified. Common 401 errors apply to both routes.

## Commit rule groups

POST commit accepts `{groups:[{key,rules:[Rule,...]},...]}`. The canonical key has kind=exact/cidr, src_port,dst_port,protocol and present address/prefix fields. All members must have that key. Commit requires explicit IDs and cannot change an existing ID's logical identity. Empty rules deletes that group; undeclared groups remain. Moving a rule requires declaring old and new groups together.

Success is `{code:"committed",groups:[{index,result}],receipt:"confirmed"}`; result is created/replaced/deleted/unchanged. receipt=deferred means publication succeeded but reclamation is pending. A no-change response has code=unchanged and no receipt. Errors contain code,error,groups, with optional localized rule/key/capacity details. Read back and reconcile after ambiguous transport or publication failures.

## Full rules and whitelist snapshots

POST atomic accepts `{rules:[Rule,...]}` and replaces all rules through a shadow generation. Empty or omitted rules clears them. Global preflight conflicts reject publication; ordinary invalid items may be excluded while valid items publish. Success returns `{success,added,failed,rules,cidr_rules,rejected}`; inspect failed/rejected even on HTTP 200. Rejections include id,reason and index when the original ID is empty. Whitelist is unchanged.

POST sync/whitelist accepts `{entries:[{id,src_ip?,dst_ip?,src_port?,dst_port?,protocol?},...]}`. Empty or omitted entries clears all whitelist entries. IDs and canonical keys must be unique; the complete input is validated before publishing. Success returns `{total,failed:0}` and sets the whitelist health flag. Malformed/invalid entries return 400, map/configuration failures 500; rules remain unchanged.

## Statistics and recent hits

Stats returns packet counters total_packets,dropped_packets,passed_packets,whitelisted_packets,rate_limited_packets,mapped_v6_dropped; byte counters total_bytes,dropped_bytes,passed_bytes; diagnostics cond_row_missing,tailcall_fail; rules_count,whitelist_count; total_pps,dropped_pps,passed_pps; and system,agent_state,xdp_info,capacity. Independent reads are not one atomic snapshot. Bytes count XDP L2 frame length without FCS.

Capacity reports blacklist,cidr_blacklist,cond,cidr_cond,whitelist,sv4_cidr_trie,dv4_cidr_trie,sv6_cidr_trie,dv6_cidr_trie,logical_state, each with limit/used. Usage is published in-memory state, not a fresh kernel dump. Pinned counters can survive agent restart, but policy does not; tailcall_fail starts over.

Stats/cpu returns `{per_cpu,rate_limit,divisor_in_map}`; each possible CPU has the original five packet counters. rate_limit has divisor,source,online_cpus,possible_cpus. A failed divisor read still returns 200 with null and divisor_in_map_error; stats read failure returns 500 with code=stats_read_failed. It does not advance global PPS baselines.

Hits requires since_ns as uint64 and returns `{now_ns,truncated,scanned,hits}`. Rows contain rule_id,logical_id,match_count,drop_count,match_bytes,drop_bytes,last_hit_ns. Timestamps use the Linux monotonic coarse clock, not Unix time. Results filter current owners with last_hit_ns >= since_ns, sort by cumulative drop_count then logical_id, and return at most 10000 rows.

The candidate snapshot is cached for 2 seconds and concurrent scans coalesce. truncated is true above 10000 filtered rows or at candidate occupancy >=8192. LRU eviction can omit active rules, so rankings may be incomplete. A shared hits token bucket defaults to 20 requests/s and burst 20; excess returns 429 `{error:"rate_limited"}` with Retry-After: 1. Invalid since_ns returns 400, map read failures 500.

## Mutation error codes

| Operation | HTTP | Codes / body |
|---|---|---|
| Commit | 400 | validation_rejected |
| Commit | 409 | duplicate_id, duplicate_logical_id, group_undeclared, content_different, cidr_overlap, condition_capacity, table_full |
| Commit | 500 | quiescence_failed, commit_failed |
| Atomic | 400 | error (JSON binding) |
| Atomic | 409 | condition_group_invalid, table_full, duplicate_logical_id, duplicate_id, duplicate_key, cidr_overlap |
| Atomic | 500 | quiescence_failed or error without code |
| Whitelist sync | 400 / 500 | error |

Atomic failures also carry added/failed except JSON binding errors. Commit errors carry groups; localized group errors can identify rule_id,undeclared_key,rule_ids,table,excess. Node error shapes differ from the controller error object.
