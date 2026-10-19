# Controller API

## Authentication and transport

All API paths use `/api/v1`. JSON is used except for the event stream and audit exports. Only health and login are public.

Users send the `xdrop_session` cookie obtained from login. It is an opaque server session, not JWT; the cookie has HttpOnly, Secure, SameSite=Strict and Path=/api/v1. Default validity is 24 absolute hours, controlled by the current `session_hours` setting. Password changes revoke user sessions.

Machines send `Authorization: Bearer <machine-key>`; `X-API-Key` is not a controller authentication method. Do not combine a session cookie and Authorization header: the request is rejected. UI means either admin or operator user session; admin means an administrator session only. Machines and operators cannot call admin routes.

Ordinary JSON bodies are limited to 1 MiB; batch bodies to 8 MiB. Unknown fields, wrong types and trailing JSON produce `bad_request`. Responses with HTTP 204 have no body.

## All routes

| Method | Path | Permission | Success | Request → response |
|---|---|---|---|---|
| GET | /api/v1/events | UI | 200 | No body → SSE; see Events |
| GET | /api/v1/health | Public | 200 | No body → {status:ok} |
| POST | /api/v1/rules | UI / machine | 201 / 200 | RulePatch + claim_ref? → Rule + existing,gen,epoch,nodes |
| POST | /api/v1/rules/batch | UI / machine | 200 | {items,claim_ref?}; validate=1 optional → {epoch,results} |
| GET | /api/v1/rules | UI / machine | 200 | limit,after,q,state,counts → {items,next_after,counts?} |
| GET | /api/v1/rules/{id} | UI / machine | 200 | No body → Rule |
| GET | /api/v1/rules/{id}/delivery | UI / machine | 200 | gen,epoch required → {rule_id,gen,target_gen,epoch,nodes} |
| PATCH | /api/v1/rules/{id} | UI | 200 | RulePatch → Rule |
| PUT | /api/v1/rules/{id}/enabled | UI | 200 | {enabled:boolean} → {enabled} |
| DELETE | /api/v1/rules/{id} | UI / machine | 204 | Machine claim_ref query optional; UI force-deletes |
| GET | /api/v1/whitelist | UI / machine | 200 | limit,after → {items,next_after} |
| POST | /api/v1/whitelist | UI | 201 / 200 | WhitelistInput → Whitelist + existing |
| DELETE | /api/v1/whitelist/{id} | UI | 204 | No body; idempotent |
| GET | /api/v1/capacity | UI / machine | 200 | No body → dimensions,tightest,candidates,rules,overloaded_nodes |
| GET | /api/v1/system | UI / machine | 200 | No body → {controller,nodes} |
| GET | /api/v1/traffic/top | UI / machine | 200 | n=1..20 or all, default 5 → rankings |
| GET | /api/v1/traffic/history | UI / machine | 200 | range required, node optional → {range,step_s,node,capped,points} |
| GET | /api/v1/nodes | UI / machine | 200 | No body → {epoch,nodes} |
| POST | /api/v1/nodes/{name}/sync | UI | 202 | No body → {status:accepted} |
| POST | /api/v1/nodes/{name}/reconcile | UI | 202 | No body → {status:accepted} |
| POST | /api/v1/nodes | Admin | 201 | {name,base_url,api_key} → {name,base_url} |
| PATCH | /api/v1/nodes/{name} | Admin | 200 | {base_url?,api_key?} → {name,base_url} |
| DELETE | /api/v1/nodes/{name} | Admin | 204 | No body; removes management, leaves remote policy |
| POST | /api/v1/nodes/{name}/test | Admin | 200 | Stored node → {reachable,compatible,key_accepted,message} |
| POST | /api/v1/nodes/test | Admin | 200 | {base_url,api_key} → same test result |
| GET | /api/v1/audit | UI | 200 | from,to,limit,cursor,action → {items,next_cursor} |
| GET | /api/v1/audit/export | Admin | 200 | from,to,format required; action optional → CSV/JSON |
| PUT | /api/v1/auth/me/password | UI | 204 | {current_password,password}; clears cookie |
| POST | /api/v1/auth/login | Public | 200 | {username,password} → {username,expires_at} + Set-Cookie |
| POST | /api/v1/auth/logout | UI | 204 | No body; invalidates session and clears cookie |
| GET | /api/v1/auth/me | UI / machine | 200 | No body → {kind,name,role} |
| GET | /api/v1/users | UI | 200 | No body → user array |
| POST | /api/v1/users | Admin | 201 | {username,password,role}; no body |
| DELETE | /api/v1/users/{name} | Admin | 204 | No body |
| PUT | /api/v1/users/{name}/password | Admin | 204 | {password} |
| GET | /api/v1/credentials | Admin | 200 | No body → credential metadata array |
| POST | /api/v1/credentials | Admin | 201 | {name} → {id,name,key,created_at,retired} |
| DELETE | /api/v1/credentials/{id} | Admin | 204 | No body; revoke |
| GET | /api/v1/settings | UI | 200 | No body → settings object |
| PUT | /api/v1/settings | Admin | 200 | Partial settings object → complete settings |
| PUT | /api/v1/users/{name}/role | Admin | 204 | {role:admin or operator} |
| GET | /api/v1/auth/me/prefs | UI | 200 | No body → JSON object |
| PUT | /api/v1/auth/me/prefs | UI | 204 | JSON object replaces preferences, at most 8 KiB |
| GET | /api/v1/templates | UI | 200 | No body → template array |
| POST | /api/v1/templates | Admin | 201 | {name,body} → template |
| PUT | /api/v1/templates/{id} | Admin | 200 | {name,body} → template |
| DELETE | /api/v1/templates/{id} | Admin | 204 | No body |

## Rules, claims and delivery

RulePatch fields are `src_ip,dst_ip,src_cidr,dst_cidr,src_port,dst_port,protocol,ttl,dscp,icmp_type,icmp_code,fragment,pkt_len,tcp_flags,match_anomaly,action,rate_limit,enabled,comment,expires_in`. Ports, rate_limit and match_anomaly are integers; enabled is boolean; the other fields are strings. Defaults are action=drop, protocol=all and enabled=true. A rate_limit action requires a positive rate. Exact addresses and prefixes cannot be combined; mapped IPv6 spellings and mixed address families are rejected.

A Rule contains the canonical match fields plus `id,logical_id,kind,group_key,cond_key,enabled,comment,created_at,updated_at,expires_at,created_by,updated_by`. An omitted expiry is permanent; an explicit expiry is a positive Go duration such as `10m`. PATCH omissions/null preserve values, while empty expires_in clears expiry.

Create returns 201 for a new row, 200 with existing=true for identical identity/action/rate. Renewal extends expiry but does not enable a disabled rule or overwrite its comment. A conflicting action/rate returns rule_conflict. Writes acknowledge committed storage before delivery.

Machines own claims by credential name and claim_ref; machine DELETE releases only that claim, with final release deleting the rule. UI DELETE removes the rule and all claims. Batch takes 1..500 items with independent transactions; inspect each result. `validate=1` simulates admission without persistence; simulated new IDs are empty and gen is omitted.

Delivery requires gen and the process epoch returned by create. States are `pending,confirmed,disabled,offline,incompatible,overloaded,rejected`. A process restart changes epoch and returns gen_epoch_mismatch for an old value; obtain current node/creation state before retrying. Confirmation concerns the configured rule generation, not measured matching packets.

## Conditions, pagination and whitelist

Conditions `ttl,dscp,icmp_type,icmp_code,pkt_len` use comma-separated unsigned decimal values or inclusive ranges, optionally prefixed by `!`. Domains are respectively 0..255, 0..63, 0..255, 0..255, 0..65535. Fragment expressions use nofrag, first, middle, last, frag and nonfirst with an IPv4 anchor. ICMP fields require ICMP/ICMPv6. Condition groups admit at most four physical candidates; expansion can consume more than one candidate.

match_anomaly is an any-bit mask: 1 bad fragment, 2 invalid, 4 length mismatch, 8 IPv4 TCP fragment at offset one. Only these four bits are accepted; bits 1 and 8 reject IPv6, and a bounded target is required. For IPv6, bit 2 (invalid) checks only TCP immediately following the fixed IPv6 header (data offset < 5); TCP after extension headers is not checked. If an IPv6 packet cannot reach the transport layer within 6 extension headers, has an unreadable extension header, or is a non-first fragment, it is treated as having no transport layer: port and TCP flag conditions do not match, while address, prefix, packet-length, and anomaly rules remain effective.

Rules and whitelist pages return `{items,next_after}`. limit defaults to 100, range 1..1000. Rules use a nonnegative logical_id cursor and ascending logical_id order; whitelist uses a string ID cursor. Exhaustion returns null. Rules also accept q (ID, IP or prefix), state=drop/rate_limit/disabled, and counts=1. Counts ignore state/pagination but honor q.

Whitelist input is `src_ip,dst_ip,src_port,dst_port,protocol,comment`; the result adds id, created_at, created_by and existing. New creation is 201; existing is 200; deletion is idempotent 204. It matches exact five-tuples, not CIDR/condition expressions.

## Nodes and operational data

Node creation requires a unique name that follows the user-name rule below, an http/https base_url with host and no user information/query/fragment, and api_key of 1..4096 bytes. PATCH requires URL and/or key; names do not change, and update/delete do not recheck the name rule. Keys are write-only. Updating replaces the live client and schedules full synchronization; deleting stops its workers without clearing remote policy. Unsaved and stored tests return reachability, protocol compatibility, key acceptance and a scrubbed message; redirects are not followed.

Node list entries expose `name,base_url,key_unreadable,online,incompatible,rules,whitelist,health,health_at,stats,stats_at,rates,overload`. Each side reports `state,reason,since,confirmed_gen,confirmable,rejected`. Use `/capacity` for admission dimensions/limits and `/system` for controller metrics, node counters and reconciliation results.

Manual sync/reconcile replies only acknowledge scheduling. Automatic reconciliation uses eligibility checks and reports persistent drift; successful HTTP does not mean every node has accepted every rule.

## Users, credentials, settings and templates

User/credential/node names use 1..64 ASCII letters, digits, dot, underscore or hyphen, and cannot be `.` or `..` (checked on creation only); passwords are 10..72 bytes. Roles are admin/operator. Removing or demoting the last administrator is rejected. User responses contain username, role, created_at, created_by and password_changed_at.

A newly issued machine key appears only once. Reissuing the same credential name creates a new key and retires active earlier keys after at most 24 hours; the claim identity remains the name. Revocation does not delete claims. Lists contain metadata rather than key plaintext.

| Setting | Default | Accepted values |
|---|---|---|
| session_hours | 24 | 1..720 |
| audit_retention_days | 180 | 1..3650 |
| reconcile_interval_minutes | 15 | 1..1440 |
| history_retention_days | 30 | 1..90 |
| default_language | en-US | en-US, zh-CN, ja-JP |

PUT settings updates only present fields. Preferences replace one JSON object, at most 8 KiB. Templates store name/body verbatim: name is 1..64 characters, body at most 64 KiB, at most 100 templates. Template responses contain id,name,body,created_at,created_by,updated_at,updated_by.

## Traffic, events and audit

Top returns `rules,targets,targets_total,updated_at,incomplete,total_dropped_pps,total_dropped_bytes_ps`; each ranking uses packet/byte rates and shares. A first or reset counter sample has no rate yet; incomplete reports missing/truncated coverage. Browser reads use the controller cache.

History requires range=15m/1h/6h/24h/7d/30d and optionally node=name. Steps are 5 seconds for 15m/1h, 60 for 6h/24h and 3600 for 7d/30d. Points contain t and dropped/passed packet/byte rates; persisted windows also have maxima. Missing buckets are omitted. Byte rates are bytes/second; multiply by eight for bits/second.

Events use text/event-stream with rules, nodes and traffic classes. The stream starts with `retry: 3000`; connections receive full snapshots, not event replay. Heartbeats are `: ping` every 15 seconds. Session invalidation closes streams.

Audit events contain id,at,actor,source,action,target,before,after. Listing accepts UTC from/to, limit 1..1000 (default 100), opaque cursor and action. Export requires from/to and format=csv or json, and optionally action. Export errors abort the connection; treat interrupted downloads as incomplete. Forwarded client addresses are trusted only from loopback peers. Business mutations and their audit rows commit together.

## Errors

Errors use `{"code":"invalid_rule","message":"...","field":"dst_port"}`. Optional context is field, rule_id, rule_ids or table; batch item errors use the same shape. Internal failures return only `internal error`. Login throttling includes Retry-After. rule_conflict is also returned for a duplicate node name on POST /nodes and for a duplicate template name on POST /templates or PUT /templates/{id}.

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

For node key rotation, the stored api_key must match the node setting `auth.node_api_key`. Restart the node after changing that setting, then PATCH the stored node with the same key; the controller API replaces the live client without restarting the controller.
