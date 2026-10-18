export type Language = 'zh-CN' | 'ja-JP' | 'en-US'
export type Theme = 'auto' | 'light' | 'dark'
export type PanelKey = 'pps' | 'ip' | 'bps' | 'rules'
export type Range = '15m' | '1h' | '6h' | '24h' | '7d' | '30d'
export interface Identity {
  name: string;
  role: 'admin' | 'operator';

}
export interface Side {
  state: string;
  reason: string;
  confirmed_gen: number;
  confirmable: boolean;
  rejected: unknown[] | null;

}
export interface Health {
  rules_synced: boolean;
  whitelist_synced: boolean;

}
export interface Rates {
  dropped_packets: number;
  passed_packets: number;
  dropped_bytes: number;
  passed_bytes: number;

}
export interface SystemStats {
  cpu_percent: number;
  mem_percent: number;

}
export interface Stats {
  system: SystemStats;

}
export interface Node {
  base_url: string;
  key_unreadable: boolean;
  name: string;
  online: boolean;
  incompatible: boolean;
  rules: Side;
  whitelist: Side;
  health_at: string;
  health: Health;
  rates: Rates | null;
  stats: Stats | null;

}
export interface Nodes {
  nodes: Node[];

}
export interface Tightest {
  name: string;
  ratio: number | null;
  exhausted: boolean;

}
export interface Dimension extends Tightest {
  used: number;
  admission_limit: number;
  limit_source: string;

}
export interface Capacity {
  tightest: Tightest;
  dimensions: Dimension[];

}
export interface Overview {
  dropped_pps: number;
  passed_pps: number;
  dropped_bytes_ps: number;
  passed_bytes_ps: number;
  nodes_online: number;
  nodes_total: number;

}
export interface TopTarget {
  target: string;
  dropped_pps: number;
  dropped_bytes_ps: number;
  share: number | null;

}
export interface TopRule extends TopTarget {
  rule_id: string;

}
export interface Top {
  targets: TopTarget[];
  rules: TopRule[];
  updated_at: string | null;
  targets_total: number;

}
export interface Traffic {
  overview: Overview;
  top: Top;

}
export interface RuleSignal {
  seq: number;

}
export interface Point {
  t: number;
  dropped_pps: number;
  passed_pps: number;
  dropped_bytes_ps: number;
  passed_bytes_ps: number;

}
export interface History {
  step_s: number;
  points: Point[];

}
export interface Rule {
  logical_id: number;
  dst_ip: string;
  dst_cidr: string;
  src_ip: string;
  src_cidr: string;
  protocol: string;
  src_port: number;
  dst_port: number;
  ttl: string | null;
  dscp: string | null;
  icmp_type: string | null;
  icmp_code: string | null;
  fragment: string | null;
  pkt_len: string | null;
  tcp_flags: string;
  match_anomaly: number;
  action: string;
  rate_limit: number;

}
export interface Settings {
  session_hours: number;
  audit_retention_days: number;
  history_retention_days: number;
  reconcile_interval_minutes: number;
  default_language: Language;

}
export interface ErrorFields {
  code: string;
  message: string;
}
export interface ErrorEnvelope extends ErrorFields {
  field?: string;

}
export interface Preferences {
  [key: string]: unknown;
  v?: number;
  lang?: unknown;
  theme?: unknown;
  overview?: {
    [key: string]: unknown;
    order?: unknown;
    split?: unknown
  };

}
// Success response roots used by the UI; contract.test.ts walks these recursively.
export interface ResponseMap {
  users: UserDTO[];
  credentials: CredentialDTO[];
  issued: IssuedDTO;
  nodeTest: NodeTestDTO;
  auditPage: AuditPage;
  whitelistPage: WhitelistPage;
  whitelist: WhitelistDTO;
  templates: TemplateDTO[];
  rulePage: RulePage;
  topAll: TopAll;
  error: ErrorFields;
  identity: Identity;
  nodes: Nodes;
  capacity: Capacity;
  top: Top;
  traffic: Traffic;
  signal: RuleSignal;
  history: History;
  rule: Rule;
  settings: Settings;
}

export interface RuleDTO extends Rule {
  id: string;
  kind: string;
  group_key: string;
  cond_key: string;
  enabled: boolean;
  comment: string;
  created_at: string;
  updated_at: string;
  expires_at: string | null;
  created_by: string;
  updated_by: string;
}
export interface RuleCounts { all: number; drop: number; rate_limit: number; disabled: number }
export interface RulePage { items: RuleDTO[]; next_after: number | null; counts?: RuleCounts }
export interface WriteError extends ErrorEnvelope { rule_id?: string; rule_ids?: string[]; table?: string }
export interface BatchResult { epoch: string; results: { index: number; rule?: RuleDTO; existing?: boolean; gen?: number; error?: WriteError }[] }
export interface TopAll extends Top { incomplete: boolean }
export interface RuleCreated extends RuleDTO { existing: boolean }
export interface RuleEnabled { enabled: boolean }
export interface ThirdParty { group: 'browser' | 'controller' | 'go' | 'font' | 'node' | 'bpf'; name: string; version: string; license: string; note?: string }
declare global { const __XD_VERSION__: string }

export interface WhitelistDTO { id: string; src_ip: string; dst_ip: string; src_port: number; dst_port: number; protocol: string; comment: string; created_at: string; created_by: string }
export interface WhitelistPage { items: WhitelistDTO[]; next_after: string | null }
export interface TemplateDTO { id: string; name: string; body: string; created_at: string; updated_at: string; created_by: string; updated_by: string }

export interface AuditEvent { id: number; at: string; actor: string; source: string; action: string; target: string; before: unknown | null; after: unknown | null }
export interface AuditPage { items: AuditEvent[]; next_cursor: string }

export interface UserDTO { username: string; role: 'admin' | 'operator'; created_at: string; created_by: string; password_changed_at: string }
export interface CredentialDTO { id: string; name: string; created_at: string; created_by: string; retire_at: string | null; revoked_at: string | null; revoked_by: string | null; active: boolean }
export interface IssuedDTO { id: string; name: string; key: string; created_at: string; retired: { id: string; retire_at: string }[] }
export interface NodeTestDTO { reachable: boolean; compatible: boolean; key_accepted: boolean; message: string }

export function isOpenSelectTarget(target: EventTarget | null): boolean {
  try {
    const element = target instanceof Element ? target : target instanceof Node ? target.parentElement : null
    return !!element?.closest('select')?.matches(':open')
  }
  catch { return false }
}
