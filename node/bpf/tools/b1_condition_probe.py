#!/usr/bin/env python3
"""Test-only ELF exposing the actual B1 lookup/output boundary.

The production main/anomaly functions remain in the compiled source. Two extra
entries use the exact production attrs initializer and lookup functions, with
packet-provided attribute bytes. This permits all 256 values even for DSCP and
anomaly values that packet extraction cannot produce. It is not parser evidence.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re


def generate(root, output):
    source = (root / 'node/bpf/xdrop_main.c').read_text()
    # The main body is its own boundary; anomaly is retired in B1 knife 5-4.
    clean = re.sub(r'/\*.*?\*/|//[^\n]*', lambda m: re.sub(r'[^\n]', ' ', m[0]), source, flags=re.S)
    starts = list(re.finditer(r'\bint xdp_firewall_main\([^;{}]*\)\s*\{', clean))
    if len(starts) != 1:
        raise ValueError('B1 main definition count')
    start = starts[0]
    end, depth = start.end(), 1
    while depth and end < len(clean):
        depth += (clean[end] == '{') - (clean[end] == '}')
        end += 1
    if depth:
        raise ValueError('B1 main unclosed body')
    main = source[start.start():end]
    entries = []
    for cidr in (False, True):
        var = 'cidr_attrs' if cidr else 'attrs'
        init = re.findall(r'struct pkt_attrs ' + var + r' = \{.*?\n\s*\};', main, re.S)
        if len(init) != 1:
            raise ValueError('B1 initializer count: ' + var)
        key_type = 'cidr_rule_key' if cidr else 'rule_key'
        name = 'cidr' if cidr else 'exact'
        lookup = 'lookup_cidr_rule' if cidr else 'lookup_rule'
        key_extra = '.src_id = 7, .dst_id = 9,' if cidr else ''
        entries.append('''
SEC("xdp") int b1_condition_''' + name + '''(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  if (data + 24 > data_end) return XDP_ABORTED;
  __u8 *p = data;
  __u16 pkt_len = (__u16)p[0] | ((__u16)p[1] << 8);
  __u8 tcp_flags = p[2], pkt_anomaly = p[3], ttl = p[4], dscp = p[5];
  __u8 icmp_type = p[6], icmp_code = p[7], frag_class = p[8], icmp_valid = p[9];
  __u8 l4_valid = p[10];
  ''' + init[0] + '''
  struct ''' + key_type + ''' key __attribute__((aligned(8))) = {
    ''' + key_extra + ''' .dst_port = l4_valid ? __builtin_bswap16(80) : 0, .protocol = 6,
  };
  struct ''' + key_type + ''' matched_key __attribute__((aligned(8))) = {0};
  __u64 config_slot = read_active_slot();
  int rule_sel = read_rule_map_selector(config_slot);
  struct rule_value *rule = ''' + lookup + '''(&key, &matched_key, &''' + var + ''', rule_sel, config_slot);
  __builtin_memcpy(data, &''' + var + ''', sizeof(''' + var + '''));
  return rule ? 0xB2 : 0xB3;
}
''')
    result = source + '\n'.join(entries)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'condition.c').write_text(result)
    record = {'source_sha256': hashlib.sha256(source.encode()).hexdigest(),
              'probe_sha256': hashlib.sha256(result.encode()).hexdigest(),
              'header_sha256': hashlib.sha256((root / 'node/bpf/xdrop.h').read_bytes()).hexdigest(),
              'entries': ['b1_condition_exact', 'b1_condition_cidr'],
              'boundary': 'production initializers and lookup functions; synthetic attrs, not extraction'}
    (output / 'condition.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record))


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--root', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    a = ap.parse_args()
    generate(a.root, a.output)
