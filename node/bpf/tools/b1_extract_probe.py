#!/usr/bin/env python3
"""Test-only ELF: observe the actual main extraction and both attrs initializers.

No lookup body or production ELF is changed. The probe stops before table
lookups, writes the ten attribute bytes back into the input packet and returns
0xB1. It proves extraction on reached paths, not production lookup/dispatch.
"""
import argparse
import hashlib
from pathlib import Path
import re


# Knife-one source guards for the intervals omitted between extraction and
# each initializer. Pin the newline-normalized text of each interval (read_text
# then encode) to reject writes, alias writes and
# unknown changes without pretending a lexical assignment scan is a C AST.
# A changed interval requires review of the extraction boundary before repinning.
SKIPPED_SHA256 = {
    'attrs': '5f24fca775b511b0b3368579b00ed0529e109df6b776cbb138e755ea7a5e94b4',
    'cidr_attrs': '4cc2eb6a99c5024afe1b3f9d157254fa67418fc40f82ab1e5e4d039c1b5b4d58',
}


# B1 current registration (knife three); knife-one identities above remain frozen.
B1_SKIPPED_SHA256 = {'attrs': 'aa26ecc4288db080de1b324205281cab63bf038328ee0d4ed6d688f244d62978', 'cidr_attrs': '5e15a2df581241c49f71f0e4b1906c4df18be99fefbef59b517d3c9790fccdc5'}


def function(source, name):
    starts = list(re.finditer(r'^(?:static |__attribute__|int )[^;{}\n]*\b'+name+r'\([^;{]*\{', source, re.M))
    if len(starts) != 1:
        raise ValueError('B1 function identity: '+name)
    start = starts[0].start()
    # All selected functions use the project's top-level closing-brace format.
    end = source.index('\n}', starts[0].end())+2
    return source[start:end]


def generate(root, output):
    source = (root/'node/bpf/xdrop_main.c').read_text()
    main = function(source, 'xdp_firewall_main')
    extraction_end = main.index('  // Read rule map selector once per packet')
    body = main[main.index('  // Parse Ethernet header'):extraction_end]
    initializers = {}
    cut2 = "struct cond_output out;" in source
    registered = B1_SKIPPED_SHA256 if cut2 else SKIPPED_SHA256
    for variable, digest in registered.items():
        matches = list(re.finditer(r'struct pkt_attrs '+variable+r' = \{.*?\n\s*\};', main, re.S))
        if len(matches) != 1:
            raise ValueError('B1 main initializer identity: '+variable)
        init = matches[0]
        if hashlib.sha256(main[extraction_end:init.start()].encode()).hexdigest() != digest:
            raise ValueError('B1 skipped source interval: '+variable)
        initializers[variable] = init[0]
    declarations = re.findall(r'^#define ANOMALY_(?:LENGTH_MISMATCH|TCP_OFFSET_ONE)[^\n]+', source, re.M)
    if len(declarations) != (0 if cut2 else 2):
        raise ValueError('B1 anomaly constant identities')
    attrs = re.findall(r'struct pkt_attrs \{[^{}]+\};', source)
    if len(attrs) != 1:
        raise ValueError('B1 attrs declaration identity')
    helpers = '\n'.join(function(source, n) for n in ('ipv4_to_mapped', 'ipv6_copy', 'parse_v4_anomaly', 'parse_ipv6_nexthdr', 'xdrop_launder'))
    preamble = '#include "xdrop.h"\n'+'\n'.join(declarations)+'\n'+attrs[0]+'\n'+helpers+'\n'
    preamble += '#define stats_inc(x) ((void)0)\n#define should_filter(x) 1\n#define bpf_redirect_map(map, index, flags) XDP_REDIRECT\n'
    if 'stats_add(' in source:
        preamble += '#define stats_add(slot, value) ((void)0)\n'
    output.mkdir(parents=True, exist_ok=True)
    for name in ('attrs', 'cidr_attrs', 'anomaly'):
        variable = 'attrs' if name == 'anomaly' else name
        entry = 'SEC("xdp") int b1_extract_'+name+'(struct xdp_md *ctx) {\n'
        entry += '  void *data = (void *)(long)ctx->data;\n  void *data_end = (void *)(long)ctx->data_end;\n'
        entry += '  __u32 ingress_ifindex = ctx->ingress_ifindex;\n  int fast_forward = 0;\n'+(body[:body.index('  // Parse L4 ports for TCP/UDP')] if name == 'anomaly' else body)+'\n'+initializers[variable]+'\n'
        entry += '  if (data + sizeof(struct pkt_attrs) > data_end) return XDP_ABORTED;\n'
        entry += '  __builtin_memcpy(data, &'+variable+', sizeof('+variable+'));\n  return 0xB1;\n}\n'
        preamble += entry
    preamble += 'char _license[] SEC("license") = "GPL";\n'
    (output/'extract.c').write_text(preamble)
    print('B1_PROBE source_sha256='+hashlib.sha256(source.encode()).hexdigest()+' probe_sha256='+hashlib.sha256(preamble.encode()).hexdigest())


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--root', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args=p.parse_args()
    generate(args.root, args.output)
