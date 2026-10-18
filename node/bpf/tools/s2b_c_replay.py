#!/usr/bin/env python3
"""Extract and replay the actual C consumers. Never builds a BPF target.

The lexical pass only locates candidate ranges. Clang's AST must confirm each
range byte for byte before it may execute. Unknown AST nodes or dependencies
are an E1 stop, not permission to substitute an implementation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile

NAMES = ("build_rule_key", "build_cidr_rule_key", "pkt_len_matches",
         "tcp_flags_matches", "lookup_rule", "lookup_rule_anomaly",
         "lookup_cidr_rule", "lookup_cidr_rule_anomaly")
KINDS = set("ArraySubscriptExpr BinaryOperator BreakStmt CStyleCastExpr CallExpr CompoundAssignOperator CompoundStmt ConditionalOperator ContinueStmt DeclRefExpr DeclStmt FunctionDecl IfStmt ImplicitCastExpr IntegerLiteral MemberExpr NoInlineAttr ParenExpr ParmVarDecl ReturnStmt UnaryOperator UnusedAttr VarDecl WhileStmt NullStmt UnaryExprOrTypeTraitExpr".split())
CALLS = set(NAMES) | {"config_lookup", "shim_lookup", "bpf_iter_num_new",
                      "bpf_iter_num_next", "bpf_iter_num_destroy",
                      "shim_cond_lookup", "cond_match"}
FIXED = {
    "build_rule_key": "b669119e4397df1d88f2fa8d56f0f5888384c38a9b743174b0fc94c2fd1b308a",
    "build_cidr_rule_key": "facbff4e5109640c7b640524b84042149dd859c99332a1d36336264d94df9a23",
    "pkt_len_matches": "7f01847977078bec40be20925d89223b543553b8210aec9ff70a68152f3c40f7",
    "tcp_flags_matches": "58350ebcff8b8269b28ed4fff344a286e9b614442acda539a3b5eed38dbdda06",
}


class ReplayError(ValueError):
    pass


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_source(root, relative):
    root = Path(root)
    if not root.is_absolute():
        raise ReplayError("absolute source root required")
    base = root.resolve(strict=True)
    path = (base / relative).resolve(strict=True)
    if not path.is_relative_to(base):
        raise ReplayError("source escapes root: " + relative)
    return path.read_bytes()


PRELUDE = b'''#include "xdrop.h"
#include "combo_masks.h"
#undef INLINE
#define INLINE __attribute__((unused))
struct pkt_attrs { __u16 pkt_len; __u8 tcp_flags; __u8 pkt_anomaly; };
struct bpf_iter_num { int pos, end; };
static __u64 *config_lookup(__u64 slot, __u32 idx);
static int bpf_iter_num_new(struct bpf_iter_num *it, int start, int end);
static int *bpf_iter_num_next(struct bpf_iter_num *it);
static void bpf_iter_num_destroy(struct bpf_iter_num *it);
static struct rule_value *shim_lookup(int sel, const void *key, int size);
#define BLACKLIST_LOOKUP(sel,key) shim_lookup(sel,key,40)
#define CIDR_BLACKLIST_LOOKUP(sel,key) shim_lookup(sel,key,16)
'''


# B1 transport is a new registration. Historical PRELUDE and both old shims
# remain unchanged. The replay has no condition rows; flag-zero behavior is
# executed by the actual extracted lookups, not a substitute predicate.
B1_PRELUDE = PRELUDE.replace(
    b"struct pkt_attrs { __u16 pkt_len; __u8 tcp_flags; __u8 pkt_anomaly; };",
    b"struct pkt_attrs { __u16 pkt_len; __u8 tcp_flags; __u8 pkt_anomaly; "
    b"__u8 ttl, dscp, icmp_type, icmp_code, frag_class, icmp_valid; "
    b"__u8 pad[2]; struct cond_output out; };") + b"""
static const struct cond_value *shim_cond_lookup(int sel, const void *key) {
  (void)sel; (void)key; return NULL;
}
static int cond_match(const struct cond_value *c, struct pkt_attrs *a) {
  (void)c; (void)a; return -1;
}
#define COND_LOOKUP(sel,key) shim_cond_lookup(sel,key)
#define CIDR_COND_LOOKUP(sel,key) shim_cond_lookup(sel,key)
"""


# TD-035 is a semantic registration above the unchanged signature classifier.
# Register helper bytes together with every lookup's flags-call spelling.
B1L4_FLAGS_SHA256 = "7086b3ec5729610b3dcadf6b1d44c2485ea649442f1316937288cf9709412082"
B1L4_PRELUDE = B1_PRELUDE.replace(
    b"__u8 pad[2]; struct cond_output out;",
    b"__u8 l4_valid; __u8 pad[1]; struct cond_output out;")
B1_SEMANTICS = {
    "b1": (FIXED["tcp_flags_matches"],
           "tcp_flags_matches(rule,key->protocol,tcp_flags)"),
    "b1l4": (B1L4_FLAGS_SHA256,
             "tcp_flags_matches(rule,key->protocol,tcp_flags,attrs->l4_valid)"),
}


# Knife 5-4 is one complete source generation: two lookups, TD-084 and B2.
# The marker is explicit; absence of retired functions never selects a generation.
CUT54_NAMES = NAMES[:4] + ("lookup_rule", "lookup_cidr_rule")
SOURCE_NAMES = {"historical": NAMES, "b1cut54": CUT54_NAMES}
CUT54_PRELUDE = B1L4_PRELUDE + b"""
static int cond_row_missing;
static __u64 cut54_missing_count;
static void *cut54_missing_lookup(void *map, const void *key) {
  (void)map; (void)key; return &cut54_missing_count;
}
#define bpf_map_lookup_elem(map,key) cut54_missing_lookup(map,key)
"""


def source_generation(source):
    markers = re.findall(rb'^#define B1_LOOKUP_GENERATION ([^\n]+)$', source, re.M)
    if not markers:
        return 'historical'
    if markers != [b'54']:
        raise ReplayError('C source generation marker')
    return 'b1cut54'


def cut54_semantic_generation(pieces):
    calls = []
    for piece in pieces[4:]:
        clean = re.sub(rb'/\*.*?\*/|//[^\n]*', b'', piece, flags=re.S)
        calls.append(re.findall(r'tcp_flags_matches\([^()]*\)', re.sub(rb'\s+', b'', clean).decode()))
    if sha(pieces[3]) != B1L4_FLAGS_SHA256 or calls != [[B1_SEMANTICS['b1l4'][1]]] * 2:
        raise ReplayError('C semantic mixed generations: tcp_flags_matches helper/predicates')
    return 'b1cut54'


def source_semantic_generation(pieces):
    helper = sha(pieces[3])
    calls = []
    for piece in pieces[4:]:
        clean = re.sub(rb'/\*.*?\*/|//[^\n]*', b'', piece, flags=re.S)
        compact = re.sub(rb'\s+', b'', clean).decode()
        calls.append(re.findall(r'tcp_flags_matches\([^()]*\)', compact))
    matches = [g for g, (digest, call) in B1_SEMANTICS.items()
               if helper == digest and calls == [[call]] * 4]
    if len(matches) != 1:
        raise ReplayError("C semantic mixed generations: tcp_flags_matches helper/predicates")
    return matches[0]


def walk(node):
    yield node
    for child in node.get("inner", []):
        yield from walk(child)


def extract(root, output):
    root, output = Path(root), Path(output)
    output.mkdir(parents=True, exist_ok=True)
    source = read_source(root, "node/bpf/xdrop_main.c")
    clean = re.sub(rb'/\*.*?\*/|//[^\n]*', lambda m: re.sub(rb'[^\n]', b' ', m[0]), source, flags=re.S)
    source_gen = source_generation(source)
    names = SOURCE_NAMES[source_gen]
    pieces, manifest = [], {}
    for name in names:
        hits = list(re.finditer(rb'^static[^;{}]*\b' + name.encode() + rb'\s*\([^;{}]*\)\s*\{', clean, re.M))
        if len(hits) != 1:
            raise ReplayError(f"E1: {name} definitions={len(hits)}, want 1")
        start, end, depth = hits[0].start(), hits[0].end(), 1
        while depth and end < len(source):
            depth += (clean[end] == 123) - (clean[end] == 125)
            end += 1
        if depth:
            raise ReplayError("E1: unclosed function " + name)
        piece = source[start:end]
        pieces.append(piece)
        manifest[name] = {"start_line": source[:start].count(b'\n') + 1,
                          "end_line": source[:end].count(b'\n') + 1,
                          "sha256": sha(piece)}
    macros = list(re.finditer(rb'^#define COMBO_WORD_MASK[^\n]*\\\n[^\n]*', source, re.M))
    if len(macros) != 1:
        raise ReplayError("E1: COMBO_WORD_MASK definition count")
    prelude = B1_PRELUDE if b'struct cond_output out;' in source else PRELUDE
    semantics = None
    if b'struct cond_output out;' in source:
        semantics = (cut54_semantic_generation(pieces) if source_gen == 'b1cut54'
                     else source_semantic_generation(pieces))
        if semantics == 'b1cut54':
            prelude = CUT54_PRELUDE
        if semantics == 'b1l4':
            prelude = B1L4_PRELUDE
    unit = prelude + macros[0][0] + b'\n' + b'\n'.join(pieces) + b'\n'
    path = output / "extracted.c"
    path.write_bytes(unit)
    flags = ["clang", "-std=gnu11", "-Wno-duplicate-decl-specifier",
             "-I" + str(root / "node/bpf"), "-I" + str(root / "node/bpf/headers")]
    cmd = flags + ["-fsyntax-only", "-Xclang", "-ast-dump=json", str(path)]
    process = subprocess.run(cmd, capture_output=True)
    (output / "ast.stderr").write_bytes(process.stderr)
    if process.returncode:
        raise ReplayError("E1: C extraction syntax/dependency failure: " + process.stderr.decode())
    tree = json.loads(process.stdout)
    defs = [n for n in tree["inner"] if n.get("kind") == "FunctionDecl" and n.get("name") in names
            and any(c["kind"] == "CompoundStmt" for c in n.get("inner", []))]
    if [n["name"] for n in defs] != list(names):
        raise ReplayError("E1: AST function identities/order differ")
    for node, piece in zip(defs, pieces):
        end = node["range"]["end"]
        actual = unit[node["range"]["begin"]["offset"]:end["offset"] + end["tokLen"]]
        if actual != piece:
            raise ReplayError("E1: AST extraction boundary differs: " + node["name"])
        for child in walk(node):
            if child["kind"] not in KINDS:
                raise ReplayError("E1: unknown AST node " + child["kind"])
            ref = child.get("referencedDecl", {})
            if ref.get("kind") == "FunctionDecl" and ref["name"] not in (CALLS | {'cut54_missing_lookup'} if source_gen == 'b1cut54' else CALLS):
                raise ReplayError("E1: extra dependency " + ref["name"])
    if semantics is not None:
        defs[0]['td035_semantic_generation'] = semantics
    record = {"root": str(root.resolve(strict=True)), "source_sha256": sha(source),
              "unit_sha256": sha(unit), "functions": manifest,
              "macro_sha256": sha(macros[0][0]), "ast_command": cmd,
              "inputs": {p: sha(read_source(root, p)) for p in
                         ("node/bpf/xdrop.h", "node/bpf/combo_masks.h", "node/bpf/headers/bpf_helpers.h")}}
    if semantics is not None:
        record['semantic_generation'] = semantics
    (output / "extraction.json").write_text(json.dumps(record, indent=2) + "\n")
    return unit, defs, record, flags


def spelling(unit, node):
    rg = node["range"]
    a, b = rg["begin"], rg["end"]
    a, b = a.get("expansionLoc", a), b.get("expansionLoc", b)
    raw = unit[a["offset"]:b["offset"] + b["tokLen"]].decode()
    raw = re.sub(r'/\*.*?\*/|//[^\n]*', '', raw, flags=re.S)
    return re.sub(r'\s+', '', raw)


def interface_generation(defs):
    """Register signatures as complete four-function generations, not per call."""
    if [n.get('name') for n in defs] == list(CUT54_NAMES):
        for node in defs[4:]:
            key = 'struct cidr_rule_key *' if 'cidr' in node['name'] else 'struct rule_key *'
            expected = [('key', key), ('matched_key', key), ('attrs', 'struct pkt_attrs *'),
                        ('rule_sel', 'int'), ('slot', '__u64')]
            children = node.get('inner', [])
            actual = [(p.get('name'), p.get('type', {}).get('qualType')) for p in children if p['kind'] == 'ParmVarDecl']
            if actual != expected or node.get('type', {}).get('qualType') != 'struct rule_value *(' + ', '.join(t for _, t in expected) + ')' or node.get('variadic', False) or node.get('storageClass') != 'static' or sum(p['kind'] == 'NoInlineAttr' for p in children) != 1:
                raise ReplayError('C interface mixed generations: b1cut54 ' + node['name'])
        return 'b1cut54'
    lookups = defs[4:]
    if [n.get("name") for n in lookups] != list(NAMES[4:]):
        raise ReplayError("C interface function identities/order")
    actual, registered = [], {g: [] for g in ("packed", "attrs", "b1")}
    for node in lookups:
        name = node["name"]
        key_type = "struct cidr_rule_key *" if "cidr" in name else "struct rule_key *"
        common = [("key", key_type), ("matched_key", key_type)]
        signatures = {
            "packed": common + [("len_flags", "__u32"),
                ("anom_sel", "__u32") if "anomaly" in name else ("rule_sel", "int"),
                ("slot", "__u64")],
            "attrs": common + [("attrs", "const struct pkt_attrs *"),
                ("rule_sel", "int"), ("slot", "__u64")],
            "b1": common + [("attrs", "const struct pkt_attrs *" if "anomaly" in name
                             else "struct pkt_attrs *"), ("rule_sel", "int"), ("slot", "__u64")],
        }
        children = node.get("inner", [])
        params = [(p.get("name"), p.get("type", {}).get("qualType"))
                  for p in children if p["kind"] == "ParmVarDecl"]
        signature = (params, node.get("type", {}).get("qualType"))
        actual.append(signature)
        for generation, expected in signatures.items():
            registered[generation].append((expected,
                "struct rule_value *(" + ", ".join(t for _, t in expected) + ")"))
        if (not any(signature == v[-1] for v in registered.values()) or
                node.get("variadic", False) or node.get("storageClass") != "static" or
                sum(p["kind"] == "NoInlineAttr" for p in children) != 1):
            raise ReplayError("C interface signature: " + name)
    matches = [g for g, group in registered.items() if group == actual]
    if len(matches) != 1:
        raise ReplayError("C interface mixed generations")
    return matches[0]


# Registered from the controlled packed prefixes, replacing only argument
# unpacking. Expectations are static; they are never derived from tested ASTs.
_ATTRS_PREFIX = ['__u16pkt_len=attrs->pkt_len;', '__u8tcp_flags=attrs->tcp_flags;']
_ANOMALY_PREFIX = ['__u8pkt_anomaly=attrs->pkt_anomaly;']
_EXACT_CONFIG = [
    '__u32bl_count_idx=CONFIG_BLACKLIST_COUNT;',
    '__u64*bl_count=config_lookup(slot,bl_count_idx);',
    'if(!bl_count||*bl_count==0){returnNULL;}',
    '__u32bitmap_idx=CONFIG_RULE_BITMAP;',
    '__u64*bitmap_ptr=config_lookup(slot,bitmap_idx);',
    '__u64bitmap=bitmap_ptr?*bitmap_ptr:~0ULL;',
]
_CIDR_CONFIG = [
    '__u32cnt_idx=CONFIG_CIDR_RULE_COUNT;',
    '__u64*cnt=config_lookup(slot,cnt_idx);',
    'if(!cnt||*cnt==0)returnNULL',
    '__u32bm_idx=CONFIG_CIDR_BITMAP;',
    '__u64*bm_ptr=config_lookup(slot,bm_idx);',
    '__u64bitmap=bm_ptr?*bm_ptr:~0ULL;',
]
_ITERATOR_PREFIX = [
    'bitmap&=COMBO_VALID_BITMAP', 'structrule_value*rule=NULL;',
    'structbpf_iter_numiter;', 'int*pos;',
    'bpf_iter_num_new(&iter,0,COMBO_ORDER_LEN)',
]
PREFIXES = {
    'lookup_rule': _ATTRS_PREFIX + _EXACT_CONFIG + _ITERATOR_PREFIX,
    'lookup_rule_anomaly': _ATTRS_PREFIX + _ANOMALY_PREFIX + _EXACT_CONFIG + _ITERATOR_PREFIX,
    'lookup_cidr_rule': _ATTRS_PREFIX + _CIDR_CONFIG + _ITERATOR_PREFIX,
    'lookup_cidr_rule_anomaly': _ATTRS_PREFIX + _ANOMALY_PREFIX + _CIDR_CONFIG + _ITERATOR_PREFIX,
}


def check_attrs_widths(root, output):
    """Compile the production declaration/assertions on the host, never BPF."""
    source = read_source(root, 'node/bpf/xdrop_main.c').decode()
    declarations = list(re.finditer(r'struct pkt_attrs\s*\{[^{}]*\};', source))
    if len(declarations) != 1:
        raise ReplayError('C attrs declaration count')
    assertions = re.findall(r'_Static_assert\(sizeof\(\(\(struct pkt_attrs \*\)0\)->\w+\).*?;', source)
    if len(assertions) != 3:
        raise ReplayError('C attrs width assertion count')
    output = Path(output); output.mkdir(parents=True, exist_ok=True)
    path = output / 'attrs-widths.c'
    path.write_text('#include "xdrop.h"\n' + declarations[0][0] + '\n' + '\n'.join(assertions) + '\n')
    cmd = ['clang', '-std=gnu11', '-fsyntax-only', '-I' + str(Path(root) / 'node/bpf'),
           '-I' + str(Path(root) / 'node/bpf/headers'), str(path)]
    result = subprocess.run(cmd, capture_output=True, text=True)
    (output / 'widths.log').write_text(result.stdout + result.stderr)
    (output / 'widths.command.json').write_text(json.dumps({'command': cmd, 'rc': result.returncode}) + '\n')
    if result.returncode:
        raise ReplayError('C attrs width compilation: ' + result.stderr)
    return 3


def check_old_symbols(root):
    count = len(re.findall(r'len_flags|anom_sel', read_source(root, 'node/bpf/xdrop_main.c').decode()))
    if count:
        raise ReplayError('C old packing symbols: ' + str(count))
    return count


def check_cut54_source(root, output):
    unit, defs, record, flags = extract(root, output)
    generation = interface_generation(defs)
    if generation != 'b1cut54':
        raise ReplayError('C current interface must be attrs or b1')
    # These helpers are outside B0's mutation scope. Their actual bytes are
    # replayed even in the bottom-level mutation entrypoint.
    for name, expected in FIXED.items():
        if name == 'tcp_flags_matches' and record.get('semantic_generation') == 'b1cut54':
            expected = B1L4_FLAGS_SHA256
        if record["functions"][name]["sha256"] != expected:
            raise ReplayError("C helper source contract: " + name)
    for node in defs[4:]:
        name = node["name"]
        body = next(c for c in node["inner"] if c["kind"] == "CompoundStmt")
        stmts = body["inner"]
        loops = [n for n in stmts if n["kind"] == "WhileStmt"]
        if len(loops) != 1:
            raise ReplayError(f"C control flow {name}: while count={len(loops)}")
        loop = loops[0]
        ix = stmts.index(loop)
        if spelling(unit, stmts[ix - 1]) != 'bpf_iter_num_new(&iter,0,COMBO_ORDER_LEN)':
            raise ReplayError("C iterator upper bound: " + name)
        if [spelling(unit, n) for n in stmts[ix + 1:]] != ['bpf_iter_num_destroy(&iter)', 'returnrule']:
            raise ReplayError("C destroy/return path: " + name)
        filters = [n for n in stmts[:ix] if spelling(unit, n) == 'bitmap&=COMBO_VALID_BITMAP']
        if len(filters) != 1:
            raise ReplayError("C valid bitmap filter: " + name)
        inner = loop['inner']
        if len(inner) != 2 or spelling(unit, inner[0]) != '(pos=bpf_iter_num_next(&iter))' or inner[1]['kind'] != 'CompoundStmt':
            raise ReplayError("C iterator condition: " + name)
        seq = inner[1]['inner']
        conditional = True
        want_count = 11 if 'cidr' in name else 10
        if len(seq) != want_count:
            raise ReplayError(f"C loop statement/control-flow count {name}: {len(seq)} != {want_count}")
        builder = 'build_cidr_rule_key' if 'cidr' in name else 'build_rule_key'
        lookup = 'CIDR_BLACKLIST_LOOKUP' if 'cidr' in name else 'BLACKLIST_LOOKUP'
        if spelling(unit, seq[0]) != '__u32i=(__u32)*pos;':
            raise ReplayError("C unsigned position origin: " + name)
        for index, cond, exitkind, label in [(1, 'i>=COMBO_ORDER_LEN', 'BreakStmt', 'position'),
                                           (3, 'b>=COMBO_MAX', 'BreakStmt', 'combo'),
                                           (4, '!(bitmap&(1ULL<<b))', 'ContinueStmt', 'bitmap miss')]:
            guard = seq[index]
            children = guard.get('inner', [])
            if guard['kind'] != 'IfStmt' or len(children) != 2 or spelling(unit, children[0]) != cond or children[1]['kind'] != exitkind:
                raise ReplayError(f"C {label} dominating guard: {name}")
        if spelling(unit, seq[2]) != '__u32b=combo_order[i];':
            raise ReplayError("C checked combo origin: " + name)
        if 'cidr' in name:
            if spelling(unit, seq[5]) != 'if(((combo_field_mask[b]&CM_SRC_IP)&&key->src_id==0)||((combo_field_mask[b]&CM_DST_IP)&&key->dst_id==0))continue':
                raise ReplayError('C TD-084 zero-ID dominating guard: ' + name)
            seq = seq[:5] + seq[6:]
        if spelling(unit, seq[5]) != builder+'(matched_key,key,b)':
            raise ReplayError("C builder combo origin: " + name)
        # Macro expansion range ends on the invocation's identifier; inspect
        # the assignment AST and the original invocation from that statement.
        if seq[6]['kind'] != 'BinaryOperator' or seq[6].get('opcode') != '=':
            raise ReplayError("C map assignment: " + name)
        start = seq[6]['range']['begin']['offset']
        text = re.sub(rb'\s+', b'', unit[start:unit.index(b';', start)]).decode()
        if text != 'rule='+lookup+'(rule_sel,matched_key)':
            raise ReplayError("C map selection/key origin: " + name)
        pred = 'rule&&pkt_len_matches(rule,pkt_len)&&tcp_flags_matches(rule,key->protocol,tcp_flags)&&'
        if record.get('semantic_generation') == 'b1cut54':
            pred = pred.replace('tcp_flags_matches(rule,key->protocol,tcp_flags)', B1_SEMANTICS['b1l4'][1])
        pred += ('rule->match_anomaly!=0&&(pkt_anomaly&rule->match_anomaly)!=0'
                 if 'anomaly' in name else 'rule->match_anomaly==0')
        if conditional:
            cond_lookup = 'CIDR_COND_LOOKUP' if 'cidr' in name else 'COND_LOOKUP'
            expected_branch = (
                'if(rule&&(rule->pad2[0]&RULE_HAS_CONDITIONS)){'
                'conststructcond_value*cv=' + cond_lookup + '(rule_sel,matched_key);'
                'if(!cv){__u32zero=0;__u64*missing=bpf_map_lookup_elem(&cond_row_missing,&zero);'
                'if(missing)(*missing)++;}'
                'if(cv&&cond_match(cv,attrs)>=0)break;rule=NULL;continue;}')
            if seq[7]['kind'] != 'IfStmt' or spelling(unit, seq[7]) != expected_branch:
                raise ReplayError('C B1 condition lookup/output/fallback contract: ' + name)
        match = seq[8 if conditional else 7]
        if match['kind'] != 'IfStmt' or len(match.get('inner', [])) != 2 or spelling(unit, match['inner'][0]) != pred or match['inner'][1]['kind'] != 'BreakStmt':
            raise ReplayError("C full post-match predicate/break: " + name)
        if spelling(unit, seq[9 if conditional else 8]) != 'rule=NULL':
            raise ReplayError("C failed predicate reset: " + name)
        # Last, so the existing fine-grained assertions retain their red points.
        if [spelling(unit, n) for n in stmts[:ix]] != PREFIXES[name]:
            raise ReplayError('C complete pre-loop prefix: ' + name)
    return record


def check_source(root, output):
    if source_generation(read_source(root, 'node/bpf/xdrop_main.c')) == 'b1cut54':
        return check_cut54_source(root, output)
    unit, defs, record, flags = extract(root, output)
    generation = interface_generation(defs)
    if generation not in ('attrs', 'b1'):
        raise ReplayError('C current interface must be attrs or b1')
    # These helpers are outside B0's mutation scope. Their actual bytes are
    # replayed even in the bottom-level mutation entrypoint.
    for name, expected in FIXED.items():
        if name == 'tcp_flags_matches' and record.get('semantic_generation') == 'b1l4':
            expected = B1L4_FLAGS_SHA256
        if record["functions"][name]["sha256"] != expected:
            raise ReplayError("C helper source contract: " + name)
    for node in defs[4:]:
        name = node["name"]
        body = next(c for c in node["inner"] if c["kind"] == "CompoundStmt")
        stmts = body["inner"]
        loops = [n for n in stmts if n["kind"] == "WhileStmt"]
        if len(loops) != 1:
            raise ReplayError(f"C control flow {name}: while count={len(loops)}")
        loop = loops[0]
        ix = stmts.index(loop)
        if spelling(unit, stmts[ix - 1]) != 'bpf_iter_num_new(&iter,0,COMBO_ORDER_LEN)':
            raise ReplayError("C iterator upper bound: " + name)
        if [spelling(unit, n) for n in stmts[ix + 1:]] != ['bpf_iter_num_destroy(&iter)', 'returnrule']:
            raise ReplayError("C destroy/return path: " + name)
        filters = [n for n in stmts[:ix] if spelling(unit, n) == 'bitmap&=COMBO_VALID_BITMAP']
        if len(filters) != 1:
            raise ReplayError("C valid bitmap filter: " + name)
        inner = loop['inner']
        if len(inner) != 2 or spelling(unit, inner[0]) != '(pos=bpf_iter_num_next(&iter))' or inner[1]['kind'] != 'CompoundStmt':
            raise ReplayError("C iterator condition: " + name)
        seq = inner[1]['inner']
        conditional = generation == 'b1' and 'anomaly' not in name
        want_count = 10 if conditional else 9
        if len(seq) != want_count:
            raise ReplayError(f"C loop statement/control-flow count {name}: {len(seq)} != {want_count}")
        builder = 'build_cidr_rule_key' if 'cidr' in name else 'build_rule_key'
        lookup = 'CIDR_BLACKLIST_LOOKUP' if 'cidr' in name else 'BLACKLIST_LOOKUP'
        if spelling(unit, seq[0]) != '__u32i=(__u32)*pos;':
            raise ReplayError("C unsigned position origin: " + name)
        for index, cond, exitkind, label in [(1, 'i>=COMBO_ORDER_LEN', 'BreakStmt', 'position'),
                                           (3, 'b>=COMBO_MAX', 'BreakStmt', 'combo'),
                                           (4, '!(bitmap&(1ULL<<b))', 'ContinueStmt', 'bitmap miss')]:
            guard = seq[index]
            children = guard.get('inner', [])
            if guard['kind'] != 'IfStmt' or len(children) != 2 or spelling(unit, children[0]) != cond or children[1]['kind'] != exitkind:
                raise ReplayError(f"C {label} dominating guard: {name}")
        if spelling(unit, seq[2]) != '__u32b=combo_order[i];':
            raise ReplayError("C checked combo origin: " + name)
        if spelling(unit, seq[5]) != builder+'(matched_key,key,b)':
            raise ReplayError("C builder combo origin: " + name)
        # Macro expansion range ends on the invocation's identifier; inspect
        # the assignment AST and the original invocation from that statement.
        if seq[6]['kind'] != 'BinaryOperator' or seq[6].get('opcode') != '=':
            raise ReplayError("C map assignment: " + name)
        start = seq[6]['range']['begin']['offset']
        text = re.sub(rb'\s+', b'', unit[start:unit.index(b';', start)]).decode()
        if text != 'rule='+lookup+'(rule_sel,matched_key)':
            raise ReplayError("C map selection/key origin: " + name)
        pred = 'rule&&pkt_len_matches(rule,pkt_len)&&tcp_flags_matches(rule,key->protocol,tcp_flags)&&'
        if record.get('semantic_generation') == 'b1l4':
            pred = pred.replace('tcp_flags_matches(rule,key->protocol,tcp_flags)', B1_SEMANTICS['b1l4'][1])
        pred += ('rule->match_anomaly!=0&&(pkt_anomaly&rule->match_anomaly)!=0'
                 if 'anomaly' in name else 'rule->match_anomaly==0')
        if conditional:
            cond_lookup = 'CIDR_COND_LOOKUP' if 'cidr' in name else 'COND_LOOKUP'
            expected_branch = (
                'if(rule&&(rule->pad2[0]&RULE_HAS_CONDITIONS)){'
                'conststructcond_value*cv=' + cond_lookup + '(rule_sel,matched_key);'
                'if(cv&&cond_match(cv,attrs)>=0)break;rule=NULL;continue;}')
            if seq[7]['kind'] != 'IfStmt' or spelling(unit, seq[7]) != expected_branch:
                raise ReplayError('C B1 condition lookup/output/fallback contract: ' + name)
        match = seq[8 if conditional else 7]
        if match['kind'] != 'IfStmt' or len(match.get('inner', [])) != 2 or spelling(unit, match['inner'][0]) != pred or match['inner'][1]['kind'] != 'BreakStmt':
            raise ReplayError("C full post-match predicate/break: " + name)
        if spelling(unit, seq[9 if conditional else 8]) != 'rule=NULL':
            raise ReplayError("C failed predicate reset: " + name)
        # Last, so the existing fine-grained assertions retain their red points.
        if [spelling(unit, n) for n in stmts[:ix]] != PREFIXES[name]:
            raise ReplayError('C complete pre-loop prefix: ' + name)
    return record


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--root', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    ap.add_argument('--extract-only', action='store_true')
    ap.add_argument('--interface-counts', action='store_true')
    args = ap.parse_args()
    if args.interface_counts:
        _, defs, _, _ = extract(args.root, args.output)
        interface_generation(defs)
        counts = [sum(p['kind'] == 'ParmVarDecl' for p in n['inner']) for n in defs[4:]]
        print('/'.join(map(str, [len(counts)] + counts)))
        return
    elif args.extract_only:
        _, _, record, _ = extract(args.root, args.output)
    else:
        record = check_source(args.root, args.output)
    print(json.dumps(record, sort_keys=True))


if __name__ == '__main__':
    main()

# Transport and deterministic helper shims only. The unit assembled above is
# included unchanged: there is no substitute lookup, predicate or builder here.
PACKED_SHIM = r'''
#include <stdlib.h>
static __u64 cfg_count, cfg_bitmap;
static int fallback, selected, injected, override_pos, calls_new, calls_destroy;
static int probe_count, probe_pos[128], probe_sel[128], probe_hit[128], probe_size[128];
static unsigned char probe_keys[128][40];
static int current_pos, rule_count, rule_sizes[8];
static unsigned char rule_keys[8][40];
static struct rule_value values[8];
static __u64 *config_lookup(__u64 slot, __u32 idx) {
  (void)slot;
  if (idx == CONFIG_BLACKLIST_COUNT || idx == CONFIG_CIDR_RULE_COUNT) return &cfg_count;
  if (idx == CONFIG_RULE_BITMAP || idx == CONFIG_CIDR_BITMAP) return fallback ? NULL : &cfg_bitmap;
  abort();
}
static int bpf_iter_num_new(struct bpf_iter_num *it, int start, int end) {
  calls_new++; it->pos = start - 1; it->end = end; return 0;
}
static int *bpf_iter_num_next(struct bpf_iter_num *it) {
  if (injected) { injected = 0; it->pos = override_pos; current_pos = it->pos; return &it->pos; }
  if (++it->pos >= it->end) return NULL;
  current_pos = it->pos; return &it->pos;
}
static void bpf_iter_num_destroy(struct bpf_iter_num *it) { (void)it; calls_destroy++; }
static struct rule_value *shim_lookup(int sel, const void *key, int size) {
  if (probe_count >= 128) abort();
  int p = probe_count++; probe_pos[p] = current_pos; probe_sel[p] = sel;
  probe_size[p] = size; memcpy(probe_keys[p], key, size); probe_hit[p] = -1;
  if (sel != selected) return NULL;
  for (int n = 0; n < rule_count; n++) {
    if (size == rule_sizes[n] && memcmp(key, rule_keys[n], size) == 0) {
      probe_hit[p] = n; return &values[n];
    }
  }
  return NULL;
}
static void decode(const char *s, unsigned char *dest, int size) {
  if ((int)strlen(s) != size * 2) abort();
  for (int n = 0; n < size; n++) { unsigned v; if (sscanf(s + n*2, "%2x", &v) != 1) abort(); dest[n] = (unsigned char)v; }
}
static void print_hex(const unsigned char *s, int size) { for (int n=0;n<size;n++) printf("%02x",s[n]); }
int main(void) {
  int stage, len_flags, anom, has_override, pos, cfg_present;
  unsigned long long bitmap;
  char key_hex[81], value_hex[65];
  while (scanf("%d %llu %d %d %d %d %d %d %d %80s", &stage, &bitmap, &len_flags, &anom,
               &selected, &fallback, &has_override, &pos, &cfg_present, key_hex) == 10) {
    if (stage < 0 || stage > 3 || scanf("%d", &rule_count) != 1 || rule_count < 0 || rule_count > 8) abort();
    union { __u64 aligned[5]; struct rule_key exact; struct cidr_rule_key cidr; } key = {0}, matched = {0};
    int size = stage < 2 ? 40 : 16;
    decode(key_hex, (unsigned char *)&key, size);
    for (int n=0;n<rule_count;n++) {
      if (scanf("%80s %64s",key_hex,value_hex) != 2) abort();
      decode(key_hex,rule_keys[n],size); decode(value_hex,(unsigned char *)&values[n],32); rule_sizes[n]=size;
    }
    cfg_count = cfg_present ? (rule_count ? rule_count : 1) : 0; cfg_bitmap=bitmap;
    injected=has_override;override_pos=pos;calls_new=0;calls_destroy=0;probe_count=0;
    struct rule_value *answer = NULL;
    switch (stage) {
      case 0: answer=lookup_rule(&key.exact,&matched.exact,len_flags,selected,0); break;
      case 1: answer=lookup_rule_anomaly(&key.exact,&matched.exact,len_flags,(anom<<1)|selected,0); break;
      case 2: answer=lookup_cidr_rule(&key.cidr,&matched.cidr,len_flags,selected,0); break;
      case 3: answer=lookup_cidr_rule_anomaly(&key.cidr,&matched.cidr,len_flags,(anom<<1)|selected,0); break;
    }
    int winner=answer ? (int)(answer-values) : -1;
    printf("{\"winner\":%d,\"new\":%d,\"destroy\":%d,\"probes\":[",winner,calls_new,calls_destroy);
    for (int n=0;n<probe_count;n++) {
      if(n)printf(",");
      printf("{\"position\":%d,\"selector\":%d,\"hit\":%d,\"key\":\"",probe_pos[n],probe_sel[n],probe_hit[n]);
      print_hex(probe_keys[n],probe_size[n]);printf("\"}");
    }
    printf("]}\n");
  }
  if (!feof(stdin)) return 3;
  return 0;
}
'''


# Only the invocation boundary differs; transport and probe accounting are shared.
ATTRS_SHIM = PACKED_SHIM.replace(
    "    switch (stage) {",
    "    struct pkt_attrs attrs = { .pkt_len = (__u16)(len_flags >> 8), "
    ".tcp_flags = (__u8)(len_flags & 0xFF), .pkt_anomaly = (__u8)anom };\n"
    "    switch (stage) {")
ATTRS_SHIM = ATTRS_SHIM.replace(
    "len_flags,(anom<<1)|selected,0", "&attrs,selected,0").replace(
    "len_flags,selected,0", "&attrs,selected,0")


B1_SHIM = ATTRS_SHIM.replace(
    ".pkt_anomaly = (__u8)anom };",
    ".pkt_anomaly = (__u8)anom, .ttl = 0, .dscp = 0, .icmp_type = 0, "
    ".icmp_code = 0, .frag_class = 0, .icmp_valid = 0, .pad = {0, 0}, "
    ".out = {.winner = COND_NO_WINNER, .action = 0, .pad = {0, 0}, "
    ".rate = 0, .rule_id = 0} };")


B1L4_SHIM = B1_SHIM.replace(
    ".icmp_valid = 0, .pad = {0, 0},",
    ".icmp_valid = 0, .l4_valid = 1, .pad = {0},")


CUT54_SHIM = B1L4_SHIM.replace(
    '      case 1: answer=lookup_rule_anomaly(&key.exact,&matched.exact,&attrs,selected,0); break;\n', '').replace(
    '      case 3: answer=lookup_cidr_rule_anomaly(&key.cidr,&matched.cidr,&attrs,selected,0); break;\n', '').replace(
    'stage < 0 || stage > 3', '(stage != 0 && stage != 2)').replace(
    '    switch (stage) {', '    cut54_missing_count = 0;\n    switch (stage) {').replace(
    '    printf("]}\\n");', '    printf("],\\"cond_row_missing\\":%llu}\\n", (unsigned long long)cut54_missing_count);')


def select_shim(defs):
    """Shared by generation and authenticated consumption after extraction.

    This selects transport only. The caller still explicitly authenticates the
    s2a/s2b source and semantic contract independently of interface generation.
    """
    generation = interface_generation(defs)
    if generation == "b1":
        generation = defs[0]['td035_semantic_generation']
    return generation, {"packed": PACKED_SHIM, "attrs": ATTRS_SHIM,
                        "b1": B1_SHIM, "b1l4": B1L4_SHIM, "b1cut54": CUT54_SHIM}[generation]


def build_replay(root, output):
    """Bottom-level semantic entrypoint for certified input or isolated mutants.

    Authentication belongs to check_s2b; this path deliberately does not apply
    source hashes first, so source mutants can reach the actual C assertions.
    AST boundary, unknown syntax and dependency checks still always apply.
    """
    unit, defs, record, flags = extract(root, output)
    generation, shim = select_shim(defs)
    record["interface_generation"] = generation
    record["shim_sha256"] = sha(shim.encode())
    output = Path(output)
    source = output / 'replay.c'
    source.write_bytes(unit + shim.encode())
    binary = output / 'replay'
    command = flags + ['-O1', '-g', '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                       str(source), '-o', str(binary)]
    p = subprocess.run(command, capture_output=True, text=True)
    (output / 'build.log').write_text(p.stdout + p.stderr)
    (output / 'build.rc').write_text(str(p.returncode) + '\n')
    if p.returncode:
        raise ReplayError('C host replay compilation failed: ' + p.stderr)
    record['build_command'] = command
    record['executable_sha256'] = sha(binary.read_bytes())
    (output / 'replay-manifest.json').write_text(json.dumps(record, indent=2) + '\n')
    return binary, record


def run_replay(binary, inputs, output):
    p = subprocess.run([str(binary)], input=''.join(inputs), capture_output=True, text=True)
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    (output / 'stdin.txt').write_text(''.join(inputs))
    (output / 'stdout.jsonl').write_text(p.stdout)
    (output / 'stderr.log').write_text(p.stderr)
    (output / 'rc.txt').write_text(str(p.returncode) + '\n')
    if p.returncode:
        raise ReplayError(f'C execution RC={p.returncode}: {p.stderr}')
    rows = [json.loads(line) for line in p.stdout.splitlines()]
    if len(rows) != len(inputs):
        raise ReplayError(f'C output count={len(rows)}, want {len(inputs)}')
    return rows
