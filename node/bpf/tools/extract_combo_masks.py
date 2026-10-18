#!/usr/bin/env python3
"""
从 xdrop_main.c 的展开代码里**机械提取** combo 掩码。

为什么存在
──────────
M1 把四个查表函数各 33 段展开的 combo 匹配块换成「掩码表 + 一个循环」。
M1-b 要求掩码**从原展开代码提取，不照注释转录** —— 注释和代码可以不一致，
而判据只认代码。本脚本就是那个提取器，也是 M1 验收判据 ① 的量具。

它验什么
────────
① 内容：四个函数各提一份掩码表，**四份必须逐位相同**。
② 顺序：按块在**源文件里出现的先后**记录，不按编号排序 —— 查表是
   「首次命中即 return」，所以顺序承重。若源码顺序与编号升序不一致，
   本脚本会报出来而不是悄悄排序掉。
③ 有效编号位图：本脚本从 xdrop.h 名册机械计算实际编号集合，并与生成头里的
   COMBO_VALID_BITMAP 对撞。空洞编号只作为派生报告，不再单独写死。

⛔ 三条设计纪律
───────────────
1. **不设默认值。** 某个字段在块里既没被赋值也没被清零 ⇒ 直接报错退出，
   不猜「大概是通配吧」。默认值会替缺陷挑一个它不在的位置。
2. **不排序、不去重。** 原样保留源码顺序，让顺序缺陷可见。
3. **认不出的行 ⇒ 报错，不跳过。** 静默跳过会让「没提取到」和「提取到通配」同形。

用法
────
    python3 node/bpf/tools/extract_combo_masks.py            # 人读的报告
    python3 node/bpf/tools/extract_combo_masks.py --json     # 机器读
    python3 node/bpf/tools/extract_combo_masks.py --emit-c   # 生成 C 掩码表
退出码 0 = 四份一致且无异常；非 0 = 有不一致或提取异常。
"""

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SRC = os.path.join(HERE, os.pardir, "xdrop_main.c")
DEFAULT_HDR = os.path.join(HERE, os.pardir, "xdrop.h")
DEFAULT_MASK_HDR = os.path.join(HERE, os.pardir, "combo_masks.h")
DEFAULT_BASELINE = os.path.join(HERE, "combo_masks_pre_m1.json")

# 五个逻辑字段的规范顺序 == 掩码的位序。
# 精确表叫 src_ip/dst_ip，CIDR 表叫 src_id/dst_id，是同一个逻辑字段的两种载体。
FIELDS = ["src_ip", "dst_ip", "src_port", "dst_port", "protocol"]
FIELD_ALIASES = {"src_id": "src_ip", "dst_id": "dst_ip"}

BLOCK_START = re.compile(r"^\s*if \(bitmap & \(1ULL << (COMBO_[A-Z_0-9]+)\)\) \{")
LOOKUP_CALL = re.compile(r"^\s*rule = \w*LOOKUP\w*\(")

# 键构造的四种合法形状。取 == 从 key 复制；零 == 显式清零。
PAT_TAKE_IP = re.compile(r"^\s*ip_copy\(&(\w+)\.(\w+), &key->(\w+)\);")
PAT_ZERO_IP = re.compile(r"^\s*ip_zero\(&(\w+)\.(\w+)\);")
PAT_TAKE_SC = re.compile(r"^\s*(\w+)\.(\w+) = key->(\w+);")
PAT_ZERO_SC = re.compile(r"^\s*(\w+)\.(\w+) = 0;")
# pad 清零与本掩码无关，但必须被显式认出，不能落进「认不出」。
PAT_PAD = re.compile(r"^\s*\w+\.pad\[0\] =")


# Independent frozen name -> ID authority from 126b4cb xdrop.h
# SHA256 5beb7825c01f141f054981cbd810cb08b7ca9721765219e447583ecca1cb62cf.
# Historical rows must be fully validated before the retirement projection.
HISTORICAL_ROSTER = {'COMBO_EXACT_5TUPLE': 0,
 'COMBO_WILDCARD_SRC_IP': 1,
 'COMBO_WILDCARD_SRC_IP_PORT': 2,
 'COMBO_DST_IP_PROTO': 3,
 'COMBO_DST_IP_ONLY': 4,
 'COMBO_PROTO_ONLY': 5,
 'COMBO_SRC_PORT_ONLY': 6,
 'COMBO_DST_PORT_ONLY': 7,
 'COMBO_SRC_IP_ONLY': 8,
 'COMBO_SRC_IP_PROTO': 9,
 'COMBO_SRC_DST_IP': 10,
 'COMBO_SRC_IP_DST_PORT': 11,
 'COMBO_DST_IP_DST_PORT': 12,
 'COMBO_SRC_DST_IP_PROTO': 13,
 'COMBO_SRC_IP_DST_PORT_PROTO': 14,
 'COMBO_SRC_PORT_PROTO': 15,
 'COMBO_DST_PORT_PROTO': 16,
 'COMBO_SRC_IP_SRC_PORT': 17,
 'COMBO_SRC_IP_SRC_PORT_PROTO': 18,
 'COMBO_DST_IP_DST_PORT_PROTO': 20,
 'COMBO_SRC_DST_IP_DST_PORT': 21,
 'COMBO_SRC_DST_IP_DST_PORT_PROTO': 22,
 'COMBO_SRC_IP_PORTS': 23,
 'COMBO_SRC_IP_PORTS_PROTO': 24,
 'COMBO_DST_IP_SRC_PORT': 25,
 'COMBO_DST_IP_SRC_PORT_PROTO': 26,
 'COMBO_PORTS_ONLY': 27,
 'COMBO_PORTS_PROTO': 28,
 'COMBO_SRC_DST_IP_SRC_PORT': 29,
 'COMBO_SRC_DST_IP_SRC_PORT_PROTO': 30,
 'COMBO_DST_IP_PORTS': 31,
 'COMBO_DST_IP_PORTS_PROTO': 32,
 'COMBO_ALL_EXCEPT_PROTO': 33}
RETIRED = {20, 32}
CURRENT_ROSTER = {name: n for name, n in HISTORICAL_ROSTER.items() if n not in RETIRED}

class ExtractError(Exception):
    pass


def canon(field):
    return FIELD_ALIASES.get(field, field)


def parse_header_roster(path):
    """读 xdrop.h 的 #define 名册与**注释掩码**。允许名字与编号被反斜杠断在两行。

    返回 (roster, comment_masks)。注释掩码是一条**独立于代码**的取证路径
    （F-086 的三方佐证之一）：注释写的是「src_ip + * + * + * + protocol」这种
    定位式的五槽，与从展开代码提取的掩码对撞，能抓出「注释与代码不符」。
    ⛔ 注释**不是**判据来源（M1-b 禁止照注释转录），它只当对照组。
    """
    text = open(path, encoding="utf-8").read()
    roster, comments = {}, {}
    pat = re.compile(r"#define\s+(COMBO_[A-Z_0-9]+)[\s\\]+(\d+)[ \t]*(?://[ \t]*(.*))?")
    for name, num, note in pat.findall(text):
        if name == "COMBO_MAX":
            continue
        if name in roster:
            raise ExtractError(f"头文件里 {name} 定义了两次")
        roster[name] = int(num)
        if note:
            m = parse_comment_mask(note)
            if m is not None:
                comments[name] = m
    dupes = [n for n in set(roster.values()) if list(roster.values()).count(n) > 1]
    if dupes:
        raise ExtractError(f"头文件里有重号: {sorted(dupes)}")
    return roster, comments


def parse_comment_mask(note):
    """把 '* + dst_ip + * + dst_port + protocol' 解析成掩码。看不懂就返回 None。"""
    slots = [s.strip() for s in note.split("+")]
    if len(slots) != len(FIELDS):
        return None
    mask = 0
    for bit, (slot, field) in enumerate(zip(slots, FIELDS)):
        if slot == "*":
            continue
        if canon(slot) != field:
            return None          # 槽位与规范顺序对不上 ⇒ 不当对照组用，别硬解
        mask |= 1 << bit
    return mask


def find_functions(lines):
    """定位含 combo 块的函数。返回 [(名字, 起行, 止行)]，行号 0-based 半开区间。"""
    starts = []
    for i, ln in enumerate(lines):
        m = re.match(r"^(?:static.*)?\b(lookup_\w+)\(", ln.strip())
        is_definition = ln.lstrip().startswith("static") or (
            i > 0 and lines[i - 1].lstrip().startswith("static")
        )
        if (m and is_definition and
                ("lookup_rule" in m.group(1) or "lookup_cidr_rule" in m.group(1))):
            starts.append((m.group(1), i))
    if not starts:
        raise ExtractError("一个查表函数都没找到 —— 先怀疑本脚本的模式，不是源文件")
    out = []
    for idx, (name, s) in enumerate(starts):
        e = starts[idx + 1][1] if idx + 1 < len(starts) else len(lines)
        out.append((name, s, e))
    return out


def extract_block(lines, start, fname, combo):
    """解析一个 combo 块的键构造，返回 5 位掩码（bit i 置位 = FIELDS[i] 参与匹配）。"""
    seen = {}
    i = start + 1
    while i < len(lines):
        line = lines[i]
        if LOOKUP_CALL.match(line):
            break
        if line.strip() == "" or line.strip().startswith("//"):
            i += 1
            continue
        if PAT_PAD.match(line):
            i += 1
            continue

        for pat, take in ((PAT_TAKE_IP, True), (PAT_ZERO_IP, False),
                          (PAT_TAKE_SC, True), (PAT_ZERO_SC, False)):
            m = pat.match(line)
            if not m:
                continue
            field = canon(m.group(2))
            if field not in FIELDS:
                raise ExtractError(
                    f"{fname}/{combo} 第 {i+1} 行给了一个不认识的字段 {m.group(2)!r}")
            # 「取」的两种形状要求左右字段同名，否则是抄错行（如 dst 抄成 src）
            if take and canon(m.group(3)) != field:
                raise ExtractError(
                    f"{fname}/{combo} 第 {i+1} 行左右字段不一致："
                    f"{m.group(2)} = key->{m.group(3)}")
            if field in seen:
                raise ExtractError(
                    f"{fname}/{combo} 字段 {field} 被赋值两次（第 {i+1} 行）")
            seen[field] = take
            break
        else:
            raise ExtractError(
                f"{fname}/{combo} 第 {i+1} 行认不出：{line.rstrip()!r}\n"
                f"  ⇒ 提取器必须认识键构造区的每一行。不许静默跳过。")
        i += 1
    else:
        raise ExtractError(f"{fname}/{combo} 没找到查表调用，块结构与预期不符")

    missing = [f for f in FIELDS if f not in seen]
    if missing:
        raise ExtractError(
            f"{fname}/{combo} 有字段既没取也没清零：{missing}\n"
            f"  ⇒ 本脚本**不设默认值**：漏赋值是真缺陷，不是通配。")

    mask = 0
    for bit, f in enumerate(FIELDS):
        if seen[f]:
            mask |= 1 << bit
    return mask


def extract_function(lines, name, start, end):
    """返回按**源码出现顺序**排列的 [(combo 名, 掩码)]。⛔ 不排序。"""
    out = []
    for i in range(start, end):
        m = BLOCK_START.match(lines[i])
        if m:
            out.append((m.group(1), extract_block(lines, i, name, m.group(1))))
    return out


def mask_str(mask):
    return "".join("1" if mask & (1 << b) else "0" for b in range(len(FIELDS)))


def bitmap_from_numbers(numbers):
    """把名册编号集合编码成一个 64-bit C 位图；范围外编号拒绝静默截断。"""
    bad = sorted(n for n in numbers if n < 0 or n >= 64)
    if bad:
        raise ExtractError(f"combo 编号超出 64-bit 位图范围：[0, 64) 之外有 {bad}")
    return sum(1 << n for n in numbers)


def parse_checked_valid_bitmap(path):
    """读取已检入生成头中的唯一 COMBO_VALID_BITMAP 定义。"""
    try:
        text = open(path, encoding="utf-8").read()
    except OSError as e:
        raise ExtractError(f"读不到生成头 {path}: {e}")
    matches = re.findall(
        r"^#define\s+COMBO_VALID_BITMAP\s+(0x[0-9A-Fa-f]+)ULL\s*$",
        text,
        flags=re.MULTILINE,
    )
    if len(matches) != 1:
        raise ExtractError(
            f"{path} 中 COMBO_VALID_BITMAP 应恰好定义一次，实为 {len(matches)} 次")
    return int(matches[0], 16)


def verify_pre_s2b_source(lines, funcs):
    """M1 后确认四个 consumer 仍共同承载快照表，而不是只重放快照假绿。"""
    source = "\n".join(lines)
    compact = re.sub(r"\s+", "", source).replace("\\", "")

    try:
        key_start = source.index("#define COMBO_WORD_MASK")
        key_end = source.index("// Helper: convert IPv4", key_start)
    except ValueError as e:
        raise ExtractError(f"post-M1 键构造区边界不存在：{e}")
    key_region = source[key_start:key_end]
    if "?" in key_region:
        raise ExtractError("post-M1 键构造区出现三元表达式；BPF 会把它编成分支")

    key_contract = [
        "(-(((__u64)combo_field_mask[(combo)]>>(field_bit))&1ULL))",
        "kw[0]=pk[0]&COMBO_WORD_MASK(combo,0);",
        "kw[1]=pk[1]&COMBO_WORD_MASK(combo,0);",
        "kw[2]=pk[2]&COMBO_WORD_MASK(combo,1);",
        "kw[3]=pk[3]&COMBO_WORD_MASK(combo,1);",
        "COMBO_WORD_MASK(combo,2)&0x000000000000FFFFULL",
        "COMBO_WORD_MASK(combo,3)&0x00000000FFFF0000ULL",
        "COMBO_WORD_MASK(combo,4)&0x000000FF00000000ULL",
        "COMBO_WORD_MASK(combo,0)&0x00000000FFFFFFFFULL",
        "COMBO_WORD_MASK(combo,1)&0xFFFFFFFF00000000ULL",
    ]
    missing = [snippet for snippet in key_contract if snippet not in compact]
    if missing:
        raise ExtractError(f"post-M1 无分支整字键构造漂移，缺少：{missing}")

    contracts = {
        "lookup_rule": ("build_rule_key", "BLACKLIST_LOOKUP", "rule->match_anomaly == 0"),
        "lookup_rule_anomaly": (
            "build_rule_key", "BLACKLIST_LOOKUP", "(pkt_anomaly & rule->match_anomaly) != 0"),
        "lookup_cidr_rule": (
            "build_cidr_rule_key", "CIDR_BLACKLIST_LOOKUP", "rule->match_anomaly == 0"),
        "lookup_cidr_rule_anomaly": (
            "build_cidr_rule_key", "CIDR_BLACKLIST_LOOKUP", "(pkt_anomaly & rule->match_anomaly) != 0"),
    }
    by_name = {name: (start, end) for name, start, end in funcs}
    for name, (builder, lookup, predicate) in contracts.items():
        if name not in by_name:
            raise ExtractError(f"post-M1 缺查表函数 {name}")
        start, end = by_name[name]
        body = "\n".join(lines[start:end])
        required_once = [
            "bitmap &= COMBO_VALID_BITMAP;",
            "bpf_iter_num_new(&iter, 0, COMBO_MAX);",
            "bpf_iter_num_next(&iter)",
            "if (b >= COMBO_MAX)",
            "if (!(bitmap & (1ULL << b)))",
            f"{builder}(matched_key, key, b);",
            f"{lookup}(rule_sel, matched_key);",
            "bpf_iter_num_destroy(&iter);",
        ]
        wrong = [snippet for snippet in required_once if body.count(snippet) != 1]
        if wrong:
            raise ExtractError(f"post-M1/{name} 迭代器共同骨架漂移：{wrong}")
        ordered = ["bitmap &= COMBO_VALID_BITMAP;", "bpf_iter_num_new(&iter, 0, COMBO_MAX);",
                   "if (!(bitmap & (1ULL << b)))", f"{builder}(matched_key, key, b);",
                   f"{lookup}(rule_sel, matched_key);"]
        positions = [body.index(snippet) for snippet in ordered]
        if positions != sorted(positions) or not re.search(
                r"if \(!\(bitmap & \(1ULL << b\)\)\)\s*continue;", body):
            raise ExtractError(f"post-M1/{name} 过滤/skip 必须先于构造 key 和查 map")
        if predicate not in body:
            raise ExtractError(f"post-M1/{name} 命中谓词漂移：缺 {predicate!r}")
        live = body[body.index("bpf_iter_num_new"):body.index("bpf_iter_num_destroy")]
        if "return " in live:
            raise ExtractError(f"post-M1/{name} 在 destroy 前直接 return，会泄漏迭代器引用")

    aligned = re.findall(
        r"struct (?:rule_key|cidr_rule_key) "
        r"(?:key|matched_key|ck|cidr_matched_key) __attribute__\(\(aligned\(8\)\)\)",
        source,
    )
    if len(aligned) != 7:
        raise ExtractError(f"post-M1 调用方 aligned(8) 声明应为 7 处，实为 {len(aligned)}")


def verify_shared_source(lines):
    source = "\n".join(lines)
    compact = re.sub(r"\s+", "", source).replace("\\", "")

    try:
        key_start = source.index("#define COMBO_WORD_MASK")
        key_end = source.index("// Helper: convert IPv4", key_start)
    except ValueError as e:
        raise ExtractError(f"post-M1 键构造区边界不存在：{e}")
    key_region = source[key_start:key_end]
    if "?" in key_region:
        raise ExtractError("post-M1 键构造区出现三元表达式；BPF 会把它编成分支")

    key_contract = [
        "(-(((__u64)combo_field_mask[(combo)]>>(field_bit))&1ULL))",
        "kw[0]=pk[0]&COMBO_WORD_MASK(combo,0);",
        "kw[1]=pk[1]&COMBO_WORD_MASK(combo,0);",
        "kw[2]=pk[2]&COMBO_WORD_MASK(combo,1);",
        "kw[3]=pk[3]&COMBO_WORD_MASK(combo,1);",
        "COMBO_WORD_MASK(combo,2)&0x000000000000FFFFULL",
        "COMBO_WORD_MASK(combo,3)&0x00000000FFFF0000ULL",
        "COMBO_WORD_MASK(combo,4)&0x000000FF00000000ULL",
        "COMBO_WORD_MASK(combo,0)&0x00000000FFFFFFFFULL",
        "COMBO_WORD_MASK(combo,1)&0xFFFFFFFF00000000ULL",
    ]
    missing = [snippet for snippet in key_contract if snippet not in compact]
    if missing:
        raise ExtractError(f"post-M1 无分支整字键构造漂移，缺少：{missing}")

    aligned = re.findall(
        r"struct (?:rule_key|cidr_rule_key) "
        r"(?:key|matched_key|ck|cidr_matched_key) __attribute__\(\(aligned\(8\)\)\)",
        source,
    )
    from s2b_c_replay import source_generation
    generation = source_generation(source.encode())
    expected_aligned = {"historical": 7, "b1cut54": 4}[generation]
    if len(aligned) != expected_aligned:
        raise ExtractError(f"post-M1 调用方 aligned(8) 声明应为 {expected_aligned} 处，实为 {len(aligned)}")


def verify_refactored_source(lines, funcs):
    verify_shared_source(lines)
    # The old numbered-loop checker is retained for frozen historical inputs.
    # Current consumers must satisfy the actual C AST control-flow contract.
    from s2b_c_replay import check_source, ReplayError
    root = os.path.abspath(os.path.join(HERE, "../../.."))
    try:
        with tempfile.TemporaryDirectory(prefix="s2b-generator-", dir="/tmp") as out:
            check_source(root, out)
    except ReplayError as error:
        raise ExtractError(str(error)) from error


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--src", default=DEFAULT_SRC)
    ap.add_argument("--hdr", default=DEFAULT_HDR)
    ap.add_argument("--mask-hdr", default=DEFAULT_MASK_HDR)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--emit-c", action="store_true")
    args = ap.parse_args()

    lines = open(args.src, encoding="utf-8").read().splitlines()
    roster, comment_masks = parse_header_roster(args.hdr)
    funcs = find_functions(lines)

    tables = {}
    for name, s, e in funcs:
        rows = extract_function(lines, name, s, e)
        if rows:
            tables[name] = rows

    # M1 前从四个展开函数机械提取的有序结果，是转换前语义的不可变证据。
    # M1 后生产源码已不再保留 1,716 行展开块；此时从该机器快照重放同一套
    # ①②③ 判据，并供 Makefile 重生成 combo_masks.h 做逐字节 diff。
    post_m1 = not tables
    if post_m1:
        if os.path.abspath(args.src) != os.path.abspath(DEFAULT_SRC):
            raise ExtractError(
                f"自定义源文件 {args.src!r} 没有 combo 展开块，拒绝借用默认基线")
        try:
            with open(DEFAULT_BASELINE, encoding="utf-8") as f:
                baseline = json.load(f)
        except (OSError, ValueError) as e:
            raise ExtractError(f"读不到 pre-M1 机器快照 {DEFAULT_BASELINE}: {e}")
        if baseline.get("fields") != FIELDS:
            raise ExtractError(
                f"pre-M1 快照字段位序漂移：{baseline.get('fields')!r} != {FIELDS!r}")
        if baseline.get("problems"):
            raise ExtractError(
                f"pre-M1 快照自身带失败项，拒绝使用：{baseline['problems']!r}")
        tables = {
            name: [(combo, int(mask)) for combo, mask in rows]
            for name, rows in baseline.get("functions", {}).items()
        }
        from s2b_c_replay import source_generation, SOURCE_NAMES
        generation = source_generation("\n".join(lines).encode())
        expected = {name for name, _, _ in funcs}
        registered = set(SOURCE_NAMES[generation][4:])
        if expected != registered:
            raise ExtractError(f"当前查表函数集 {sorted(expected)} != 世代 {generation} 登记 {sorted(registered)}")
        if generation == "b1cut54":
            historical = set(SOURCE_NAMES['historical'][4:])
            if set(tables) != historical:
                raise ExtractError("pre-M1 快照函数集不等于完整历史登记")
            tables = {name: rows for name, rows in tables.items() if name in registered}
        if set(tables) != expected:
            raise ExtractError(
                f"pre-M1 快照函数集 {sorted(tables)} != 当前查表函数集 {sorted(expected)}")
        verify_refactored_source(lines, funcs)

    problems = []

    # ── 判据 ①：四份逐位相同 ────────────────────────────────────────────
    names = sorted(tables)
    base_name = names[0]
    base = tables[base_name]
    for n in names[1:]:
        if tables[n] != base:
            problems.append(f"❌ ① {n} 与 {base_name} 不一致")
            bl, ol = dict(base), dict(tables[n])
            for combo in sorted(set(bl) | set(ol)):
                if bl.get(combo) != ol.get(combo):
                    problems.append(
                        f"     {combo}: {base_name}={mask_str(bl[combo]) if combo in bl else '缺'}"
                        f"  {n}={mask_str(ol[combo]) if combo in ol else '缺'}")

    # ── 判据 ②：源码顺序 vs 编号升序 ────────────────────────────────────
    history = HISTORICAL_ROSTER
    nums = [history[c] for c, _ in base if c in history]
    unknown = [c for c, _ in base if c not in history]
    if unknown:
        problems.append(f"❌ ② 源码里的 combo 头文件没定义：{unknown}")
    if nums != sorted(nums):
        problems.append(f"❌ ② 源码顺序不是编号升序 —— M1-c 的『b 升序』前提不成立：{nums}")

    # ── 判据 ③：有效编号位图 == xdrop.h 名册的实际编号集合 ─────────────
    present = set(nums)
    roster_numbers = set(roster.values())
    if roster != CURRENT_ROSTER:
        problems.append("❌ ③ 当前活跃名册不等于冻结名册减退役集合")
    if len(base) != len(history) or len(nums) != len(set(nums)):
        problems.append("❌ ② 历史行存在缺失或重复")
    holes = sorted(set(range(0, max(roster_numbers) + 1)) - roster_numbers)
    if present != set(history.values()):
        problems.append(
            "❌ ③ pre-M1 掩码行编号集合与独立历史名册不一致："
            f"只在掩码行={sorted(present - set(history.values()))}，"
            f"只在名册={sorted(set(history.values()) - present)}")
    expected_valid_bitmap = bitmap_from_numbers(roster_numbers)
    checked_valid_bitmap = None
    if post_m1 and not args.emit_c:
        checked_valid_bitmap = parse_checked_valid_bitmap(args.mask_hdr)
        if checked_valid_bitmap != expected_valid_bitmap:
            problems.append(
                "❌ ③ COMBO_VALID_BITMAP 与名册实际编号集合不一致："
                f"生成头=0x{checked_valid_bitmap:016X}ULL，"
                f"名册期望=0x{expected_valid_bitmap:016X}ULL，空洞={holes}")

    by_num = {history[c]: m for c, m in base if c in history}

    # ── 自检：装置的已知答案（阳性对照）──────────────────────────────
    #
    # F-072 从 **Go 侧** 取证：combo 20 与 combo 2 等价、combo 32 与 combo 1 等价
    # （所以那两位永不置位、是死代码）。本提取器走的是 **C 侧展开代码**这条
    # 完全不同的路径 —— 它必须独立地重现同一结论。
    #
    # 🔑 这条不是在断言「重复是对的」，而是给仪器一个**已知该往哪边走**的场景：
    #    装置坏掉时，这条会先红，而不是让一张悄悄错了的掩码表通过验收。
    KNOWN_DUPLICATES = [(20, 2), (32, 1)]   # (死 combo, 与它等价的那个) —— F-072
    for dead, live in KNOWN_DUPLICATES:
        if dead not in by_num or live not in by_num:
            problems.append(f"❌ 自检 combo {dead}/{live} 不在提取结果里")
        elif by_num[dead] != by_num[live]:
            problems.append(
                f"❌ 自检失败：combo {dead} 掩码 {mask_str(by_num[dead])} "
                f"≠ combo {live} 掩码 {mask_str(by_num[live])}，"
                f"与 F-072 矛盾。\n"
                f"     ⇒ **先怀疑本提取器**，再怀疑 F-072。\n"
                f"     ⇒ 此自检认证历史快照，退役投影不得绕过它。")

    # Project only after interpreting every historical row. Unknown rows have
    # already produced a failure; they are never silently filtered as retired.
    projected = [(c, m) for c, m in base if c in history and history[c] not in RETIRED]
    for combo, mask in base:
        if not isinstance(mask, int) or not 0 < mask < 32:
            problems.append(f"❌ ① 历史掩码非法：{combo}={mask!r}")

    # ── 对撞：代码 vs 头文件注释（F-086 的独立路径）────────────────────
    # M1-b 禁止照注释转录 ⇒ 注释只当**对照组**。两边不符时报出来，
    # 但**以代码为准** —— 注释错了是注释的问题。
    mismatched, uncomparable = [], []
    for combo, mask in projected:
        if combo not in comment_masks:
            uncomparable.append(combo)
        elif comment_masks[combo] != mask:
            mismatched.append(
                f"     {combo}: 代码={mask_str(mask)}  注释={mask_str(comment_masks[combo])}")
    if mismatched:
        problems.append("❌ 对撞：注释与代码不符（**以代码为准**，去修注释）：")
        problems.extend(mismatched)

    if post_m1 and hashlib.sha256(json.dumps(baseline, sort_keys=True, separators=(",", ":")).encode()).hexdigest() != "5057780ea97fc74b8e917ac81d28951734be1d5b0d8deb61ddb9e86906d7cab1":
        problems.append("❌ 历史快照身份改变（pre-M1 JSON canonical SHA256）")

    if args.json:
        print(json.dumps({
            "fields": FIELDS,
            "functions": {n: [[c, m] for c, m in rows] for n, rows in tables.items()},
            "holes": holes,
            "valid_bitmap": expected_valid_bitmap,
            "problems": problems,
        }, indent=2, ensure_ascii=False))
        return 1 if problems else 0

    if args.emit_c:
        if problems:
            sys.stderr.write("⛔ 判据未全过，拒绝生成表。先修上面的问题。\n")
            for p in problems:
                sys.stderr.write(p + "\n")
            return 1
        emit_c(projected, roster)
        return 0

    print(f"源文件 : {os.path.relpath(args.src)}")
    print(f"字段位序: {'  '.join(f'{i}:{f}' for i, f in enumerate(FIELDS))}")
    print(f"函数    : {len(tables)} 个，各 {len(base)} 段\n")
    print(f"{'#':>3}  {'combo':<34} {'掩码':<7} 参与匹配的字段")
    print("-" * 78)
    for combo, mask in projected:
        fs = ",".join(f for b, f in enumerate(FIELDS) if mask & (1 << b))
        print(f"{roster.get(combo, -1):>3}  {combo:<34} {mask_str(mask):<7} {fs}")
    print("-" * 78)
    print(f"历史行={len(base)}；退役投影={len(base)-len(projected)}；活跃行={len(projected)}；空洞={holes}")
    print()
    if problems:
        for p in problems:
            print(p)
        print("\n🔴 判据未全过")
        return 1
    print(f"✅ ① 当前世代掩码逐位相同（{len(tables)}/{len(tables)}）")
    print("✅ ② pre-M1 源码顺序 == 编号升序（M1-c 的前提成立）")
    print(f"✅ ③ COMBO_VALID_BITMAP == 名册编号集合 "
          f"(0x{expected_valid_bitmap:016X}ULL)，空洞={holes}")
    if post_m1:
        print(f"✅ post-M1 {len(funcs)} 循环通过世代合同、有效位图过滤、引用释放、{4 if generation == 'b1cut54' else 7} 处对齐与无分支键构造")
    print(f"✅ 自检 装置重现 F-072：{', '.join(f'{d}≡{l}' for d, l in KNOWN_DUPLICATES)}"
          f"（该结论原从 Go 侧取证，本器走 C 侧）")
    if uncomparable:
        print(f"⚠️  对撞 有 {len(uncomparable)} 个 combo 的头文件注释无法解析 ⇒ "
              f"**未参与对撞**，不是通过：{', '.join(uncomparable)}")
    else:
        print(f"✅ 对撞 全部 {len(projected)} 个 combo 的头文件注释与代码一致")
    return 0


def emit_c(rows, roster):
    """生成掩码表。索引 = combo 编号，空洞行显式置 0 并标注永不被试探。"""
    by_num = {roster[c]: (c, m) for c, m in rows}
    valid_bitmap = bitmap_from_numbers(set(roster.values()))
    hi = max(roster.values())
    print("// ⚠️ 本文件由 node/bpf/tools/extract_combo_masks.py 生成，⛔ 不要手改。")
    print("// 掩码从 xdrop_main.c 的展开代码机械提取（M1-b：不照注释转录）。")
    print("// pre-M1 四函数有序结果冻结于 tools/combo_masks_pre_m1.json。")
    print("// 重新生成：python3 node/bpf/tools/extract_combo_masks.py --emit-c")
    print()
    print("_Static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__,")
    print('               "combo whole-word masks require little-endian byte order");')
    print()
    print(f"#define COMBO_VALID_BITMAP 0x{valid_bitmap:016X}ULL")
    print()
    for b, f in enumerate(FIELDS):
        print(f"#define CM_{f.upper()} (1u << {b})")
    print()
    print(f"// 索引 = combo 编号。有效槽 0..{hi}（COMBO_MAX={hi + 1}）。")
    print("// 表按 COMBO_TABLE_SLOTS 定长，⛔ 不是按 COMBO_MAX：combo 号取自一次 __u8")
    print("// 载入，verifier 只能断定它 <= 255。表做满 256 槽，combo_field_mask[b] 就")
    print("// 恒在界内，⛔ 不再依赖「b <= 33 那条检查能不能在优化后活下来」。")
    print("// 多出的槽恒为 0 = 不定位任何字段，与历史空洞同义。")
    print("#define COMBO_TABLE_SLOTS 256")
    print("static const __u8 combo_field_mask[COMBO_TABLE_SLOTS] = {")
    for n in range(hi + 1):
        if n in by_num:
            c, m = by_num[n]
            fs = " | ".join(f"CM_{f.upper()}" for b, f in enumerate(FIELDS) if m & (1 << b))
            print(f"    [{n}] = {fs or '0'},  // {c}")
        else:
            print(f"    [{n}] = 0,  // 历史空洞或退役槽；构造 key 前由 COMBO_VALID_BITMAP 过滤。")
    print("};")
    order = sorted(by_num, key=lambda n: (-bin(by_num[n][1]).count("1"), n))
    if len(order) != len(roster) or set(order) != set(roster.values()):
        raise ExtractError("order identity set differs from authenticated roster")
    print()
    print("// B0: descending field population; stable ID ascending breaks ties.")
    print("static const __u8 combo_order[] = {")
    print("    " + ", ".join(map(str, order)) + ",")
    print("};")
    print("#define COMBO_ORDER_LEN (sizeof(combo_order) / sizeof(combo_order[0]))")
    print('_Static_assert(sizeof(combo_field_mask) == COMBO_TABLE_SLOTS, "mask slots must keep stable IDs");')
    print('_Static_assert(COMBO_MAX <= COMBO_TABLE_SLOTS, "every live combo id must own a slot");')
    print('_Static_assert(COMBO_TABLE_SLOTS == 256, "slots must cover the full __u8 range the verifier sees");')
    print('_Static_assert(sizeof(combo_field_mask[0]) == 1, "mask elements must remain bytes");')
    print('_Static_assert(0 < COMBO_ORDER_LEN && COMBO_ORDER_LEN <= COMBO_MAX && COMBO_MAX <= 64,')
    print('               "order/slot/shift bounds must hold");')


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ExtractError as e:
        sys.stderr.write(f"🔴 提取失败：{e}\n")
        sys.exit(2)
