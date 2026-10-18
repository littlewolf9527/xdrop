#!/usr/bin/env python3
"""Mutation tests for the post-M1 combo-mask verifier.

Every mutation runs in a temporary BPF tree containing copies of the verifier,
the frozen pre-M1 evidence, xdrop_main.c, xdrop.h, and combo_masks.h. Production
files are never edited. A mutation passes only when it is non-empty, the
verifier exits nonzero, and the expected named guard appears in its output.
"""

import copy
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
BPF = os.path.join(HERE, os.pardir)
TOOL = os.path.join(HERE, "extract_combo_masks.py")
BASELINE = os.path.join(HERE, "combo_masks_pre_m1.json")
SRC = os.path.join(BPF, "xdrop_main.c")
HDR = os.path.join(BPF, "xdrop.h")
MASK_HDR = os.path.join(BPF, "combo_masks.h")
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("extractor", TOOL)
extractor = importlib.util.module_from_spec(spec)
spec.loader.exec_module(extractor)


def run(src, hdr, mask_hdr, baseline):
    with tempfile.TemporaryDirectory(dir="/tmp") as d:
        bpf = os.path.join(d, "bpf")
        tools = os.path.join(bpf, "tools")
        os.makedirs(tools)
        shutil.copy2(TOOL, os.path.join(tools, "extract_combo_masks.py"))
        with open(os.path.join(tools, "combo_masks_pre_m1.json"), "w", encoding="utf-8") as f:
            json.dump(baseline, f, ensure_ascii=False, indent=2)
        with open(os.path.join(bpf, "xdrop_main.c"), "w", encoding="utf-8") as f:
            f.write(src)
        with open(os.path.join(bpf, "xdrop.h"), "w", encoding="utf-8") as f:
            f.write(hdr)
        with open(os.path.join(bpf, "combo_masks.h"), "w", encoding="utf-8") as f:
            f.write(mask_hdr)
        p = subprocess.run(
            [sys.executable, os.path.join(tools, "extract_combo_masks.py")],
            capture_output=True,
            text=True,
        )
        return p.returncode, p.stdout + p.stderr


def row_index(rows, combo):
    return next(i for i, row in enumerate(rows) if row[0] == combo)


def roster_numbers(hdr):
    nums = {
        int(n) for name, n in re.findall(
            r"#define\s+(COMBO_[A-Z_0-9]+)[\s\\]+(\d+)", hdr)
        if name != "COMBO_MAX"
    }
    return nums


def mut_corrupt_valid_bitmap(src, hdr, mask_hdr, baseline):
    """Set one roster hole in the checked-in bitmap; criterion 3 must fail."""
    matches = re.findall(
        r"^#define\s+COMBO_VALID_BITMAP\s+(0x[0-9A-Fa-f]+)ULL\s*$",
        mask_hdr,
        flags=re.MULTILINE,
    )
    assert len(matches) == 1
    holes = sorted(set(range(max(roster_numbers(hdr)) + 1)) - roster_numbers(hdr))
    assert holes
    old_value = int(matches[0], 16)
    new_value = old_value | (1 << holes[0])
    old = f"#define COMBO_VALID_BITMAP 0x{old_value:016X}ULL"
    new = f"#define COMBO_VALID_BITMAP 0x{new_value:016X}ULL"
    assert old in mask_hdr and old != new
    return src, hdr, mask_hdr.replace(old, new), baseline


def legacy_hole_guards_would_green(src, hdr, baseline, expected_holes):
    """重放被替换的两条旧检查，证明其在空洞真相变化后会假绿。"""
    legacy_src = src.replace(
        "bitmap &= COMBO_VALID_BITMAP;", "bitmap &= ~(1ULL << 19);")
    if legacy_src.count("bitmap &= ~(1ULL << 19);") != 4:
        return False
    roster = {
        name: int(n) for name, n in re.findall(
            r"#define\s+(COMBO_[A-Z_0-9]+)[\s\\]+(\d+)", hdr)
        if name != "COMBO_MAX"
    }
    tables = list(baseline["functions"].values())
    if any(rows != tables[0] for rows in tables[1:]):
        return False
    roster = dict(extractor.HISTORICAL_ROSTER, **roster)
    nums = [roster[name] for name, _ in tables[0]]
    holes = sorted(set(range(max(roster.values()) + 1)) - set(nums))
    return nums == sorted(nums) and holes == expected_holes


def mut_flip_field(src, hdr, mask_hdr, baseline):
    """Only one frozen function changes, so criterion 1 must fail."""
    rows = baseline["functions"]["lookup_rule"]
    rows[row_index(rows, "COMBO_PROTO_ONLY")][1] = 0
    return src, hdr, mask_hdr, baseline


def mut_swap_order(src, hdr, mask_hdr, baseline):
    """All four snapshots swap 6/7: content parity stays green, order fails."""
    for rows in baseline["functions"].values():
        a = row_index(rows, "COMBO_SRC_PORT_ONLY")
        b = row_index(rows, "COMBO_DST_PORT_ONLY")
        rows[a], rows[b] = rows[b], rows[a]
    return src, hdr, mask_hdr, baseline


def mut_fill_hole_19(src, hdr, mask_hdr, baseline):
    """名册与四份快照合法复活空洞，但故意让已检入运行时位图保持旧值。"""
    old = "// Note: combo 19 was removed (duplicate of COMBO_DST_IP_PROTO)"
    new = "#define COMBO_RESURRECTED_19 19  // * + dst_ip + * + dst_port + protocol"
    assert old in hdr
    hdr = hdr.replace(old, new)
    for rows in baseline["functions"].values():
        pos = row_index(rows, "COMBO_DST_IP_DST_PORT_PROTO")
        rows.insert(pos, ["COMBO_RESURRECTED_19", 26])
    return src, hdr, mask_hdr, baseline


def mut_break_selfcheck(src, hdr, mask_hdr, baseline):
    """All four combo-20 masks drift together; F-072 positive control fails."""
    for rows in baseline["functions"].values():
        rows[row_index(rows, "COMBO_DST_IP_DST_PORT_PROTO")][1] = 18
    return src, hdr, mask_hdr, baseline


def mut_add_key_branch(src, hdr, mask_hdr, baseline):
    """Put a ternary in the key constructor; BPF would compile it as a branch."""
    old = "(-(((__u64)combo_field_mask[(combo)] >> (field_bit)) & 1ULL))"
    new = "((combo_field_mask[(combo)] >> (field_bit)) & 1ULL ? ~0ULL : 0ULL)"
    assert old in src
    return src.replace(old, new, 1), hdr, mask_hdr, baseline


def mut_drop_destroy(src, hdr, mask_hdr, baseline):
    """Drop one iterator release; the common-shape/ref guard must fail."""
    old = "  bpf_iter_num_destroy(&iter);"
    assert src.count(old) == 4
    return src.replace(old, "", 1), hdr, mask_hdr, baseline


def mut_drop_alignment(src, hdr, mask_hdr, baseline):
    """Remove one caller alignment annotation; the seven-site guard must fail."""
    old = "struct rule_key key __attribute__((aligned(8))) = {0};"
    new = "struct rule_key key = {0};"
    assert old in src
    return src.replace(old, new, 1), hdr, mask_hdr, baseline


def mut_corrupt_comment(src, hdr, mask_hdr, baseline):
    """Make the independent xdrop.h comment disagree with frozen code evidence."""
    old = "#define COMBO_DST_IP_ONLY 4            // * + dst_ip + * + * + *"
    new = "#define COMBO_DST_IP_ONLY 4            // * + dst_ip + * + dst_port + *"
    assert old in hdr
    return src, hdr.replace(old, new), mask_hdr, baseline


def mut_unknown_row(src, hdr, mask_hdr, baseline):
    for rows in baseline["functions"].values():
        rows[-1][0] = "COMBO_UNKNOWN_ROW"
    return src, hdr, mask_hdr, baseline


def mut_duplicate_row(src, hdr, mask_hdr, baseline):
    for rows in baseline["functions"].values():
        rows.append(rows[-1][:])
    return src, hdr, mask_hdr, baseline


def mut_missing_row(src, hdr, mask_hdr, baseline):
    for rows in baseline["functions"].values():
        rows.pop()
    return src, hdr, mask_hdr, baseline


def mut_filter_late(src, hdr, mask_hdr, baseline):
    old = "  bitmap &= COMBO_VALID_BITMAP;"
    assert src.count(old) == 4
    src = src.replace(old, "", 1)
    anchor = "    build_rule_key(matched_key, key, b);"
    assert anchor in src
    return src.replace(anchor, anchor+"\n"+old, 1), hdr, mask_hdr, baseline


def mut_skip_missing(src, hdr, mask_hdr, baseline):
    old = "if (!(bitmap & (1ULL << b)))\n      continue;"
    assert old in src
    return src.replace(old, "if (!(bitmap & (1ULL << b))) ;", 1), hdr, mask_hdr, baseline


CASES = [
    ("未知历史行", mut_unknown_row, "源码里的 combo 头文件没定义"),
    ("重复历史行", mut_duplicate_row, "历史行存在缺失或重复"),
    ("缺失历史行", mut_missing_row, "历史行存在缺失或重复"),
    ("过滤晚于构造", mut_filter_late, "过滤/skip 必须先于构造"),
    ("删除空洞 continue", mut_skip_missing, "过滤/skip 必须先于构造"),
    ("① 内容：只改一份冻结掩码", mut_flip_field, "❌ ①"),
    ("② 顺序：四份同调 6/7", mut_swap_order, "❌ ②"),
    ("③a 位图：生成头错误纳入一个空洞", mut_corrupt_valid_bitmap, "❌ ③"),
    ("③b 空洞集合变化但运行时位图未跟上", mut_fill_hole_19, "❌ ③"),
    ("自检：四份同破坏 20≡2", mut_break_selfcheck, "自检失败"),
    ("键构造：加入三元分支", mut_add_key_branch, "键构造区出现三元表达式"),
    ("引用：删一次 destroy", mut_drop_destroy, "迭代器共同骨架漂移"),
    ("对齐：删一处 aligned(8)", mut_drop_alignment, "aligned(8) 声明应为 7 处"),
    ("对撞：改坏头文件注释", mut_corrupt_comment, "注释与代码不符"),
]


def main():
    with open(SRC, encoding="utf-8") as f:
        base_src = f.read()
    with open(HDR, encoding="utf-8") as f:
        base_hdr = f.read()
    with open(MASK_HDR, encoding="utf-8") as f:
        base_mask_hdr = f.read()
    with open(BASELINE, encoding="utf-8") as f:
        base_baseline = json.load(f)

    print("═══ 阴性对照：未变异的真文件必须全绿 ═══")
    rc, out = run(base_src, base_hdr, base_mask_hdr, base_baseline)
    if rc != 0:
        print(out)
        print("🔴 基线就不绿 —— 后面的变异测试全部无意义。")
        return 1
    print(out)
    print("✅ 未变异对照=1；RC=0\n")

    print("═══ 变异测试：每条都必须让指定判据变红 ═══")
    failures = 0
    for name, mutate, expect in CASES:
        src = base_src
        hdr = base_hdr
        mask_hdr = base_mask_hdr
        baseline = copy.deepcopy(base_baseline)
        try:
            src2, hdr2, mask_hdr2, baseline2 = mutate(
                src, hdr, mask_hdr, baseline)
        except (AssertionError, StopIteration) as e:
            print(f"  ❌ {name}\n       变异算子锚点失效：{e}")
            failures += 1
            continue
        if (src2 == src and hdr2 == hdr and mask_hdr2 == mask_hdr and
                baseline2 == base_baseline):
            print(f"  ❌ {name}\n       变异为空，红绿均不可归因。")
            failures += 1
            continue
        if mutate is mut_fill_hole_19:
            if not legacy_hole_guards_would_green(src2, hdr2, baseline2, []):
                print(f"  ❌ {name}\n       无法复现旧两条判据的假绿。")
                failures += 1
                continue
        rc, out = run(src2, hdr2, mask_hdr2, baseline2)
        if rc == 0:
            print(f"  ❌ {name}\n       变异后仍绿，判据没有约束力。")
            failures += 1
        elif expect not in out:
            print(f"  ❌ {name}\n       红因不符，缺少 {expect!r}。\n{out}")
            failures += 1
        else:
            print(f"  ✅ {name}; RC={rc}; red="+next(line for line in out.splitlines() if expect in line))
            if mutate is mut_fill_hole_19:
                print("       旧检查（更新期望空洞后）假绿；新 checker 拒绝偏离固定当前名册，另报位图/名册不符。")

    print()
    if failures:
        print(f"🔴 {failures}/{len(CASES)} 条变异没有红在指定判据。")
        return 1
    print(f"🟢 {len(CASES)}/{len(CASES)} 条非空变异全部红在指定判据。")
    print("   ⇒ post-M1 提取器的绿色结果具备约束力。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
