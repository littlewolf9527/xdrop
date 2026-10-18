#!/usr/bin/env bash
# M1 一键验证 —— 本地改码，远端量。
#
# 为什么是脚本而不是一串命令
# ──────────────────────────
# 目标机是一台**活着的**服务器：跑着 nginx(:80/:443)、docker、以及 xdrop 的
# 生产 agent（XDP 挂在 ens37/ens38）与 controller。把一串 ssh 命令贴给别人执行，
# 出事的方式有很多种且没人拦。做成脚本可以把避让与事后核查一起焊进去。
#
# ⛔ 三条硬避让（脚本层强制，不靠人记）
# ──────────────────────────────────────
# 1. **不 attach 任何网卡** —— attach 会顶掉活的 FF 桥
# 2. **不往 /sys/fs/bpf/ 钉任何东西** —— 活 agent 在 /sys/fs/bpf/xdrop/ 有 21 个 pin
# 3. **不写 /opt/xdrop** —— 只在 $SCRATCH 干活；rsync ⛔ 不带 --delete
#
# 每轮结束会**逐条复核**活部署没被动过（进程 / XDP link / 挂载的 prog id /
# /opt/xdrop 的 mtime / 内核里有无残留程序）。任何一条对不上就非零退出。
#
# 用法
# ────
#   export XDROP_LAB_HOST=root@<主机>          # ⛔ 真实地址不写进本仓
#   bash node/bpf/tools/m1_verify.sh            # 全套
#   bash node/bpf/tools/m1_verify.sh --quick    # 只编译 + 掩码判据，跳过 verifier
#
# 退出码：0 = 全过；1 = 有判据未过；2 = 🔴 活部署被动了（立即人工介入）

set -u
LAB="${XDROP_LAB_HOST:-}"
SCRATCH="/root/m1-verify"
QUICK=0
[ "${1:-}" = "--quick" ] && QUICK=1

if [ -z "$LAB" ]; then
  cat >&2 <<'MSG'
🔴 未设 XDROP_LAB_HOST。

  export XDROP_LAB_HOST=root@<主机>

⛔ 本仓文件里不写真实地址（禁真实 IP 的红线）。地址从环境变量传。
MSG
  exit 1
fi

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
SSH=(ssh -o BatchMode=yes -o ConnectTimeout=8 "$LAB")

# ── 基线（2026-08-29 在目标机实测，逐位复现了 F-058）────────────────────
BASE_MAIN=915505      # xdp_firewall_main       91.55%
BASE_GATE=36149       # xdp_whitelist_gate       3.61%
BASE_ANOM=719990      # anomaly 校验程序        71.99%
BASE_STACK_MAIN="296+48+80+0+0"   # 512 上限 ⇒ 余量 88 字节
LIMIT=1000000

fail=0
say() { printf '%s\n' "$*"; }
hr()  { printf '%s\n' "────────────────────────────────────────────────────────"; }

# ══ 0. 前置 ══════════════════════════════════════════════════════════════
say "═══ 0. 前置检查 ═══"
if ! "${SSH[@]}" true 2>/dev/null; then
  say "🔴 连不上 $LAB。注意：连不上 ≠ 机器不存在，先自查网络与密钥。"; exit 1
fi

read -r RHOST RKERN RARCH < <("${SSH[@]}" 'echo "$(hostname) $(uname -r) $(uname -m)"')
say "  主机 : $RHOST"
say "  内核 : $RKERN ($RARCH)"

# 开放编码迭代器需要 ≥ 6.4。低于此，M1 的选定路线根本加载不了。
kmaj=${RKERN%%.*}; krest=${RKERN#*.}; kmin=${krest%%.*}
if [ "$kmaj" -lt 6 ] || { [ "$kmaj" -eq 6 ] && [ "$kmin" -lt 4 ]; }; then
  say "🔴 内核 $RKERN < 6.4 —— 开放编码迭代器加载不了。换机器。"; exit 1
fi
say "  ✅ 内核 ≥ 6.4"

if ! "${SSH[@]}" 'printf "int f(void){return 0;}\n" > /tmp/_bt.c && clang -target bpf -O2 -c /tmp/_bt.c -o /tmp/_bt.o 2>/dev/null && rm -f /tmp/_bt.c /tmp/_bt.o'; then
  say "🔴 目标机 clang 编不了 bpf target。"; exit 1
fi
say "  ✅ clang 可编 bpf"

# ══ 1. 事前快照（事后要逐条对回来）══════════════════════════════════════
say ""
say "═══ 1. 活部署事前快照 ═══"
SNAP_BEFORE=$("${SSH[@]}" 'bash -s' <<'EOS'
echo "xdpcount=$(bpftool prog show 2>/dev/null | grep -c xdp)"
echo "agentpid=$(pgrep -f '/opt/xdrop/node/xdrop-agent' | head -1)"
echo "ctrlpid=$(pgrep -f '/opt/xdrop/controller/xdrop-controller' | head -1)"
echo "ens37prog=$(ip -d link show ens37 2>/dev/null | grep -o 'prog/xdp id [0-9]*')"
echo "ens38prog=$(ip -d link show ens38 2>/dev/null | grep -o 'prog/xdp id [0-9]*')"
echo "optmtime=$(stat -c %Y /opt/xdrop/node/xdrop-agent 2>/dev/null)"
echo "pincount=$(ls /sys/fs/bpf/xdrop/ 2>/dev/null | wc -l)"
EOS
)
say "$SNAP_BEFORE" | sed 's/^/  /'

# ══ 2. 同步（⛔ 无 --delete，⛔ 不进 /opt）═══════════════════════════════
say ""
say "═══ 2. 同步到 $SCRATCH ═══"
case "$SCRATCH" in /opt/*|/|/usr/*|/etc/*) say "🔴 SCRATCH=$SCRATCH 指向系统路径，拒绝。"; exit 2;; esac
"${SSH[@]}" "mkdir -p $SCRATCH/node" || { say "🔴 建目录失败"; exit 1; }
rsync -a --exclude '.git' --exclude '*.elf' --exclude '*.o' \
      "$REPO/node/" "$LAB:$SCRATCH/node/" || { say "🔴 rsync 失败"; exit 1; }
say "  ✅ 已同步（无 --delete）"

# ══ 3. 掩码判据 ①②③（不需要内核，但在同一份源码上跑才算数）═══════════
say ""
say "═══ 3. 掩码判据 ①②③ ═══"
if MASKOUT=$("${SSH[@]}" "cd $SCRATCH && python3 node/bpf/tools/extract_combo_masks.py 2>&1"); then
  say "$MASKOUT" | grep -E '^(✅|⚠️|🔴|❌)' | sed 's/^/  /'
else
  say "$MASKOUT" | tail -20 | sed 's/^/  /'
  say "  🔴 掩码判据未过"; fail=$((fail+1))
fi

# ══ 4. 编译 ═════════════════════════════════════════════════════════════
say ""
say "═══ 4. 编译 ═══"
if BUILD=$("${SSH[@]}" "cd $SCRATCH/node/bpf && make 2>&1"); then
  say "  ✅ 小端编译通过"
  "${SSH[@]}" "ls -l $SCRATCH/node/bpf/xdrop_main.elf $SCRATCH/node/bpf/xdrop_gate.elf | awk '{print \"  \"\$9\"  \"\$5\" bytes\"}'"
else
  say "$BUILD" | tail -25 | sed 's/^/  /'
  say "  🔴 编译失败 —— 后面的判据全部无意义"
  exit 1
fi

# 整字键掩码只定义了小端语义。bpfeb 必须红在这条显式契约上，不能等到
# 一个语义错误但可装载的 ELF 悄悄产出。
if BEOUT=$("${SSH[@]}" "cd $SCRATCH/node/bpf && bash -s" 2>&1 <<'EOS'
set +e
out=$(clang -O2 -g -Wall -target bpfeb -D__BPF__ -I./headers \
      -c xdrop_main.c -o /tmp/m1-bpfeb-proof.elf 2>&1)
rc=$?
rm -f /tmp/m1-bpfeb-proof.elf
set -e
if [ "$rc" -eq 0 ]; then
  echo "bpfeb unexpectedly compiled successfully"
  exit 1
fi
if ! grep -Fq "combo whole-word masks require little-endian byte order" <<<"$out"; then
  printf '%s\n' "$out"
  echo "bpfeb failed, but not at the little-endian contract"
  exit 1
fi
grep -F "combo whole-word masks require little-endian byte order" <<<"$out" | head -1
EOS
); then
  say "  ✅ bpfeb 按预期编译失败：$BEOUT"
else
  say "$BEOUT" | tail -20 | sed 's/^/  /'
  say "  🔴 bpfeb 端序断言证明失败"
  exit 1
fi

# ══ 5. ABI 跨语言安全网 ═════════════════════════════════════════════════
say ""
say "═══ 5. ABI 跨语言安全网（C 结构 vs Go 结构）═══"
if ABIOUT=$("${SSH[@]}" "cd $SCRATCH/node/agent && go test ./abi/ 2>&1"); then
  say "  ✅ $(echo "$ABIOUT" | tail -1)"
else
  say "$ABIOUT" | tail -20 | sed 's/^/  /'
  say "  🔴 ABI 契约破了 —— 改了 C 侧没改 Go 侧"; fail=$((fail+1))
fi

# ══ 6. verifier 预算 ════════════════════════════════════════════════════
if [ "$QUICK" -eq 1 ]; then
  say ""; say "═══ 6. verifier —— 已按 --quick 跳过 ═══"
else
  say ""
  say "═══ 6. verifier 预算（只 load，⛔ 不 attach ⛔ 不 pin）═══"
  probe_ok=1
  if ! PROBE=$("${SSH[@]}" "cd $SCRATCH/node/agent && go build -o /tmp/m0probe ./cmd/m0probe/ && /tmp/m0probe m1 $SCRATCH/node/bpf/xdrop_main.elf $SCRATCH/node/bpf/xdrop_gate.elf 2>&1"); then
    probe_ok=0
  fi
  echo "$PROBE" | grep -E '入口|VerifiedInstructions|stack depth|🔴' | sed 's/^/  /'
  if [ "$probe_ok" -eq 0 ]; then
    say ""
    say "  🔴 verifier 探针返回非零；原始错误尾部："
    echo "$PROBE" | tail -80 | sed 's/^/    /'
    fail=$((fail+1))
  fi

  # 从 "✅ VerifiedInstructions = 915505   (...)" 里取数字。
  # ⚠️ 这里踩过一次：原先取 $3，那是**等号**不是数字。而守卫写的是「非空则通过」，
  #    "=" 非空 ⇒ 放行 ⇒ 算术报错 ⇒ 脚本照样打绿灯。
  #    ⇒ 判据必须是「**是不是十进制数字**」，不是「是不是非空」。
  extract_insns() {   # $1 = 入口名
    echo "$PROBE" | awk -v e="入口 $1" '
      index($0, e) {f=1; next}
      f && /──── 入口 / {exit}
      f && /VerifiedInstructions/ {
        for (i = 1; i <= NF; i++) if ($i ~ /^[0-9]+$/) { print $i; exit }
      }'
  }
  cur_main=$(extract_insns xdp_firewall_main)
  cur_gate=$(extract_insns xdp_whitelist_gate)

  say ""
  hr
  printf '  %-24s %10s %10s %9s %10s\n' "程序" "基线" "本轮" "占用" "相对基线"
  hr
  for row in "xdp_firewall_main:$BASE_MAIN:${cur_main:-}" "xdp_whitelist_gate:$BASE_GATE:${cur_gate:-}"; do
    IFS=: read -r nm base cur <<<"$row"
    # 🔑 「是不是数字」，⛔ 不是「是不是非空」
    if ! [[ "$cur" =~ ^[0-9]+$ ]]; then
      printf '  %-24s %10s %10s %9s %10s\n' "$nm" "$base" "读不到" "—" "—"
      say "     🔴 取到的不是数字（拿到 ${cur:-<空>}）—— **先疑装置**（m0probe 输出格式变了？"
      say "        正则错位？），⛔ 绝不当成\"没变化\"。"
      fail=$((fail+1)); continue
    fi
    pct=$(( cur * 10000 / LIMIT ))
    d=$(( cur - base ))
    sign=$([ "$d" -gt 0 ] && echo "+" || echo "")
    printf '  %-24s %10s %10s %8s%% %10s\n' \
      "$nm" "$base" "$cur" "$((pct/100)).$((pct%100))" "${sign}${d}"
  done
  hr
  say "  基线主程序栈: $BASE_STACK_MAIN （512 上限 ⇒ 余量 88 字节）"
fi

# ══ 7. 事后核查：活部署有没有被动 ════════════════════════════════════════
say ""
say "═══ 7. 活部署事后核查 ═══"
SNAP_AFTER=$("${SSH[@]}" 'bash -s' <<'EOS'
echo "xdpcount=$(bpftool prog show 2>/dev/null | grep -c xdp)"
echo "agentpid=$(pgrep -f '/opt/xdrop/node/xdrop-agent' | head -1)"
echo "ctrlpid=$(pgrep -f '/opt/xdrop/controller/xdrop-controller' | head -1)"
echo "ens37prog=$(ip -d link show ens37 2>/dev/null | grep -o 'prog/xdp id [0-9]*')"
echo "ens38prog=$(ip -d link show ens38 2>/dev/null | grep -o 'prog/xdp id [0-9]*')"
echo "optmtime=$(stat -c %Y /opt/xdrop/node/xdrop-agent 2>/dev/null)"
echo "pincount=$(ls /sys/fs/bpf/xdrop/ 2>/dev/null | wc -l)"
EOS
)
if [ "$SNAP_BEFORE" = "$SNAP_AFTER" ]; then
  say "  ✅ 七项快照逐字节相同 —— 进程 / XDP link / 挂载 prog id / /opt mtime / pin 数 / 内核残留"
else
  say "  🔴🔴 活部署状态变了！"
  diff <(echo "$SNAP_BEFORE") <(echo "$SNAP_AFTER") | sed 's/^/     /'
  say "  ⇒ 立刻人工介入。⛔ 不要继续跑本脚本。"
  exit 2
fi

# ══ 收尾 ════════════════════════════════════════════════════════════════
say ""
if [ "$fail" -gt 0 ]; then
  say "🔴 $fail 项判据未过。"
  exit 1
fi
say "🟢 全部判据通过，且活部署未被触碰。"
