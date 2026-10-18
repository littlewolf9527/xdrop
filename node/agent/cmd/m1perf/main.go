// m1perf —— M1 的运行时性能对比工具（第二版，消除顺序偏差）。
//
// ── 它回答什么 ──────────────────────────────────────────────────────────────
//
// 「把 33 段手工展开的匹配代码换成循环之后，每个包变慢了吗？两种循环写法哪个快？」
//
// 这是 M1 唯一剩下的未答项，也是选路判据（plans/phase1 §M1-e）。
// 预算那本账已经结了（facts.md F-067 / F-069，两条路都绰绰有余）⇒ **只剩速度这本。**
//
// ── 🔴 闸门场景 = 全部组合启用（最坏情况）──────────────────────────────────
//
// 项目所有者 2026-08-13 指出：**规则派发器下发的字段组合不可预测**，本系统当初的
// 设计目标之一就是兼容别的软件 ⇒ **禁止对「实际用到哪几种组合」做任何假设**。
// 所以闸门用最坏情况：位图全开、报文**不命中任何规则** ⇒ 33 种组合全部试完。
// 这也正是同口径对比 —— 基线本来就为每种组合各付一段展开代码。
//
// ── 🔴 第一版为什么作废（本版针对它而改）──────────────────────────────────
//
// 第一版一个变体跑完再跑下一个，每个场景各自新建一整套内核表（几百 MB）。
// 结果基线内部出现物理上不可能的读数：**关掉 CIDR 反而更慢**
// ⇒ 证明读数被「场景顺序 / 内存压力」污染。那一轮全部作废。
//
// 本版三条改动：
//  1. **三份程序在同一进程里一次性全部加载好**，之后不再新建/销毁
//  2. **同一场景下按 基线→迭代器→bpf_loop 交替跑多轮**，任何漂移对三者同等
//  3. **报告每轮离散度（最小/中位/最大）**，不再只报最小值 —— 藏起离散度等于藏起噪声
//
// ── 装置自检 ────────────────────────────────────────────────────────────────
//
// 保留「CIDR 关」这个场景当**装置自检**：它比「CIDR 开」少做一部分工作
// ⇒ **必须更快**。若它更慢，说明装置又有偏，本轮读数一律作废，不许解释成发现。
// （教训来源：靠它抓出了第一版的偏差；同类招数还救过一次静默空转。）
//
// ── 仪器的两条已知偏差（读数时必须带上）────────────────────────────────────
//
//  1. BPF_PROG_TEST_RUN 只测程序本身，**不含网卡驱动那一段** ⇒ 适合比相对快慢，
//     不能当绝对 pps
//  2. 它反复跑同一个包，**缓存全是热的** ⇒「代码小了 64%」那个好处会被低估
//
// 用法：m1perf <标签1>=<elf1> <标签2>=<elf2> ...
package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

// config_a 的下标，与 node/bpf/xdrop.h 的 CONFIG_* 一一对应。
const (
	cfgBlacklistCount = 0
	cfgRuleBitmap     = 2
	cfgFastForward    = 4
	cfgFilterIfindex  = 5
	cfgCIDRRuleCount  = 6
	cfgCIDRBitmap     = 7
	cfgRuleMapSel     = 9
	cfgAnomalyCount   = 10
	cfgRLCPUDivisor   = 11
)

// 33 个有效 combo（编号 0–33，19 是历史空洞）。
const allCombos = (uint64(1)<<34 - 1) & ^(uint64(1) << 19)

const (
	xdpDrop = 1
	xdpPass = 2
)

const (
	repeat = 200000 // 每轮迭代次数
	cycles = 7      // 交替轮数
)

var (
	pktSrcIP = [4]byte{192, 0, 2, 1} // RFC 5737 文档段；本仓红线：不得出现真实 IP
	pktDstIP = [4]byte{198, 51, 100, 1}
	pktSPort = uint16(12345)
	pktDPort = uint16(80)
)

func buildPacket() []byte {
	p := make([]byte, 54)
	copy(p[0:6], []byte{0x02, 0, 0, 0, 0, 1})
	copy(p[6:12], []byte{0x02, 0, 0, 0, 0, 2})
	binary.BigEndian.PutUint16(p[12:14], 0x0800)
	p[14] = 0x45 // version 4, ihl 5
	binary.BigEndian.PutUint16(p[16:18], 40)
	binary.BigEndian.PutUint16(p[20:22], 0) // frag_off = 0 ⇒ 非分片，避开 anomaly 判定
	p[22] = 64
	p[23] = 6 // TCP
	copy(p[26:30], pktSrcIP[:])
	copy(p[30:34], pktDstIP[:])
	binary.BigEndian.PutUint16(p[34:36], pktSPort)
	binary.BigEndian.PutUint16(p[36:38], pktDPort)
	p[46] = 5 << 4
	p[47] = 0x02 // SYN
	binary.BigEndian.PutUint16(p[48:50], 65535)
	return p
}

// rule_key：40 字节 packed。IPv4 以 IPv4-mapped IPv6 存放。
// ⚠️ 端口原样取自报文 ⇒ **大端**（数据面 `key.src_port = tcp->source` 不做转换）。
func ruleKey(srcIP, dstIP *[4]byte, sport, dport uint16, proto uint8) []byte {
	k := make([]byte, 40)
	if srcIP != nil {
		k[10], k[11] = 0xff, 0xff
		copy(k[12:16], srcIP[:])
	}
	if dstIP != nil {
		k[26], k[27] = 0xff, 0xff
		copy(k[28:32], dstIP[:])
	}
	binary.BigEndian.PutUint16(k[32:34], sport)
	binary.BigEndian.PutUint16(k[34:36], dport)
	k[36] = proto
	return k
}

// lpmKey：cidr_v4_lpm_key = { __u32 prefixlen; __u8 addr[4] } packed，8 字节。
// prefixlen 是**主机序**（内核 LPM_TRIE 的硬要求），地址是网络序。
func lpmKey(prefixlen uint32, ip *[4]byte) []byte {
	k := make([]byte, 8)
	binary.LittleEndian.PutUint32(k[0:4], prefixlen)
	copy(k[4:8], ip[:])
	return k
}

func ruleValue(action uint8) []byte {
	v := make([]byte, 32)
	v[0] = action
	return v
}

type variant struct {
	label string
	coll  *ebpf.Collection
	prog  *ebpf.Program
}

type scenario struct {
	name    string
	bitmap  uint64
	cidrCnt uint64
	hitRule bool
	wantRet uint32
	kind    string // "gate" | "ref" | "selfcheck"
}

type stat struct{ min, med, max float64 }

func summarize(xs []float64) stat {
	sort.Float64s(xs)
	return stat{xs[0], xs[len(xs)/2], xs[len(xs)-1]}
}

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "用法: m1perf <标签>=<elf> <标签>=<elf> ...（至少两个，第一个当基线）")
		os.Exit(2)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintf(os.Stderr, "⚠️  RemoveMemlock: %v\n", err)
	}

	pkt := buildPacket()

	// ── 三份程序一次性全部加载好，之后全程不再新建/销毁 ───────────────────
	var vs []*variant
	for _, arg := range os.Args[1:] {
		parts := strings.SplitN(arg, "=", 2)
		if len(parts) != 2 {
			fmt.Fprintf(os.Stderr, "参数格式应为 标签=路径，收到 %q\n", arg)
			os.Exit(2)
		}
		spec, err := ebpf.LoadCollectionSpec(parts[1])
		if err != nil {
			fmt.Fprintf(os.Stderr, "🔴 解析 %s: %v\n", parts[1], err)
			os.Exit(1)
		}
		coll, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "🔴 加载 %s: %v\n", parts[1], err)
			os.Exit(1)
		}
		defer coll.Close()
		prog := coll.Programs["xdp_firewall_main"]
		if prog == nil {
			fmt.Fprintf(os.Stderr, "🔴 %s 里没有 xdp_firewall_main\n", parts[1])
			os.Exit(1)
		}
		vs = append(vs, &variant{label: parts[0], coll: coll, prog: prog})
	}

	scenarios := []scenario{
		{"🔴闸门·全组合+全miss", allCombos, 1, false, xdpPass, "gate"},
		{"自检·全组合+CIDR关", allCombos, 0, false, xdpPass, "selfcheck"},
		{"对照·全组合+首个命中", allCombos, 1, true, xdpDrop, "ref"},
		{"对照·单组合+miss", 1, 0, false, xdpPass, "ref"},
	}

	fmt.Printf("════ m1perf v2 · 三份同时加载 · 交替 %d 轮 · 每轮 %d 次迭代 ════\n", cycles, repeat)
	fmt.Printf("报文 %d 字节 以太网+IPv4+TCP(SYN)，地址用 RFC5737 文档段\n", len(pkt))
	fmt.Printf("⚠️ 仪器不含网卡驱动那一段 ⇒ 只比相对快慢，不是绝对 pps；缓存全热 ⇒ 低估「代码变小」的好处\n\n")

	results := map[string]map[string]stat{} // 场景 → 变体 → 统计
	bad := false

	for _, sc := range scenarios {
		// 每个变体都按同一场景配置
		for _, v := range vs {
			if err := configure(v, sc, pkt); err != nil {
				fmt.Printf("🔴 %s / %s 配置失败: %v\n", sc.name, v.label, err)
				bad = true
			}
		}
		// 预热并核对返回码 —— 路径没走到预期分支的话，这个数字测的不是我们以为的东西
		for _, v := range vs {
			ret, err := v.prog.Run(&ebpf.RunOptions{Data: pkt, Repeat: 1})
			if err != nil {
				fmt.Printf("🔴 %s / %s 预热失败: %v\n", sc.name, v.label, err)
				bad = true
				continue
			}
			if ret != sc.wantRet {
				fmt.Printf("🔴 %s / %s 返回码 %d，应为 %d —— 场景未构造成功，该行作废\n",
					sc.name, v.label, ret, sc.wantRet)
				bad = true
			}
		}

		// 🔴 交替跑：同一轮里依次跑三个变体，任何漂移对三者同等
		samples := map[string][]float64{}
		for c := 0; c < cycles; c++ {
			for _, v := range vs {
				_, d, err := v.prog.Benchmark(pkt, repeat, nil)
				if err != nil {
					fmt.Printf("🔴 %s / %s benchmark: %v\n", sc.name, v.label, err)
					bad = true
					continue
				}
				samples[v.label] = append(samples[v.label], float64(d.Nanoseconds()))
			}
		}
		results[sc.name] = map[string]stat{}
		for _, v := range vs {
			if len(samples[v.label]) > 0 {
				results[sc.name][v.label] = summarize(samples[v.label])
			}
		}
	}

	// ── 输出 ───────────────────────────────────────────────────────────────
	base := vs[0].label
	for _, sc := range scenarios {
		fmt.Printf("── %s ──\n", sc.name)
		fmt.Printf("  %-22s %10s %10s %10s   %s\n", "变体", "min", "中位", "max", "相对基线")
		for _, v := range vs {
			st, ok := results[sc.name][v.label]
			if !ok {
				fmt.Printf("  %-22s %s\n", v.label, "（无数据）")
				continue
			}
			rel := ""
			// 用 min 算倍数：min 是「本征成本」最干净的估计量，中位/最大仍然打印出来。
			if bs, ok2 := results[sc.name][base]; ok2 && v.label != base && bs.min > 0 {
				rel = fmt.Sprintf("%.2f×", st.min/bs.min)
			}
			spread := (st.max - st.min) / st.med * 100
			flag := ""
			if spread > 15 {
				flag = fmt.Sprintf("  ⚠️离散 %.0f%%", spread)
			}
			fmt.Printf("  %-22s %10.0f %10.0f %10.0f   %-8s%s\n", v.label, st.min, st.med, st.max, rel, flag)
		}
		fmt.Println()
	}

	// ── 装置自检：CIDR 关必须比 CIDR 开更快，否则本轮全部作废 ─────────────
	fmt.Println("──── 装置自检 ────")
	on, onOK := results["🔴闸门·全组合+全miss"]
	off, offOK := results["自检·全组合+CIDR关"]
	if onOK && offOK {
		for _, v := range vs {
			a, ok1 := on[v.label]
			b, ok2 := off[v.label]
			if !ok1 || !ok2 {
				continue
			}
			if b.min < a.min*0.97 { // 要求明显更快，不接受「差不多」
				fmt.Printf("  ✅ %-22s CIDR关(%.0f) 明显 < CIDR开(%.0f)，符合物理\n", v.label, b.min, a.min)
			} else {
				fmt.Printf("  🔴 %-22s CIDR关(%.0f) 未明显快于 CIDR开(%.0f)\n"+
					"       ⇒ 要么装置有偏，要么 CIDR 那半边根本没被跑到。两种都不许当发现。\n",
					v.label, b.min, a.min)
				bad = true
			}
		}
	}
	fmt.Println()
	if bad {
		fmt.Println("🔴🔴 本轮存在自检失败或场景构造失败 ⇒ **读数不得用于判读**")
		os.Exit(1)
	}
	fmt.Printf("✅ 自检通过（含 %d 台变体 × %d 场景），读数可用于判读\n", len(vs), len(scenarios))
	_ = runtime.NumCPU
}

func configure(v *variant, sc scenario, pkt []byte) error {
	cfg := v.coll.Maps["config_a"]
	act := v.coll.Maps["active_config"]
	bl := v.coll.Maps["blacklist"]
	if cfg == nil || act == nil || bl == nil {
		return fmt.Errorf("缺 config_a / active_config / blacklist")
	}
	for idx, val := range map[uint32]uint64{
		cfgBlacklistCount: 1,
		cfgRuleBitmap:     sc.bitmap,
		cfgFastForward:    0,
		cfgFilterIfindex:  0,
		cfgCIDRRuleCount:  sc.cidrCnt,
		cfgCIDRBitmap:     sc.bitmap,
		cfgRuleMapSel:     0,
		cfgAnomalyCount:   0, // 0 ⇒ 不跳转到异常判定程序（跳转表是空的）
		cfgRLCPUDivisor:   uint64(runtime.NumCPU()),
	} {
		if err := cfg.Put(idx, val); err != nil {
			return fmt.Errorf("写 config[%d]: %w", idx, err)
		}
	}
	if err := act.Put(uint32(0), uint64(0)); err != nil {
		return fmt.Errorf("写 active_config: %w", err)
	}

	// ── 🔴 必须填两棵 IPv4 LPM 树，否则 CIDR 那 33 个组合根本不会被跑到 ──────
	//
	// 数据面的门是 `if (src_cidr_id != 0 || dst_cidr_id != 0)` —— 只有 LPM 树
	// 解析出 ID 才会调用 lookup_cidr_rule。树是空的 ⇒ ID 恒为 0 ⇒ 那半边整段跳过。
	//
	// 本工具第二版就是这么错的：号称测「最坏情况」，实际只测了精确匹配那一半，
	// 而且 CIDR 开/关毫无差别（差值是纯噪声）。**装置自检正是靠这一点把它抓出来的。**
	sv4, dv4 := v.coll.Maps["sv4_cidr_trie"], v.coll.Maps["dv4_cidr_trie"]
	if sv4 == nil || dv4 == nil {
		return fmt.Errorf("缺 sv4_cidr_trie / dv4_cidr_trie")
	}
	if err := sv4.Put(lpmKey(32, &pktSrcIP), uint32(1)); err != nil {
		return fmt.Errorf("填 sv4 树: %w", err)
	}
	if err := dv4.Put(lpmKey(32, &pktDstIP), uint32(2)); err != nil {
		return fmt.Errorf("填 dv4 树: %w", err)
	}

	// 一条**不命中本报文**的规则：让 blacklist 非空、但 33 次查表全部落空。
	miss := ruleKey(&[4]byte{203, 0, 113, 9}, &[4]byte{203, 0, 113, 10}, 1, 2, 17)
	if err := bl.Put(miss, ruleValue(1)); err != nil {
		return fmt.Errorf("插入不命中规则: %w", err)
	}

	hit := ruleKey(&pktSrcIP, &pktDstIP, pktSPort, pktDPort, 6)
	if sc.hitRule {
		if err := bl.Put(hit, ruleValue(1)); err != nil { // action = DROP
			return fmt.Errorf("插入命中规则: %w", err)
		}
	} else {
		// 🔴 必须删掉，否则上一个场景插进去的命中规则会污染本场景
		if err := bl.Delete(hit); err != nil && !isNotExist(err) {
			return fmt.Errorf("删除命中规则: %w", err)
		}
	}
	return nil
}

func isNotExist(err error) bool {
	return strings.Contains(err.Error(), "not exist") || strings.Contains(err.Error(), "ENOENT")
}
