//go:build linux && integration

// main_pkt_attrs_source_test.go — S4 字段来源的真机动态判据。
//
// 🔴 射程：只覆盖 xdp_firewall_main 里 **lookup_rule 那一个** `struct pkt_attrs attrs = {`
// 构造点。S4 一共四个构造点（main/lookup_rule · main/lookup_cidr_rule ·
// anomaly/lookup_rule_anomaly · anomaly/lookup_cidr_rule_anomaly），其余三个本文件
// **不覆盖**，它们仍只有文本门 + Go source-lock。⛔ 本文件绿 ≠ S4 字段来源闭合。
//
// S4 把四个 lookup_* 的第 3 参改成 `const struct pkt_attrs *attrs`。守它的文本门只数
// 字符串存在性；主机回放桩自造 attrs 直接调 lookup_*，从不执行 xdp_firewall_main ⇒
// 正确片段留在注释 / 死代码里门照样绿。本测试把报文经 BPF_PROG_TEST_RUN 打进**真的**
// xdp_firewall_main，让规则只在 pkt_len / tcp_flags 上区分，断言判决翻转。
// ⛔ 不 attach、不 pin、不写 /opt/xdrop。
//
// 装配（每个场景重 Put 一遍，⛔ 不依赖上一场景留下的值；扫描场景每一点只重 Put 规则值）：
//
//	active_config[0]                        = S      S=0 选 config_a、S=1 选 config_b（下称「在用」）
//	在用[CONFIG_BLACKLIST_COUNT=0]          = 1      否则 lookup_rule 直接快返回
//	在用[CONFIG_RULE_BITMAP=2]              = 1<<7   combo 7 = COMBO_DST_PORT_ONLY
//	在用[CONFIG_RULE_MAP_SELECTOR=9]        = R      R=0 用 blacklist、R=1 用 blacklist_b
//	在用[CONFIG_ANOMALY_RULE_COUNT=10]      = 0      否则 miss 时 tail_call
//	blacklist / blacklist_b（按 R）[rule_key{dst_port=80}] = rule_value{…}
//
// 🔑 整张表在 **四种装配** 下各跑一遍：S×R = {0,1}×{0,1}。这两个选择器是 A/B 双缓冲，现网每推一次
// 配置 / 规则就翻一次 ⇒ 程序大约一半时间活在另一半状态里（外审 r4：`.pkt_len = rule_sel ? 0 : pkt_len`
// 在只测 R=0 时 394,651 包全绿）。变异 Q（`rule_sel ? …`）只在 R=1、R（`config_slot ? …`）只在 S=1 的装配红
// ⇒ 两个选择器变量在程序里确实取到了 1。每种装配前把不在用的一侧清掉（另一张 config 的上述四槽写 0、
// 另一张规则表删掉这条 key），只为让每种装配从干净状态开始。
// ⛔ 这**不**证明程序按选择器取表：「两边都查」或「哪边非空用哪边」的写法在这四种装配下同样全绿（外审 r5）。
// 双缓冲取表是否正确是另一个机制，不在本测试射程。
// 其余 config 槽保持 0：FAST_FORWARD 关 ⇒ miss 返回 XDP_PASS；CIDR 计数 0 ⇒
// lookup_cidr_rule 快返回；FILTER_IFINDEX 0 ⇒ 不按接口过滤。
//
// 对照与反例（每一类对应一种「接错却全绿」的写法）：
//   - reach / wrong_combo：装配到位、combo 不隐形（`bitmap &= COMBO_VALID_BITMAP` 那个坑）
//   - 帧长 ≠ 声明长度的包：排除 `data_end - data (- 14)` 这类「差不多」的来源 ——
//     若所有包都满足 帧长 = 14 + 声明长度，帧长来源就永远与真来源同判
//   - 🔑 全域扫描：pkt_len 每个值一条精确规则 min=max=x（v4 扫 0..65535，v6 扫 40..65535），
//     tcp_flags 每个值一条 mask=0xFF value=x（v4、v6 各 0..255）；x ⇒ DROP，邻值 ⇒ PASS。
//     ⇒ 构造点对本字段做的**任何**变换，只要在任何一个值上算错，就必有一点翻红。
//     挑边界的做法前三轮外审各被一种避开边界的变换打穿（`帧长−14`、`& 0xFFFE`、
//     `| (pkt_len >> 8)`）；16 位一共 65536 个值，全跑一遍只要几秒，⛔ 不再挑边界。
//   - 另一个字段取全 0 / 全 1 两档（扫长度时 flags = 0x00 / 0xFF；扫 flags 时长度 = v4 0 / 65535，
//     v6 40 / 65535）：「把另一个字段的位混进来」的写法（如 `pkt_len | (tcp_flags & 1)`）
//     在全 0 那档与正确来源同判。
//
// 🔴 仍只是抽查的维度（对它们的依赖只有抽查证据）：帧长（扫描固定 v4 54 / v6 74 字节，
// 另有几组错配包）· 其余头字段（端口、地址、TTL…）· 另一个字段除全 0 / 全 1 以外的取值。
// 🔴 程序状态只覆盖到这里：测试写入的只有 active_config、两张 config 的 0/2/9/10 四个槽（其中 RULE_BITMAP
// 取 bit7 / bit8 两个值，bit8 仅 wrong_combo 用）、选中规则表里 dst_port=80 这一条规则的 value（随场景变）。
// 其余一律只有一组值：两张 config 的其它槽恒为 0（含 FAST_FORWARD、FILTER_IFINDEX、WL_BITMAP、WL_MAP_SELECTOR、
// CIDR 计数与 bitmap、RL_CPU_DIVISOR），其它 map 测试不写（cidr_blacklist / cidr_blist_b、whitelist、devmap、
// prog_tail_map、剪枝用的 map… 为空或全 0；.rodata 由 ELF 初始化；stats / rl_states 等由程序自己写）。构造点若依赖这些状态的其它取值或组合，本测试抓不到。
// v6 不扫 payload_len ≥ 65496：那里 `payload_len + 40` 在 16 位里回绕成 0..39，是程序
// 现有语义、⛔ 不是本测试的射程。
//
// 运行（lab）：
//
//	cd node/agent && go test -tags=integration -count=1 -v -run PktAttrsSourceMain ./bpf/
//	XDROP_BPF_ELF=<变异 ELF> 同上 ⇒ 必须红（变异记录见 internal_docs/audits/2026-09-22-field-source/）
//
// ⛔ ELF 读不到 / 加载失败一律 Fatal，⛔ 不 Skip：顶层 SKIP 会以 0 包执行拿到 PASS（外审指出）。
package bpf

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/cilium/ebpf"
)

// xdrop.h 的 CONFIG_* 槽位与 combo 编号（combo_masks.h）。改那边先改这里。
const (
	cfgBlacklistCount   = uint32(0)
	cfgRuleBitmap       = uint32(2)
	cfgRuleMapSelector  = uint32(9)
	cfgAnomalyRuleCount = uint32(10)
	comboDstPortOnly    = 7 // combo_field_mask[7] = CM_DST_PORT
	comboSrcIPOnly      = 8 // 阴性对照用：bitmap 指到这里，dst_port 规则就隐形

	srcTestDstPort = uint16(80)
	srcXDPDrop     = uint32(1)
	srcXDPPass     = uint32(2)
	tcpSYN         = uint8(0x02)
	tcpACK         = uint8(0x10)

	// 每个场景最多逐条打印几个红包；其余只计数（扫描场景一个变异可红六万多包）。
	srcMaxShownRed = 5

	// 门必须断言执行量：场景表改了这里也要改，⛔ 别让它自动跟着表走。
	//   每种装配：显式场景 9 个 / 19 包；扫描 4 个，每点 3 包：
	//   v4 长度 65536 点 · v6 长度 65496 点（40..65535）· v4/v6 flags 各 256 点
	//   19 + 3 × (65536 + 65496 + 256 + 256) = 394,651；四种装配 ⇒ 52 个子测试 / 1,578,604 包
	wantScenarios  = 13
	wantAssemblies = 4
	wantPackets    = 1578604
)

// ruleValueWire 逐字节镜像 xdrop.h `struct rule_value`（packed，32 字节）。
// 偏移由 xdrop.h 的 _Static_assert 钉死：match_anomaly@3 rate_limit@4 pkt_len_min@24 pkt_len_max@26。
type ruleValueWire struct {
	Action          uint8    // 0
	TcpFlagsMask    uint8    // 1
	TcpFlagsValue   uint8    // 2
	MatchAnomaly    uint8    // 3
	RateLimit       uint32   // 4
	LogicalID       uint32   // 8
	LogicalReserved [12]byte // 12
	PktLenMin       uint16   // 24  与 BPF 侧 pkt_len（主机序）直接比较；0 = 不限
	PktLenMax       uint16   // 26  0 = 不限
	Pad2            [4]uint8
}

// dstPortOnlyKey 构造 combo 7 命中的 rule_key：40 字节全零，只有 dst_port（偏移 34，
// 存的是报文里的原始网络序）非零。build_rule_key 用 combo_field_mask[7] 把报文 key
// 别的字段全清零后再查表，所以这里别的字段必须也是零。
func dstPortOnlyKey(port uint16) [40]byte {
	var k [40]byte
	binary.BigEndian.PutUint16(k[34:36], port)
	return k
}

type pktSpec struct {
	v6       bool
	l3Len    int   // 头里**声明**的 L3 长度：IPv4 tot_len；IPv6 payload_len + 40。BPF 侧 pkt_len 就该等于它
	tcpFlags uint8 // TCP flags 字节
	tail     int   // 帧尾多（>0）/ 少（<0）几个字节 ⇒ 帧长 = 14 + l3Len + tail ≠ 14 + 声明长度
}

func (s pktSpec) String() string {
	fam := "v4"
	if s.v6 {
		fam = "v6"
	}
	return fmt.Sprintf("%s l3=%d flags=0x%02x tail=%+d", fam, s.l3Len, s.tcpFlags, s.tail)
}

// buildTCP 生成 以太网 + IPv4/IPv6 + TCP + 零填充 的帧，dport 固定 80。
// tail 让帧长偏离声明长度（多则追加零字节，少则截掉尾部填充；⛔ 不许截进头）。
func buildTCP(s pktSpec) []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0x00, 0x0c, 0x29, 0x30, 0xa5, 0x0e})
	buf.Write([]byte{0x00, 0x0c, 0x29, 0x7a, 0x19, 0x0a})
	if s.v6 {
		buf.Write([]byte{0x86, 0xdd})
		buf.Write([]byte{0x60, 0x00, 0x00, 0x00})
		binary.Write(&buf, binary.BigEndian, uint16(s.l3Len-40)) // payload_len
		buf.Write([]byte{6, 64})                                 // nexthdr=TCP, hop=64
		buf.Write([]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11})
		buf.Write([]byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x13})
	} else {
		buf.Write([]byte{0x08, 0x00})
		buf.Write([]byte{0x45, 0x00})
		binary.Write(&buf, binary.BigEndian, uint16(s.l3Len)) // tot_len（声明）
		binary.Write(&buf, binary.BigEndian, uint16(1))       // id
		binary.Write(&buf, binary.BigEndian, uint16(0))       // flags/frag
		buf.Write([]byte{64, 6})                              // ttl, proto=TCP
		binary.Write(&buf, binary.BigEndian, uint16(0))       // csum
		buf.Write([]byte{10, 99, 0, 11})
		buf.Write([]byte{10, 99, 0, 13})
	}
	binary.Write(&buf, binary.BigEndian, uint16(1234))
	binary.Write(&buf, binary.BigEndian, srcTestDstPort)
	binary.Write(&buf, binary.BigEndian, uint32(0))
	binary.Write(&buf, binary.BigEndian, uint32(0))
	buf.Write([]byte{0x50, s.tcpFlags}) // doff=5
	binary.Write(&buf, binary.BigEndian, uint16(0xffff))
	binary.Write(&buf, binary.BigEndian, uint16(0))
	binary.Write(&buf, binary.BigEndian, uint16(0))
	hdr := 20
	if s.v6 {
		hdr = 40
	}
	pad := s.l3Len - hdr - 20 + s.tail
	if pad < 0 {
		panic("frame would cut into headers")
	}
	buf.Write(make([]byte, pad))
	return buf.Bytes()
}

// loadMainELF 读一次字节：对这份字节算 SHA-256、再从同一份字节解析 spec。
// ⛔ 不先单独算文件 SHA 再按路径 LoadCollectionSpec —— 那是两次读取，SHA 与加载可能不是同一份内容。
// ⛔ 读不到就 Fatal：Skip 会让顶层以 0 包执行拿到 PASS。
func loadMainELF(t *testing.T) (*ebpf.CollectionSpec, string, string) {
	t.Helper()
	path := os.Getenv("XDROP_BPF_ELF")
	if path == "" {
		path = "../../bpf/xdrop_main.elf"
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ELF %s not readable (build BPF first, or set XDROP_BPF_ELF): %v", path, err)
	}
	sum := sha256.Sum256(raw)
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("LoadCollectionSpecFromReader: %v", err)
	}
	return spec, path, hex.EncodeToString(sum[:])
}

// srcPoint：一条规则，和在这条规则下要打的包及各自的期望判决。
type srcPoint struct {
	rule ruleValueWire
	pkts []pktSpec
	want []uint32
}

// srcScenario：显式场景只有一个点；扫描场景每个取值一个点。
type srcScenario struct {
	name   string
	bitmap uint64
	points []srcPoint
	proves string
}

func buildScenarios() []srcScenario {
	drop := ruleValueWire{LogicalID: 540401, Action: 1}
	v4 := func(l3 int, fl uint8) pktSpec { return pktSpec{l3Len: l3, tcpFlags: fl} }
	v6 := func(l3 int, fl uint8) pktSpec { return pktSpec{v6: true, l3Len: l3, tcpFlags: fl} }
	// 帧固定（v4 54 字节 / v6 74 字节：以太 + IP + TCP，无填充），声明长度任意 —— 程序读的是 IP 头字段⛔ 不是帧长
	v4hdr := func(l3 int, fl uint8) pktSpec { return pktSpec{l3Len: l3, tcpFlags: fl, tail: 40 - l3} }
	v6hdr := func(l3 int, fl uint8) pktSpec { return pktSpec{v6: true, l3Len: l3, tcpFlags: fl, tail: 60 - l3} }
	bit7 := uint64(1) << comboDstPortOnly
	D, P := srcXDPDrop, srcXDPPass
	one := func(rule ruleValueWire, pkts []pktSpec, want []uint32) []srcPoint {
		return []srcPoint{{rule: rule, pkts: pkts, want: want}}
	}

	scs := []srcScenario{
		{ // 阳性对照：装配对了、combo 不隐形 ⇒ 无论长度都 DROP
			name: "reach", bitmap: bit7,
			points: one(drop, []pktSpec{v4(64, tcpSYN), v4(256, tcpSYN)}, []uint32{D, D}),
			proves: "6 次 Put 装配到位；dst_port 规则经 combo 7 可达",
		},
		{ // 阴性对照：bitmap 指到 combo 8，同一条规则隐形 ⇒ 都 PASS（这就是那个坑的样子）
			name: "wrong_combo", bitmap: uint64(1) << comboSrcIPOnly,
			points: one(drop, []pktSpec{v4(64, tcpSYN), v4(256, tcpSYN)}, []uint32{P, P}),
			proves: "bitmap 真在门口；判决不翻可能只是 combo 隐形",
		},
		{
			name: "pkt_len_min", bitmap: bit7,
			points: one(ruleValueWire{LogicalID: 540402, Action: 1, PktLenMin: 256}, []pktSpec{v4(64, tcpSYN), v4(256, tcpSYN)}, []uint32{P, D}),
			proves: "attrs.pkt_len 随 IPv4 tot_len 变化（只设下界）",
		},
		{
			name: "pkt_len_max", bitmap: bit7,
			points: one(ruleValueWire{LogicalID: 540403, Action: 1, PktLenMax: 100}, []pktSpec{v4(64, tcpSYN), v4(256, tcpSYN)}, []uint32{D, P}),
			proves: "attrs.pkt_len 随 IPv4 tot_len 变化（只设上界）",
		},
		{
			name: "pkt_len_boundary_256_v6", bitmap: bit7,
			points: one(ruleValueWire{LogicalID: 540404, Action: 1, PktLenMin: 256}, []pktSpec{v6(255, tcpSYN), v6(256, tcpSYN)}, []uint32{P, D}),
			proves: "IPv6 分支 attrs.pkt_len == payload_len + 40（帧长 = 14 + 声明）",
		},
		{ // 帧长 ≠ 声明长度：声明 255 却多一字节（帧 270）、声明 256 却少一字节（帧 269）
			name: "pkt_len_frame_mismatch_v4", bitmap: bit7,
			points: one(ruleValueWire{LogicalID: 540405, Action: 1, PktLenMin: 256},
				[]pktSpec{{l3Len: 255, tcpFlags: tcpSYN, tail: +1}, {l3Len: 256, tcpFlags: tcpSYN, tail: -1}}, []uint32{P, D}),
			proves: "attrs.pkt_len 来自 IP 头声明⛔ 不是帧长（data_end-data-14 在这里同判反）",
		},
		{
			name: "pkt_len_frame_mismatch_v6", bitmap: bit7,
			points: one(ruleValueWire{LogicalID: 540406, Action: 1, PktLenMin: 256},
				[]pktSpec{{v6: true, l3Len: 255, tcpFlags: tcpSYN, tail: +1}, {v6: true, l3Len: 256, tcpFlags: tcpSYN, tail: -1}}, []uint32{P, D}),
			proves: "IPv6 分支同上",
		},
		{ // 掩码与值分离：SYN 且非 ACK
			name: "tcp_flags_mask_vs_value", bitmap: bit7,
			points: one(ruleValueWire{LogicalID: 540407, Action: 1, TcpFlagsMask: tcpSYN | tcpACK, TcpFlagsValue: tcpSYN},
				[]pktSpec{v4(64, tcpSYN), v4(64, tcpSYN|tcpACK), v4(64, tcpACK)}, []uint32{D, P, P}),
			proves: "attrs.tcp_flags 同时参与掩码与值比较（SYN|ACK 必须 PASS）",
		},
		{
			name: "tcp_flags_v6", bitmap: bit7,
			points: one(ruleValueWire{LogicalID: 540408, Action: 1, TcpFlagsMask: tcpACK, TcpFlagsValue: tcpACK},
				[]pktSpec{v6(64, tcpACK), v6(64, tcpSYN)}, []uint32{D, P}),
			proves: "IPv6 分支 attrs.tcp_flags 随 flags 字节变化（部分掩码）",
		},
	}

	// pkt_len 全域扫描：规则 min=max=x ⇒ 当且仅当 attrs.pkt_len == x 才 DROP。
	// 每点三包：声明 x 带 flags 0x00 ⇒ DROP · 声明 x 带 flags 0xFF ⇒ DROP · 声明邻值 ⇒ PASS（证明这一点的规则真在区分长度）。
	// x=0 例外：min=max=0 表示「不限」，改用 min=1 ⇒ 声明 0（两档 flags）PASS、声明 1 DROP。
	lenSweep := func(name string, hdr func(int, uint8) pktSpec, lo int) srcScenario {
		pts := make([]srcPoint, 0, 0x10000-lo)
		for x := lo; x <= 0xFFFF; x++ {
			if x == 0 {
				pts = append(pts, srcPoint{rule: ruleValueWire{LogicalID: 540409, Action: 1, PktLenMin: 1},
					pkts: []pktSpec{hdr(0, 0x00), hdr(0, 0xFF), hdr(1, 0x00)}, want: []uint32{P, P, D}})
				continue
			}
			nb := x + 1
			if x == 0xFFFF {
				nb = x - 1
			}
			pts = append(pts, srcPoint{rule: ruleValueWire{LogicalID: 540410, Action: 1, PktLenMin: uint16(x), PktLenMax: uint16(x)},
				pkts: []pktSpec{hdr(x, 0x00), hdr(x, 0xFF), hdr(nb, 0x00)}, want: []uint32{D, D, P}})
		}
		return srcScenario{name: name, bitmap: bit7, points: pts,
			proves: "attrs.pkt_len == 声明长度，逐值精确（flags 全 0 / 全 1 两档）"}
	}
	// tcp_flags 全域扫描：规则 mask=0xFF value=x ⇒ 当且仅当 attrs.tcp_flags == x 才 DROP。
	// 每点三包：flags x 带长度 lens[0] ⇒ DROP · flags x 带长度 lens[1] ⇒ DROP · flags x+1 ⇒ PASS。
	flagSweep := func(name string, hdr func(int, uint8) pktSpec, lens [2]int) srcScenario {
		pts := make([]srcPoint, 0, 0x100)
		for x := 0; x <= 0xFF; x++ {
			pts = append(pts, srcPoint{rule: ruleValueWire{LogicalID: 540411, Action: 1, TcpFlagsMask: 0xFF, TcpFlagsValue: uint8(x)},
				pkts: []pktSpec{hdr(lens[0], uint8(x)), hdr(lens[1], uint8(x)), hdr(lens[0], uint8(x+1))}, want: []uint32{D, D, P}})
		}
		return srcScenario{name: name, bitmap: bit7, points: pts,
			proves: "attrs.tcp_flags == TCP flags 字节，逐值精确（长度全 0 / 全 1 两档）"}
	}
	scs = append(scs,
		lenSweep("pkt_len_sweep_v4", v4hdr, 0),
		lenSweep("pkt_len_sweep_v6", v6hdr, 40), // payload_len 0..65495；再往上 +40 回绕，见文件头
		flagSweep("tcp_flags_sweep_v4", v4hdr, [2]int{0, 0xFFFF}),
		flagSweep("tcp_flags_sweep_v6", v6hdr, [2]int{40, 0xFFFF}),
	)
	return scs
}

// srcAssembly：一种双缓冲选择器组合。slot = active_config[0]（0=config_a 1=config_b），
// sel = 在用 config 的 CONFIG_RULE_MAP_SELECTOR（0=blacklist 1=blacklist_b）。
type srcAssembly struct {
	name string
	slot uint64
	sel  uint64
}

var srcAssemblies = []srcAssembly{{"cfgA_sel0", 0, 0}, {"cfgA_sel1", 0, 1}, {"cfgB_sel0", 1, 0}, {"cfgB_sel1", 1, 1}}

// TestPktAttrsSourceMain：xdp_firewall_main 的 pkt_attrs.pkt_len / .tcp_flags 确实来自解析出的报文字段。
// 一次加载（每次 NewCollection 要过 16 万条指令的 verifier，≈8 s），逐装配、逐场景重 Put。
func TestPktAttrsSourceMain(t *testing.T) {
	spec, path, sum := loadMainELF(t)
	t.Logf("elf=%s sha256=%s", path, sum)

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		t.Fatalf("NewCollection (needs CAP_BPF / root): %v", err)
	}
	defer coll.Close()
	prog := coll.Programs["xdp_firewall_main"]
	if prog == nil {
		t.Fatal("xdp_firewall_main not found")
	}
	for _, m := range []string{"active_config", "config_a", "config_b", "blacklist", "blacklist_b"} {
		if coll.Maps[m] == nil {
			t.Fatalf("map %s not found", m)
		}
	}
	put := func(m string, k, v interface{}) {
		if err := coll.Maps[m].Put(k, v); err != nil {
			t.Fatalf("%s.Put(%v): %v", m, k, err)
		}
	}

	scenarios := buildScenarios()
	if len(scenarios) != wantScenarios {
		t.Fatalf("scenario table has %d entries, want %d (update wantScenarios/wantPackets together)", len(scenarios), wantScenarios)
	}
	if len(srcAssemblies) != wantAssemblies {
		t.Fatalf("assembly table has %d entries, want %d", len(srcAssemblies), wantAssemblies)
	}
	ran, redTotal, runs := 0, 0, 0
	for _, asm := range srcAssemblies {
		cfgOn, cfgOff := "config_a", "config_b"
		if asm.slot == 1 {
			cfgOn, cfgOff = cfgOff, cfgOn
		}
		blOn, blOff := "blacklist", "blacklist_b"
		if asm.sel == 1 {
			blOn, blOff = blOff, blOn
		}
		for _, sc := range scenarios {
			sc, asm := sc, asm
			runs++
			t.Run(asm.name+"/"+sc.name, func(t *testing.T) {
				put("active_config", uint32(0), asm.slot)
				put(cfgOn, cfgBlacklistCount, uint64(1))
				put(cfgOn, cfgRuleBitmap, sc.bitmap)
				put(cfgOn, cfgRuleMapSelector, asm.sel)
				put(cfgOn, cfgAnomalyRuleCount, uint64(0))
				// 不在用的一侧清空：每种装配从干净状态开始（⛔ 不据此证明程序按选择器取表，见文件头）
				for _, slot := range []uint32{cfgBlacklistCount, cfgRuleBitmap, cfgRuleMapSelector, cfgAnomalyRuleCount} {
					put(cfgOff, slot, uint64(0))
				}
				if err := coll.Maps[blOff].Delete(dstPortOnlyKey(srcTestDstPort)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
					t.Fatalf("%s.Delete: %v", blOff, err)
				}

				n, red := 0, 0
				var bySlot [3]int // 点内第几个包红：扫描场景 = [x 带全 0 档, x 带全 1 档, 邻值]
				for pi, pt := range sc.points {
					if len(pt.pkts) != len(pt.want) {
						t.Fatalf("point[%d] pkts/want length mismatch", pi)
					}
					var val bytes.Buffer
					if err := binary.Write(&val, binary.LittleEndian, &pt.rule); err != nil {
						t.Fatalf("encode rule_value: %v", err)
					}
					if val.Len() != 32 {
						t.Fatalf("rule_value wire is %d bytes, want 32", val.Len())
					}
					put(blOn, dstPortOnlyKey(srcTestDstPort), val.Bytes())

					for i, ps := range pt.pkts {
						pkt := buildTCP(ps)
						ret, _, err := prog.Test(pkt)
						if err != nil {
							t.Fatalf("point[%d] pkt[%d] prog.Test: %v", pi, i, err)
						}
						n++
						if ret != pt.want[i] {
							red++
							bySlot[i]++
							if red <= srcMaxShownRed {
								t.Errorf("point[%d] pkt[%d] %s frame=%dB rule{min=%d max=%d mask=0x%02x value=0x%02x}: got %d want %d — %s",
									pi, i, ps, len(pkt), pt.rule.PktLenMin, pt.rule.PktLenMax, pt.rule.TcpFlagsMask, pt.rule.TcpFlagsValue,
									ret, pt.want[i], sc.proves)
							}
						} else if len(sc.points) == 1 {
							t.Logf("pkt[%d] %s frame=%dB: verdict %d ✓", i, ps, len(pkt), ret)
						}
					}
				}
				if red > srcMaxShownRed {
					t.Errorf("… another %d red packets not shown", red-srcMaxShownRed)
				}
				t.Logf("scenario=%s/%s points=%d packets=%d red=%d by_pkt=%d/%d/%d", asm.name, sc.name, len(sc.points), n, red, bySlot[0], bySlot[1], bySlot[2])
				ran += n
				redTotal += red
			})
		}
	}
	// 门必须断言执行量：0 个包跑过也能「无失败」。
	if runs != wantScenarios*wantAssemblies || ran != wantPackets {
		t.Fatalf("executed %d subtests / %d packets, want %d / %d", runs, ran, wantScenarios*wantAssemblies, wantPackets)
	}
	t.Logf("assemblies=%d scenarios=%d packets=%d red=%d elf_sha256=%s", len(srcAssemblies), runs, ran, redTotal, sum)
}
