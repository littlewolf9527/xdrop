package api

import (
	"fmt"
	"sort"
	"testing"
)

// Exhaustive output-domain regression retained from M1. This does not detect
// overlapping/unreachable cases by itself; TestS2aClassifierConditions checks
// every raw condition and first-hit witness. Retired slots are not active IDs.

// comboRoster 是 xdrop.h 与 combo.go 共同定义的合法编号集合。
// ⛔ 这是**白名单**。不要改成「范围检查」—— 范围检查正是生产代码里那条
// 挡不住第 19 位的守卫（feedback_blocklist_never_complete）。
var comboRoster = func() map[int]string {
	m := map[int]string{
		0: "ComboExact5Tuple", 1: "ComboWildcardSrcIP", 2: "ComboWildcardSrcIPPort",
		3: "ComboDstIPProto", 4: "ComboDstIPOnly", 5: "ComboProtoOnly",
		6: "ComboSrcPortOnly", 7: "ComboDstPortOnly", 8: "ComboSrcIPOnly",
		9: "ComboSrcIPProto", 10: "ComboSrcDstIP", 11: "ComboSrcIPDstPort",
		12: "ComboDstIPDstPort", 13: "ComboSrcDstIPProto", 14: "ComboSrcIPDstPortProto",
		15: "ComboSrcPortProto", 16: "ComboDstPortProto", 17: "ComboSrcIPSrcPort",
		18: "ComboSrcIPSrcPortProto",
		// 19 缺席：历史空洞，见 xdrop.h 的移除注记。
		21: "ComboSrcDstIPDstPort",
		22: "ComboSrcDstIPDstPortProto", 23: "ComboSrcIPPorts", 24: "ComboSrcIPPortsProto",
		25: "ComboDstIPSrcPort", 26: "ComboDstIPSrcPortProto", 27: "ComboPortsOnly",
		28: "ComboPortsProto", 29: "ComboSrcDstIPSrcPort", 30: "ComboSrcDstIPSrcPortProto",
		31: "ComboDstIPPorts", 33: "ComboAllExceptProto",
	}
	return m
}()

// keyFor 造一个恰好点亮指定五个布尔量的 RuleKey。
// 取值刻意用「非 1 的随手值」，以免某处把 1 当特殊值时被掩盖。
func keyFor(hasSrcIP, hasDstIP, hasSrcPort, hasDstPort, hasProto bool) RuleKey {
	var k RuleKey
	if hasSrcIP {
		k.SrcIP[0], k.SrcIP[3] = 10, 7
	}
	if hasDstIP {
		k.DstIP[0], k.DstIP[3] = 10, 9
	}
	if hasSrcPort {
		k.SrcPort = 40000
	}
	if hasDstPort {
		k.DstPort = 8443
	}
	if hasProto {
		k.Protocol = 17 // UDP
	}
	return k
}

func bits(i int) (b [5]bool) {
	for j := 0; j < 5; j++ {
		b[j] = i&(1<<j) != 0
	}
	return
}

func label(b [5]bool) string {
	names := [5]string{"srcIP", "dstIP", "srcPort", "dstPort", "proto"}
	s := ""
	for j, on := range b {
		if on {
			if s != "" {
				s += "+"
			}
			s += names[j]
		}
	}
	if s == "" {
		return "(全空)"
	}
	return s
}

// TestGetComboTypeExhaustive_Never19 是判据 ③ 的支柱。
func TestGetComboTypeExhaustive_Never19(t *testing.T) {
	const inputs = 1 << 5

	// 阳性对照：先证明这套装置**能**看见一个已知值，否则「32 个都合格」
	// 与「装置根本没在判」输出相同（feedback_null_reading_needs_live_instrument）。
	if got := getComboType(keyFor(true, true, true, true, true)); got != ComboExact5Tuple {
		t.Fatalf("阳性对照失败：五字段全非零应得 ComboExact5Tuple(%d)，实得 %d。"+
			"装置或被测函数有问题，后面 32 例的结论都不可信",
			ComboExact5Tuple, got)
	}

	produced := map[int][]string{}
	for i := 0; i < inputs; i++ {
		b := bits(i)
		got := getComboType(keyFor(b[0], b[1], b[2], b[3], b[4]))

		if got == ComboUnknown {
			produced[ComboUnknown] = append(produced[ComboUnknown], label(b))
			continue
		}
		if got == 19 {
			t.Errorf("🔴 输入 %s 得到 combo 19 —— 那是历史空洞，掩码表该格为全零，"+
				"会构造出五字段全通配的 key。判据③ 被推翻。", label(b))
			continue
		}
		if _, ok := comboRoster[got]; !ok {
			t.Errorf("🔴 输入 %s 得到 %d，不在名册内。生产守卫只查 [0,64) 范围，"+
				"拦不住它 ⇒ 位图会被置上一个没有掩码的位。", label(b), got)
			continue
		}
		produced[got] = append(produced[got], label(b))
	}

	// 每个输入必须**恰好**产生一个结果，且不同输入不该塌到同一个 combo
	// （塌陷 = 有输入被吃掉，正是 F-072 那类缺陷的形状）。
	total := 0
	for _, ins := range produced {
		total += len(ins)
	}
	if total != inputs {
		t.Fatalf("计数对不上：%d 个输入只归档了 %d 个", inputs, total)
	}
	for combo, ins := range produced {
		if combo != ComboUnknown && len(ins) > 1 {
			t.Errorf("🔴 combo %d(%s) 被 %d 个不同输入命中：%v —— "+
				"应当一一对应", combo, comboRoster[combo], len(ins), ins)
		}
	}
}

// TestGetComboTypeExhaustive_DeadCombosMatchF072 retains the historical test
// identity. S2a now requires the entire active roster to be reachable. The
// frozen before-source and raw-condition gate preserve the old defect proof.
func TestGetComboTypeExhaustive_DeadCombosMatchF072(t *testing.T) {
	reachable := map[int]bool{}
	unknownInputs := 0
	for i := 0; i < 1<<5; i++ {
		b := bits(i)
		got := getComboType(keyFor(b[0], b[1], b[2], b[3], b[4]))
		if got == ComboUnknown {
			unknownInputs++
			continue
		}
		reachable[got] = true
	}

	var dead []int
	for n := range comboRoster {
		if !reachable[n] {
			dead = append(dead, n)
		}
	}
	sort.Ints(dead)

	// S2a removes the aliases from the active roster; every surviving ID is reachable.
	wantDead := []int{}
	if fmt.Sprint(dead) != fmt.Sprint(wantDead) {
		t.Errorf("🔴 不可达 combo = %v，S2a 活跃名册应为 %v。\n"+
			"  ⇒ 当前活跃名册中的每个编号都必须可达。",
			dead, wantDead)
	}

	// 计数自洽：32 输入 = unknown 的那些 + 可达 combo 数（每个恰一个输入）
	if unknownInputs+len(reachable) != 1<<5 {
		t.Errorf("计数不自洽：unknown=%d + 可达=%d ≠ %d",
			unknownInputs, len(reachable), 1<<5)
	}
	if len(reachable)+len(dead) != len(comboRoster) {
		t.Errorf("可达 %d + 不可达 %d ≠ 名册 %d",
			len(reachable), len(dead), len(comboRoster))
	}

	t.Logf("穷举计数：%d 个输入 → %d 个落到 Unknown（全空 key）+ %d 个可达 combo；"+
		"名册 %d ⇒ 不可达 %v", 1<<5, unknownInputs, len(reachable), len(comboRoster), dead)
}

// TestComboRosterMatchesConstants 防止名册与 combo.go 的常量漂移。
// 名册是本包里手抄的一份副本 ⇒ 必须有东西盯着它别抄错。
func TestComboRosterMatchesConstants(t *testing.T) {
	actual := map[int]string{
		ComboExact5Tuple: "ComboExact5Tuple", ComboWildcardSrcIP: "ComboWildcardSrcIP",
		ComboWildcardSrcIPPort: "ComboWildcardSrcIPPort", ComboDstIPProto: "ComboDstIPProto",
		ComboDstIPOnly: "ComboDstIPOnly", ComboProtoOnly: "ComboProtoOnly",
		ComboSrcPortOnly: "ComboSrcPortOnly", ComboDstPortOnly: "ComboDstPortOnly",
		ComboSrcIPOnly: "ComboSrcIPOnly", ComboSrcIPProto: "ComboSrcIPProto",
		ComboSrcDstIP: "ComboSrcDstIP", ComboSrcIPDstPort: "ComboSrcIPDstPort",
		ComboDstIPDstPort: "ComboDstIPDstPort", ComboSrcDstIPProto: "ComboSrcDstIPProto",
		ComboSrcIPDstPortProto: "ComboSrcIPDstPortProto", ComboSrcPortProto: "ComboSrcPortProto",
		ComboDstPortProto: "ComboDstPortProto", ComboSrcIPSrcPort: "ComboSrcIPSrcPort",
		ComboSrcIPSrcPortProto:    "ComboSrcIPSrcPortProto",
		ComboSrcDstIPDstPort:      "ComboSrcDstIPDstPort",
		ComboSrcDstIPDstPortProto: "ComboSrcDstIPDstPortProto",
		ComboSrcIPPorts:           "ComboSrcIPPorts", ComboSrcIPPortsProto: "ComboSrcIPPortsProto",
		ComboDstIPSrcPort: "ComboDstIPSrcPort", ComboDstIPSrcPortProto: "ComboDstIPSrcPortProto",
		ComboPortsOnly: "ComboPortsOnly", ComboPortsProto: "ComboPortsProto",
		ComboSrcDstIPSrcPort:      "ComboSrcDstIPSrcPort",
		ComboSrcDstIPSrcPortProto: "ComboSrcDstIPSrcPortProto",
		ComboDstIPPorts:           "ComboDstIPPorts",
		ComboAllExceptProto:       "ComboAllExceptProto",
	}
	if len(actual) != len(comboRoster) {
		t.Fatalf("常量 %d 个，名册 %d 个 —— 有一侧漏了", len(actual), len(comboRoster))
	}
	for n, name := range actual {
		if comboRoster[n] != name {
			t.Errorf("编号 %d：常量叫 %s，名册写 %s", n, name, comboRoster[n])
		}
	}
	if _, ok := comboRoster[19]; ok {
		t.Error("🔴 名册里出现了 19 —— 它是历史空洞，不该有名字")
	}
}
