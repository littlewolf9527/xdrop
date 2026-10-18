// Package abi holds the ONE test that ties the C data-plane structs to the Go
// structs that write into them.
//
// ── 为什么单独一个包 ────────────────────────────────────────────────────────
//
// 它不属于 api 层——它跨 C 与 Go 两侧，放进 api 会让人以为是 API 的测试。
// 这个包里只应该有跨语言契约，不放别的。
//
// ── 它补的是哪个洞 ──────────────────────────────────────────────────────────
//
// 在此之前，守护结构布局的测试只读 Go 侧的 unsafe.Sizeof 与字段地址差
// （node/agent/api/rule_value_layout_test.go），而 C 侧只有注释和（Phase 0 新加的）
// _Static_assert 在守。两边各守各的 ⇒ **改 C、不改 Go，全绿**。
// 见 internal_docs/tech-debt.md TD-010。
//
// 本测试读 **编译产物**：map 的 key_size / value_size 是 C 侧 `sizeof(struct ...)`
// 编译出来的结果，写进 ELF。拿它和 Go 侧 unsafe.Sizeof 比，两种语言就绑在一起了。
//
// ── 为什么不需要内核 ────────────────────────────────────────────────────────
//
// ebpf.LoadCollectionSpec 只解析 ELF，不 attach、不需要 root、不需要 BPF 文件系统。
// 所以本测试能在任何有 ELF 的机器上跑。
//
// ── 🔴 为什么没有跳过路径 ───────────────────────────────────────────────────
//
// ELF 不存在时本测试 **失败**，不 Skip。
//
// 本仓库已经有一批「条件不满足就跳过」而从此永不执行的测试（internal_docs/facts.md
// F-052 的 decoder fixture、TD-018 的 positive control）。Phase 0 的目的就是消灭这种形态，
// 不能在同一个 Phase 里又造一个。
//
// 在没有 BPF 编译器的机器上（例如 macOS，Apple clang 没有 bpf target）本测试会红。
// **那是正确行为**——它准确地说明了「你这里没法验证 ABI」，而不是假装验证过了。
package abi

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"

	"github.com/littlewolf9527/xdrop/node/agent/api"
)

// elfPath 指向 make -C node/bpf 的产物。
const elfRelPath = "../../bpf/xdrop_main.elf"

const buildHint = `
xdrop_main.elf 不存在。先跑：

    make -C node/bpf

本测试是 Phase 1 迁移期唯一的跨语言安全网，**不提供跳过路径**——
理由见 internal_docs/facts.md F-052（本仓有一批测试正是这样静默失效的）。

macOS 上 Apple clang 没有 bpf target，需要装带 BPF 后端的 LLVM，或在 Linux 上跑。`

// loadSpec 加载 ELF；失败即 t.Fatal，绝不 Skip。
func loadSpec(t *testing.T) *ebpf.CollectionSpec {
	t.Helper()
	abs, err := filepath.Abs(elfRelPath)
	if err != nil {
		t.Fatalf("解析 ELF 路径失败: %v", err)
	}
	if _, err := os.Stat(abs); err != nil {
		t.Fatalf("找不到 %s: %v\n%s", abs, err, buildHint)
	}
	spec, err := ebpf.LoadCollectionSpec(abs)
	if err != nil {
		t.Fatalf("解析 %s 失败: %v", abs, err)
	}
	return spec
}

// sizeCase 描述一条「ELF 里某张 map 的某个尺寸，必须等于 Go 侧某个结构的大小」。
type sizeCase struct {
	mapName string
	field   string // "key" 或 "value"
	goType  string
	goSize  uintptr
	why     string
}

func (c sizeCase) elfSize(ms *ebpf.MapSpec) uint32 {
	if c.field == "key" {
		return ms.KeySize
	}
	return ms.ValueSize
}

// TestELFMapSizesMatchGoStructs 是本包的核心。
//
// 覆盖 Phase 1 会动到的所有 map（清单依据 internal_docs/facts.md F-001 / F-002）。
func TestELFMapSizesMatchGoStructs(t *testing.T) {
	spec := loadSpec(t)

	ruleKeySize := unsafe.Sizeof(api.RuleKey{})
	ruleValueSize := unsafe.Sizeof(api.RuleValue{})
	cidrKeySize := unsafe.Sizeof(api.CIDRRuleKey{})

	cases := []sizeCase{
		// ── rule_key 族（F-001）。Phase 1 不改 key，但改错了必须立刻知道。
		{"blacklist", "key", "api.RuleKey", ruleKeySize,
			"blacklist 的 key 就是五元组身份（F-004）"},
		{"blacklist_b", "key", "api.RuleKey", ruleKeySize,
			"B 槽必须与 A 槽同布局，否则原子切换会换出一个读不懂的表"},
		{"whitelist", "key", "api.RuleKey", ruleKeySize,
			"白名单与黑名单共用 rule_key"},

		// ── rule_value 族（F-005）。**Phase 1 要动的就是这个。**
		{"blacklist", "value", "api.RuleValue", ruleValueSize,
			"🔴 Phase 1 把 value 扩成候选集，改动首先落在这里"},
		{"blacklist_b", "value", "api.RuleValue", ruleValueSize,
			"🔴 同上，B 槽必须同步"},

		// ── cidr_rule_key 族（F-002 / F-045）。与 rule_key 是两套不同的身份。
		{"cidr_blacklist", "key", "api.CIDRRuleKey", cidrKeySize,
			"CIDR 走另一套身份：src_id/dst_id 是节点本地整数 ID，不是 IP"},
		{"cidr_blist_b", "key", "api.CIDRRuleKey", cidrKeySize,
			"B 槽必须与 A 槽同布局"},
		{"cidr_blacklist", "value", "api.RuleValue", ruleValueSize,
			"🔴 CIDR 与 exact 共用同一个 value 结构 ⇒ Phase 1 改 value 会同时影响两条路径"},
		{"cond_a", "key", "api.RuleKey", ruleKeySize, "B1 exact conditions A"},
		{"cond_b", "key", "api.RuleKey", ruleKeySize, "B1 exact conditions B"},
		{"cidr_cond_a", "key", "api.CIDRRuleKey", cidrKeySize, "B1 CIDR conditions A"},
		{"cidr_cond_b", "key", "api.CIDRRuleKey", cidrKeySize, "B1 CIDR conditions B"},
		{"cond_a", "value", "api.ConditionValue", unsafe.Sizeof(api.ConditionValue{}), "B1 condition row ABI"},
		{"cond_b", "value", "api.ConditionValue", unsafe.Sizeof(api.ConditionValue{}), "B1 condition row ABI"},
		{"cidr_cond_a", "value", "api.ConditionValue", unsafe.Sizeof(api.ConditionValue{}), "B1 condition row ABI"},
		{"cidr_cond_b", "value", "api.ConditionValue", unsafe.Sizeof(api.ConditionValue{}), "B1 condition row ABI"},
	}

	for _, c := range cases {
		t.Run(fmt.Sprintf("%s_%s", c.mapName, c.field), func(t *testing.T) {
			ms, ok := spec.Maps[c.mapName]
			if !ok {
				t.Fatalf("ELF 里没有名为 %q 的 map。\n"+
					"要么它被改名/删除了（那就同步改本测试与 facts.md F-001/F-002），"+
					"要么 ELF 是旧的（重新 make）。", c.mapName)
			}
			got, want := c.elfSize(ms), uint32(c.goSize)
			if got != want {
				t.Fatalf(""+
					"跨语言 ABI 不一致：%s.%s_size\n"+
					"  C 侧（ELF 编译产物）= %d\n"+
					"  Go 侧 %s          = %d\n"+
					"\n"+
					"为什么这条重要：%s\n"+
					"\n"+
					"⇒ 只改了一侧。两侧必须同一个 commit 一起改。\n"+
					"   不一致会让 Agent 按错误宽度读写 map：轻则字段错位，重则 pin schema "+
					"不符导致 map 被删重建（facts.md F-011）。",
					c.mapName, c.field, got, c.goType, want, c.why)
			}
		})
	}
}

// TestELFHasExpectedPrograms 钉住程序入口数。
//
// 为什么值得测：verifier 的指令预算是**按程序各算的**（facts.md F-046）。
// 悄悄多出一个程序入口，意味着多一个需要单独进预算的对象——
// 这正是 Phase 1 里程碑 M0 要逐个量的东西。
func TestELFHasExpectedPrograms(t *testing.T) {
	spec := loadSpec(t)

	want := []string{"xdp_firewall_main"}
	for _, name := range []string{"tail_stash", "rl_states", "cidr_rl_states"} {
		if spec.Maps[name] != nil {
			t.Errorf("retired map remains: %s", name)
		}
	}
	for _, name := range want {
		if _, ok := spec.Programs[name]; !ok {
			t.Errorf("ELF 里缺少程序入口 %q（B1 5-4 main 只保留一个入口）", name)
		}
	}
	if len(spec.Programs) != len(want) {
		got := make([]string, 0, len(spec.Programs))
		for n := range spec.Programs {
			got = append(got, n)
		}
		t.Errorf("xdrop_main.elf 的程序入口数 = %d %v，期望 %d %v。\n"+
			"多出来的入口要单独进 verifier 预算（F-046）；改动前先读 plans/phase1 M0。",
			len(spec.Programs), got, len(want), want)
	}
}

// TestGoStructSizesAreWhatFactsSay 是一道**廉价的反向哨兵**。
//
// 上面两个测试在没有 ELF 的机器上会失败（设计如此）。本测试不依赖 ELF，
// 所以即使在 macOS 上也能跑——它至少保证 Go 侧没有单方面漂移。
//
// ⚠️ 它**不能**替代上面的跨语言断言：Go 侧对了、C 侧变了，本测试照样绿。
// 留着它是为了「有 ELF 时抓两侧不一致，没 ELF 时至少抓 Go 侧不一致」。
func TestGoStructSizesAreWhatFactsSay(t *testing.T) {
	for _, c := range []struct {
		name string
		got  uintptr
		want uintptr
		fact string
	}{
		{"api.RuleKey", unsafe.Sizeof(api.RuleKey{}), 40, "F-004"},
		{"api.RuleValue", unsafe.Sizeof(api.RuleValue{}), 32, "F-005"},
		{"api.CIDRRuleKey", unsafe.Sizeof(api.CIDRRuleKey{}), 16, "F-045"},
	} {
		if c.got != c.want {
			t.Errorf("sizeof(%s) = %d，期望 %d（internal_docs/facts.md %s）。\n"+
				"若这是有意的结构变更：同步改 C 侧 xdrop.h 的 _Static_assert、"+
				"本测试、facts.md %s，并跑 bash internal_docs/_verify_facts.sh",
				c.name, c.got, c.want, c.fact, c.fact)
		}
	}
}
