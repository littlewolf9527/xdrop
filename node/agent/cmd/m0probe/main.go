// m0probe —— Phase 1 里程碑 M0 的测量工具。
//
// ── 它回答什么 ──────────────────────────────────────────────────────────────
//
// 「把 rule_value 换成候选集之后，程序还装不装得进 verifier 的指令预算？
//
//	最多能挂几个候选？」
//
// 这是 **唯一能否决整个 Phase 1 的事实**（internal_docs/architecture.md §2.6、
// plans/phase1/plan.md §M0）。现有证据（F-006 / F-007 / F-046 以及数据面里
// 那几条「曾经超限」的注释）**既不能证明可行、也不能证明不可行** ⇒ 只能实测。
//
// ── 它为什么不是普通测试 ────────────────────────────────────────────────────
//
// 它 **真的把程序加载进内核**。verifier 只在 load 时运行，静态分析拿不到这个数。
// 需要 root。它不 attach 任何网卡、不 pin 任何东西，Close 后内核里不留痕迹。
//
// ── 输出里哪个数字是承重的 ──────────────────────────────────────────────────
//
//	VerifiedInstructions  ← 🔴 这个。verifier 实际走过的指令数，1M 上限约束的就是它
//	TranslatedSize        ← 程序体积，参考值，与预算不是同一回事
//
// 预算 **按程序各算**（F-046）⇒ 每个入口都要单独看，不能只看最大的那个。
//
// 用法：
//
//	m0probe <标签> <a.elf> [b.elf ...]
//
// 标签只是打印出来标记这一轮是哪个 N，不影响行为。
package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"sort"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "用法: m0probe <标签> <a.elf> [b.elf ...]")
		os.Exit(2)
	}
	label := os.Args[1]

	// 内核 5.11+ 用 memcg 记账，这一步通常是空操作；失败不致命但要说出来，
	// 否则「加载失败」会被误读成 verifier 拒绝（其实是 memlock 不够）。
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintf(os.Stderr, "⚠️  RemoveMemlock 失败: %v\n", err)
	}

	fmt.Printf("╔══════════════════════════════════════════════════════════════╗\n")
	fmt.Printf("║ M0 verifier 探针 · 本轮标签: %-31s ║\n", label)
	fmt.Printf("╚══════════════════════════════════════════════════════════════╝\n")

	allOK := true
	for _, path := range os.Args[2:] {
		if !probe(path) {
			allOK = false
		}
	}

	fmt.Printf("\n═══════════════════════════════════════════════════════════════\n")
	if allOK {
		fmt.Printf("本轮结果【%s】: ✅ 全部程序通过 verifier\n", label)
		return
	}
	fmt.Printf("本轮结果【%s】: 🔴 有程序未能加载（上界证据）\n", label)
	os.Exit(1)
}

func probe(path string) bool {
	fmt.Printf("\n────────────────────────────────────────────────────────────────\n")
	fmt.Printf("ELF: %s\n", path)
	fmt.Printf("────────────────────────────────────────────────────────────────\n")

	// 🔑 读一次字节：对**这份字节**算 SHA-256，再从**同一份字节**解析。
	// ⛔ 不先单独算文件 SHA 再按路径 LoadCollectionSpec —— 那是两次读取，
	// 打印的 SHA 与实际加载的内容可能不是同一份（2026-09-20 冻结验收门犯过这个错）。
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Printf("🔴 读 ELF 失败（还没到 verifier 这一步）: %v\n", err)
		return false
	}
	sum := sha256.Sum256(raw)
	fmt.Printf("ELF sha256: %x  (%d bytes, 哈希与加载用同一份字节)\n", sum, len(raw))
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(raw))
	if err != nil {
		fmt.Printf("🔴 解析 ELF 失败（还没到 verifier 这一步）: %v\n", err)
		return false
	}

	names := make([]string, 0, len(spec.Programs))
	for n := range spec.Programs {
		names = append(names, n)
	}
	sort.Strings(names)
	fmt.Printf("程序入口 %d 个: %v\n", len(names), names)

	// 顺带把候选集的 value_size 打出来 —— 它是「本轮 N 是多少」的独立佐证，
	// 比相信命令行标签可靠（标签是人写的，这个是编译产物里的）。
	for _, m := range []string{"blacklist", "blacklist_b", "cidr_blacklist", "cidr_blist_b"} {
		if ms, ok := spec.Maps[m]; ok {
			fmt.Printf("  map %-16s key_size=%-4d value_size=%d\n", m, ms.KeySize, ms.ValueSize)
		}
	}

	// 🔴 **逐个程序单独加载**，不是整个 collection 一次性加载。
	//
	// 理由：预算按程序各算（F-046）。整体加载时任何一个程序超限都只会返回一个
	// 笼统的错误，**分不清是谁超的**，而「谁超的」正是 M0 要记录的东西
	// （plans/phase1 验收条件 M0-A：三个入口的指令数都要有记录）。
	//
	// 另一半理由：一个程序失败不该掩盖其余程序的读数。先失败的那个会让后面
	// 全部变成「没测」，而「没测」和「测了没超」长得一样（feedback：空读数要有仪器）。
	allOK := true
	for _, n := range names {
		fmt.Printf("\n──── 入口 %s ────\n", n)

		one := spec.Copy()
		for other := range one.Programs {
			if other != n {
				delete(one.Programs, other)
			}
		}

		coll, err := ebpf.NewCollectionWithOptions(one, ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				// Stats 给出末尾那行 "processed N insns (limit 1000000) ..."。
				// 不开 Branch —— 那会打出几十 MB 的逐指令轨迹，对本次测量没有增量信息。
				LogLevel: ebpf.LogLevelStats,
			},
		})
		if err != nil {
			allOK = false
			var ve *ebpf.VerifierError
			if errors.As(err, &ve) {
				fmt.Printf("🔴🔴 VERIFIER 拒绝加载 %s —— 上界证据\n\n%+v\n", n, ve)
			} else {
				fmt.Printf("🔴 %s 加载失败，但**不是** verifier 拒绝（别把它当上界）: %v\n", n, err)
			}
			continue
		}

		p := coll.Programs[n]
		info, ierr := p.Info()
		if ierr != nil {
			fmt.Printf("取 ProgramInfo 失败: %v\n", ierr)
		} else {
			if vi, ok := info.VerifiedInstructions(); ok {
				fmt.Printf("✅ VerifiedInstructions = %d   (内核上限 1000000，占用 %.2f%%)\n",
					vi, float64(vi)/10000.0)
			} else {
				fmt.Printf("VerifiedInstructions: 内核未提供\n")
			}
			if ts, terr := info.TranslatedSize(); terr == nil {
				fmt.Printf("   TranslatedSize      = %d 条指令（程序体积，非预算口径）\n", ts)
			}
		}
		fmt.Printf("verifier 日志原文:\n%s\n", p.VerifierLog)
		coll.Close()
	}
	return allOK
}
