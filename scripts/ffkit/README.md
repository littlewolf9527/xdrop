# FF 节点小刀 ffn-1 / ffkit

依据封存的 FF 节点小刀 PLAN v1.0。从指定 kit-ref/ffkit 拷贝扩展；生产源码、测试和装置一起绑定清单。只用 Python/Go 标准库及模块既有依赖，不下载。macOS dry-run/selfcheck 是装置自检，不是 Linux 真帧或零丢帧证据。

## 输入与运行

SOURCE 为本刀审阅源树，BASELINE 为该树 HEAD（交付时 d39805f4910e4245004cf1157056c0ad749ef379），BEFORE 为独立干净的 d39805f 源树，供 upg/ctl 构建旧 agent+ELF。KIT=$SOURCE/scripts/ffkit。源清单包含 controller、node/agent、node/bpf；kit 位于三个前缀外，避免自引用。重新绑定前先核源改动仍是审阅结果。

```sh
export PYTHONDONTWRITEBYTECODE=1
python3 "$KIT/manifest.py" --source "$SOURCE" --baseline "$BASELINE"
python3 "$KIT/runner.py" --source "$SOURCE" --baseline "$BASELINE" \
  --baseline-src "$BEFORE" --ref <ref-dir> \
  --scratch <work-root>/ffn-r1-scratch \
  --out <work-root>/ffn-r1-results --dry-run --list-cells
```

主会话在 lab 移除 dry-run/list-cells，四轮各用新的 scratch/out。--work-root 将目录前缀守卫参数化，缺省 /root/xdrop-lab/；scratch/out 必须尚不存在，且与 source/ref/baseline-src 无祖先关系。REF 只读，含 node-vendor/controller-vendor。

`controller-vendor-old/` = 旧代源树（upg / ctl）的 controller vendor；当本树 controller/go.mod 与旧树不同时必需。该目录不存在时沿用 `controller-vendor/`，不一致由 Go 构建直接报错。

需要 Linux root、Go/cgo/C、clang BPF/llvm、make、iproute2/tc、ethtool、unshare/mount/stat、taskset、ps、patch、Python。两代 ELF 用逐字相同 Makefile、make -B、同一 node-vendor REF；两代 agent 都 CGO_ENABLED=0、go build -o <binary> .，GOPROXY=off、GOTOOLCHAIN=local、GOFLAGS=-mod=vendor。构建日志与 ELF SHA 留证。controller/api.test 用 cgo；缺失 web/dist/index.html 由 scratch 内 Go overlay 提供 headless HTML，源树不改，不构建前端。

默认 inb,both,hidx,upg,ctl；inb/both 并行，二者结束后依次 hidx/upg/ctl。--only 是诊断范围，不能以缩减集合通过正常轮。各场景私有 netns/bpffs/账户状态；lo 用 10.77.0.1/32，veth 无协议栈地址，IPv6协议栈关闭。ifindex 2–5，hidx 40–43；generic、pinning=require，只创建装置 veth。

## 格、连续流与机器记录

inb/both 经控制器创建六条规则（含 R-crl：10.10.7.0/24、UDP、rate_limit=5）与 W-5；P0 读回规则/白名单/health/XDP。P2 commit、P3 atomic、P4 重启后 P4c 保持原覆盖。

| 集合 | 每场景 | 合计 |
|---|---:|---:|
| inb/both：P1 22，P2/P3/P4c 各24，P4a 6 | 100 | 200 |
| 计数：P1 8，P2/P3/P4c 各10 | 38 | 76 |
| hidx P1h：F-miss4/F-miss6/F-arp 双向 | 6 | 6 |
| upg P1u-before/after：F-ex/F-miss4/F-arp 双向 | 12 | 12 |
| ctl 同 upg 的格 | 12 | 另计12 |

正常功能集合218格，含ctl实际230格。F-crl/F-rl各50帧，过滤方向收1…49，非过滤方向50，其余20帧；限速格前各等2.5秒，突发≤200ms。rate_limited_packets 期望累加两格的50−收到。核发送、唯一序号、字节、错误和重复；仅容许尾部零填充。

P3 后先开 S（独立阶段标记、F-miss4、WAN→LAN、递增序号、目标1000pps），再SIGTERM、等退出、读两口PROMISC/XDP、跑P4a（S照跑）、起新agent。T为本次首次healthy观测；hidx不起控制器，T/P0接受首次HTTP200含degraded。发送至T+2.1秒，核末帧严格晚于T+2秒，接收另收尾1秒。hidx也跑S；upg旧→新，ctl旧→旧。

S独立接收socket，P4a另有socket，内核各给副本。PACKET_STATISTICS完整结构只在开流前清零、收尾后读；tp_drops=0、读失败为红。接收超时50ms，空读也计迭代。有效性①发间隔≤20ms；②[SIGTERM,T]发送量≥窗口ms×0.5；③接收覆盖首帧至末帧+1秒，且前/后收帧均在；④仅ctl要求每个丢失序号发于窗口内；⑤socket无drops、接收迭代间隔≤100ms。发送>0、失败0、首帧早于SIGTERM、收发启动记录、字节完整全部必需。

保留 FFCELL/FFCOUNT/FFSHAPE/FFSELECTOR/FFPOST/FFALIVE/FFEND。新增 FFSTREAM 含全部数量、时刻、覆盖、定位、drops、迭代间隔、①–⑤布尔；FFPOSTTERM 是停机后两口读回；FFHIDX 是 HIDX_FORWARD 或 N3 的 HIDX_START_FAIL。监督进程输出 FFMOUNT/FFSECRET/FFEXIT。runner 独立复算原始读数与完整集合，矛盾 pass/expect/validity 为红；格失败 Errorf 收齐，装置前置失败 Fatalf，不以RC代门。

正常轮 FF_RESULTS expected=218 present=218 pass=218。装置可判G1格/G2计数/G3四个S零丢失与停机状态/G4 ctl丢失>0/G5并行UTC/G9 envelope/G10秘密与隔离；G3/G4还须汇总四轮。G6需十二份变异。G7/G8/G11打印PENDING，交主会话执行。

## 变异与自检

```sh
python3 "$KIT/selfcheck.py" --source "$SOURCE" --patch-out "$KIT/mutations" --frames --oracles
python3 "$KIT/runner.py" --source "$SOURCE" --baseline "$BASELINE" \
  --baseline-src "$BEFORE" --scratch <work-root>/ffn-M8-scratch \
  --out <work-root>/ffn-M8-results --mutation M8
```

补丁全部对本刀源重生成，函数/区段锚点由 /usr/bin/grep 核恰1，M8替换恰3，N3两定义分别核。仅在scratch打补丁，强制重编ELF，改C对应ELF SHA必须变化；finally恢复全部目标源并核SHA。

| 变异 | 场景 | 必红 |
|---|---|---|
| M1 | inb | P1 LAN→WAN F-map6 |
| M3 | inb,both | 两场景P1 WAN→LAN F-miss4 |
| M4 | inb | P1双向F-ex |
| M5 | both | P2 WAN→LAN F-miss4 |
| M6 | inb | P1 LAN→WAN F-ex |
| M7 | both | P1 WAN→LAN F-miss4 |
| M8 | inb | P1 WAN→LAN F-crl |
| N2 | inb | SIGTERM后两口PROMISC=on |
| N3 | hidx | HIDX_START_FAIL：≤30秒非0退出、两次Load成功见证、devmap写入E2BIG、未响应health |
| N4 | Go测试 | TestFFDevmapReconcile |
| N5 | Go测试 | TestFFStartupOrder传统分支 |
| N6 | upg+Go测试 | TestFFStartupOrder |

允许集合逐字对照见DELIVERY。M8仅各阶段WAN→LAN F-crl与rate_limited_packets；N2仅postterm promisc；N3允许hidx格缺失/失败；N4/N5仅点名测试；N6额外允许upg S丢失。M6补LAN→WAN F-crl及R-crl计数，M5/M7正期望格含F-crl。S例外：M3/M7仅loss/pre/post，M5仅loss/pre（post须恢复），N6仅loss；①②⑤、收发错误、字节、覆盖不豁免，④只用于ctl。

N4/N5/N6在变异源实际执行 go test -json -tags integration -count=1 -run '^<点名>$' .；同包同名必须有run和fail事件，无其他测试fail/skip。编译失败、仅包fail、缺事件不算击杀。打印 MUTATION <名> must_red_hit=a/b outside_allowed=k verdict=RED_OK|FAIL；须完整集合、必红全命中、全部失败⊆允许集合、装置门成立、还原SHA相等。

selfcheck抽取实际Go纯帧/接收校验函数，核12帧、未知序号/短标记/改字节等旧负控；oracle核缺格、重复、零发送、漏必红、集合外失败、假pass/expect、编译失败。四条S合成负控：中段停发、接收提前停、全部未收、中段接收停摆/队列丢包但两端成功，均须红。synthetic=1不是lab证据。

## 外部门与边界

门七新增 node/agent/bpf TestFFGate7（linux && integration）。同lab/clang/探针：FF_BEFORE_GATE_ELF/FF_BEFORE_MAIN_ELF为d39805f ELF，XDROP_GATE_ELF/XDROP_BPF_ELF为本刀ELF；FF_BEFORE_SOURCE=d39805f4910e4245004cf1157056c0ad749ef379，FF_AFTER_SOURCE为本刀源身份含diff摘要。执行 go test -tags integration ./bpf -run '^TestFFGate7$' -count=1 -v；同句日志两ELF SHA/源身份/指令/栈，gate≤500000、Δ≤20000、栈Δ≤64，main≤1000000并记Δ；不复用TestAFGate7标签。

G8 lab范围：node/agent根包、bpf(private+host)、api/eval/sync/abi/cidr/ifmgr/config，同机d39805f事件比；FAIL=0，pass集含基线减旧ZerosFFSlots，SKIP集相等。未变异源必须PASS无SKIP：根包 TestFFStartupOrder/TestClearFastForwardSlots/TestFFDevmapReconcile/TestRestoreSkipsAttached；api TestInitDynamicConfig_PreservesFFSlots。

ABI三测 TestELFMapSizesMatchGoStructs/TestELFHasExpectedPrograms/TestB1LogicalStateABI 交主会话lab；eval三组 TestS2aParityCallerIdentity/TestS2aSourceRejections/TestS2bCompetition 交主会话沙箱外；断言不改、必须PASS、同机基线核。本机不记通过。controller全量单测/race亦交主会话；Linux controller编译需cgo。

## 宿主、秘密、清理

bpffs核st_dev不同且bpf_fs，Go核自身/agent mount namespace。envelope核宿主link/XDP、tc、bpffs、netns、/opt/xdrop、存活daemon，前后全等、残留零。inb/both固定可用CPU第一/第二项；实际XDP处理CPU/定时精度由lab核。

node key和四类账户秘密仅在scratch私有文件产生；发布前扫描raw日志、库/WAL/响应覆盖与已知阳性，匹配0才发布，不发布阳性内容。嵌套finally清理进程/私有挂载/owned netns、恢复变异、核envelope、删scratch；SIGKILL/断电按owned-netns.txt定点恢复。dry-run不建网络、不挂载、不启动agent。
