package eval

// Contract is selected explicitly by the caller; no input-shape inference.
type Contract string

const (
	PreS2a Contract = "pre-s2a"
	S2a    Contract = "s2a"
)

// Frozen F-067 C field incidence masks, also independently used by S1-5 AUTH.
// 126b4cb retains this historical table; S2a projects only slots 20 and 32.
var historicalFields = [...]uint64{0x0000000261E66F01, 0x00000003E670341F, 0x00000003FF868043, 0x0000000399F15887, 0x000000015555E22F}
var historicalRoster = map[string]int{
	"COMBO_EXACT_5TUPLE":              0,
	"COMBO_WILDCARD_SRC_IP":           1,
	"COMBO_WILDCARD_SRC_IP_PORT":      2,
	"COMBO_DST_IP_PROTO":              3,
	"COMBO_DST_IP_ONLY":               4,
	"COMBO_PROTO_ONLY":                5,
	"COMBO_SRC_PORT_ONLY":             6,
	"COMBO_DST_PORT_ONLY":             7,
	"COMBO_SRC_IP_ONLY":               8,
	"COMBO_SRC_IP_PROTO":              9,
	"COMBO_SRC_DST_IP":                10,
	"COMBO_SRC_IP_DST_PORT":           11,
	"COMBO_DST_IP_DST_PORT":           12,
	"COMBO_SRC_DST_IP_PROTO":          13,
	"COMBO_SRC_IP_DST_PORT_PROTO":     14,
	"COMBO_SRC_PORT_PROTO":            15,
	"COMBO_DST_PORT_PROTO":            16,
	"COMBO_SRC_IP_SRC_PORT":           17,
	"COMBO_SRC_IP_SRC_PORT_PROTO":     18,
	"COMBO_DST_IP_DST_PORT_PROTO":     20,
	"COMBO_SRC_DST_IP_DST_PORT":       21,
	"COMBO_SRC_DST_IP_DST_PORT_PROTO": 22,
	"COMBO_SRC_IP_PORTS":              23,
	"COMBO_SRC_IP_PORTS_PROTO":        24,
	"COMBO_DST_IP_SRC_PORT":           25,
	"COMBO_DST_IP_SRC_PORT_PROTO":     26,
	"COMBO_PORTS_ONLY":                27,
	"COMBO_PORTS_PROTO":               28,
	"COMBO_SRC_DST_IP_SRC_PORT":       29,
	"COMBO_SRC_DST_IP_SRC_PORT_PROTO": 30,
	"COMBO_DST_IP_PORTS":              31,
	"COMBO_DST_IP_PORTS_PROTO":        32,
	"COMBO_ALL_EXCEPT_PROTO":          33,
}

// Exact input bytes certified for each contract. A copied tree is allowed only
// with explicit root, real-path containment, and these same source identities.
var contractHashes = map[Contract]map[string]string{
	PreS2a: {
		"node/bpf/xdrop.h":       "5beb7825c01f141f054981cbd810cb08b7ca9721765219e447583ecca1cb62cf",
		"node/bpf/combo_masks.h": "9cfa30722183816b4cc860b7822827a34e2da2c1f8daf17a167de95997e1de3c",
		"node/bpf/xdrop_gate.c":  "a15a6d1081d82c7d815d18a0918198876240d69be0ba843e67c4f28ac5f58199",
	},
	S2a: {
		"node/bpf/xdrop.h":       "d1dd8269ab0dfb0923e565fe075f830f652e150b0e741f9869d1231d967833d2",
		"node/bpf/combo_masks.h": "0246f4655ea2cad3adfa958112a6db800d05705064efc634a5360796e92318f5",
		"node/bpf/xdrop_gate.c":  "a15a6d1081d82c7d815d18a0918198876240d69be0ba843e67c4f28ac5f58199",
	},
}

func (c Contract) active(i int) bool {
	return i >= 0 && i < 34 && i != 19 && (c == PreS2a || c == S2a && i != 20 && i != 32)
}
func (c Contract) bitmap() uint64 {
	var b uint64
	for i := 0; i < 34; i++ {
		if c.active(i) {
			b |= 1 << i
		}
	}
	return b
}
func (c Contract) mask(i int) Mask {
	if !c.active(i) {
		return 0
	}
	var m Mask
	for j, field := range historicalFields {
		if field&(1<<i) != 0 {
			m |= 1 << j
		}
	}
	return m
}
