// ⚠️ 本文件由 node/bpf/tools/extract_combo_masks.py 生成，⛔ 不要手改。
// 掩码从 xdrop_main.c 的展开代码机械提取（M1-b：不照注释转录）。
// pre-M1 四函数有序结果冻结于 tools/combo_masks_pre_m1.json。
// 重新生成：python3 node/bpf/tools/extract_combo_masks.py --emit-c

_Static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__,
               "combo whole-word masks require little-endian byte order");

#define COMBO_VALID_BITMAP 0x00000002FFE7FFFFULL

#define CM_SRC_IP (1u << 0)
#define CM_DST_IP (1u << 1)
#define CM_SRC_PORT (1u << 2)
#define CM_DST_PORT (1u << 3)
#define CM_PROTOCOL (1u << 4)

// 索引 = combo 编号。有效槽 0..33（COMBO_MAX=34）。
// 表按 COMBO_TABLE_SLOTS 定长，⛔ 不是按 COMBO_MAX：combo 号取自一次 __u8
// 载入，verifier 只能断定它 <= 255。表做满 256 槽，combo_field_mask[b] 就
// 恒在界内，⛔ 不再依赖「b <= 33 那条检查能不能在优化后活下来」。
// 多出的槽恒为 0 = 不定位任何字段，与历史空洞同义。
#define COMBO_TABLE_SLOTS 256
static const __u8 combo_field_mask[COMBO_TABLE_SLOTS] = {
    [0] = CM_SRC_IP | CM_DST_IP | CM_SRC_PORT | CM_DST_PORT | CM_PROTOCOL,  // COMBO_EXACT_5TUPLE
    [1] = CM_DST_IP | CM_SRC_PORT | CM_DST_PORT | CM_PROTOCOL,  // COMBO_WILDCARD_SRC_IP
    [2] = CM_DST_IP | CM_DST_PORT | CM_PROTOCOL,  // COMBO_WILDCARD_SRC_IP_PORT
    [3] = CM_DST_IP | CM_PROTOCOL,  // COMBO_DST_IP_PROTO
    [4] = CM_DST_IP,  // COMBO_DST_IP_ONLY
    [5] = CM_PROTOCOL,  // COMBO_PROTO_ONLY
    [6] = CM_SRC_PORT,  // COMBO_SRC_PORT_ONLY
    [7] = CM_DST_PORT,  // COMBO_DST_PORT_ONLY
    [8] = CM_SRC_IP,  // COMBO_SRC_IP_ONLY
    [9] = CM_SRC_IP | CM_PROTOCOL,  // COMBO_SRC_IP_PROTO
    [10] = CM_SRC_IP | CM_DST_IP,  // COMBO_SRC_DST_IP
    [11] = CM_SRC_IP | CM_DST_PORT,  // COMBO_SRC_IP_DST_PORT
    [12] = CM_DST_IP | CM_DST_PORT,  // COMBO_DST_IP_DST_PORT
    [13] = CM_SRC_IP | CM_DST_IP | CM_PROTOCOL,  // COMBO_SRC_DST_IP_PROTO
    [14] = CM_SRC_IP | CM_DST_PORT | CM_PROTOCOL,  // COMBO_SRC_IP_DST_PORT_PROTO
    [15] = CM_SRC_PORT | CM_PROTOCOL,  // COMBO_SRC_PORT_PROTO
    [16] = CM_DST_PORT | CM_PROTOCOL,  // COMBO_DST_PORT_PROTO
    [17] = CM_SRC_IP | CM_SRC_PORT,  // COMBO_SRC_IP_SRC_PORT
    [18] = CM_SRC_IP | CM_SRC_PORT | CM_PROTOCOL,  // COMBO_SRC_IP_SRC_PORT_PROTO
    [19] = 0,  // 历史空洞或退役槽；构造 key 前由 COMBO_VALID_BITMAP 过滤。
    [20] = 0,  // 历史空洞或退役槽；构造 key 前由 COMBO_VALID_BITMAP 过滤。
    [21] = CM_SRC_IP | CM_DST_IP | CM_DST_PORT,  // COMBO_SRC_DST_IP_DST_PORT
    [22] = CM_SRC_IP | CM_DST_IP | CM_DST_PORT | CM_PROTOCOL,  // COMBO_SRC_DST_IP_DST_PORT_PROTO
    [23] = CM_SRC_IP | CM_SRC_PORT | CM_DST_PORT,  // COMBO_SRC_IP_PORTS
    [24] = CM_SRC_IP | CM_SRC_PORT | CM_DST_PORT | CM_PROTOCOL,  // COMBO_SRC_IP_PORTS_PROTO
    [25] = CM_DST_IP | CM_SRC_PORT,  // COMBO_DST_IP_SRC_PORT
    [26] = CM_DST_IP | CM_SRC_PORT | CM_PROTOCOL,  // COMBO_DST_IP_SRC_PORT_PROTO
    [27] = CM_SRC_PORT | CM_DST_PORT,  // COMBO_PORTS_ONLY
    [28] = CM_SRC_PORT | CM_DST_PORT | CM_PROTOCOL,  // COMBO_PORTS_PROTO
    [29] = CM_SRC_IP | CM_DST_IP | CM_SRC_PORT,  // COMBO_SRC_DST_IP_SRC_PORT
    [30] = CM_SRC_IP | CM_DST_IP | CM_SRC_PORT | CM_PROTOCOL,  // COMBO_SRC_DST_IP_SRC_PORT_PROTO
    [31] = CM_DST_IP | CM_SRC_PORT | CM_DST_PORT,  // COMBO_DST_IP_PORTS
    [32] = 0,  // 历史空洞或退役槽；构造 key 前由 COMBO_VALID_BITMAP 过滤。
    [33] = CM_SRC_IP | CM_DST_IP | CM_SRC_PORT | CM_DST_PORT,  // COMBO_ALL_EXCEPT_PROTO
};

// B0: descending field population; stable ID ascending breaks ties.
static const __u8 combo_order[] = {
    0, 1, 22, 24, 30, 33, 2, 13, 14, 18, 21, 23, 26, 28, 29, 31, 3, 9, 10, 11, 12, 15, 16, 17, 25, 27, 4, 5, 6, 7, 8,
};
#define COMBO_ORDER_LEN (sizeof(combo_order) / sizeof(combo_order[0]))
_Static_assert(sizeof(combo_field_mask) == COMBO_TABLE_SLOTS, "mask slots must keep stable IDs");
_Static_assert(COMBO_MAX <= COMBO_TABLE_SLOTS, "every live combo id must own a slot");
_Static_assert(COMBO_TABLE_SLOTS == 256, "slots must cover the full __u8 range the verifier sees");
_Static_assert(sizeof(combo_field_mask[0]) == 1, "mask elements must remain bytes");
_Static_assert(0 < COMBO_ORDER_LEN && COMBO_ORDER_LEN <= COMBO_MAX && COMBO_MAX <= 64,
               "order/slot/shift bounds must hold");
