// ⚠️ 本文件由 node/bpf/tools/extract_combo_masks.py 生成，⛔ 不要手改。
// 掩码从 xdrop_main.c 的展开代码机械提取（M1-b：不照注释转录）。
// pre-M1 四函数有序结果冻结于 tools/combo_masks_pre_m1.json。
// 重新生成：python3 node/bpf/tools/extract_combo_masks.py --emit-c

_Static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__,
               "combo whole-word masks require little-endian byte order");

#define COMBO_VALID_BITMAP 0x00000003FFF7FFFFULL

#define CM_SRC_IP (1u << 0)
#define CM_DST_IP (1u << 1)
#define CM_SRC_PORT (1u << 2)
#define CM_DST_PORT (1u << 3)
#define CM_PROTOCOL (1u << 4)

// 索引 = combo 编号。表长 34，与 COMBO_MAX 对齐。
static const __u8 combo_field_mask[] = {
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
    [19] = 0,  // ⛔ 历史空洞：无原始块。位图第 19 位永不置位 ⇒ 永不被试探。
           //    若该保证失效，全零掩码会构造出一个五字段全通配的 key。
    [20] = CM_DST_IP | CM_DST_PORT | CM_PROTOCOL,  // COMBO_DST_IP_DST_PORT_PROTO
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
    [32] = CM_DST_IP | CM_SRC_PORT | CM_DST_PORT | CM_PROTOCOL,  // COMBO_DST_IP_PORTS_PROTO
    [33] = CM_SRC_IP | CM_DST_IP | CM_SRC_PORT | CM_DST_PORT,  // COMBO_ALL_EXCEPT_PROTO
};
