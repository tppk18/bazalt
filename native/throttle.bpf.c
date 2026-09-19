#define SEC(NAME) __attribute__((section(NAME), used))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) __typeof__(val) *name

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

#define BPF_MAP_TYPE_LPM_TRIE 11
#define BPF_F_NO_PREALLOC 1
#define XDP_DROP 1
#define XDP_PASS 2
#define ETH_P_IP 0x0800
#define ETH_P_8021Q 0x8100
#define ETH_P_8021AD 0x88A8

struct xdp_md {
    __u32 data;
    __u32 data_end;
    __u32 data_meta;
    __u32 ingress_ifindex;
    __u32 rx_queue_index;
    __u32 egress_ifindex;
};

struct throttle_key {
    __u32 prefixlen;
    __u32 addr;
};

struct throttle_value {
    __u32 drop_percent;
    __u32 reserved;
    __u64 expires_at_ns;
    __u64 seen_packets;
    __u64 seen_bytes;
    __u64 dropped_packets;
    __u64 dropped_bytes;
};

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 16384);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, struct throttle_key);
    __type(value, struct throttle_value);
} throttle_rules SEC(".maps");

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static __u32 (*bpf_get_prandom_u32)(void) = (void *)7;

static __inline int is_vlan(__u16 proto) {
    return proto == ETH_P_8021Q || proto == ETH_P_8021AD;
}

static __inline __u16 read_be16(const __u8 *p) {
    return ((__u16)p[0] << 8) | (__u16)p[1];
}

SEC("xdp")
int bazalt_throttle(struct xdp_md *ctx) {
    __u8 *data = (__u8 *)(long)ctx->data;
    __u8 *data_end = (__u8 *)(long)ctx->data_end;
    if (data + 14 > data_end)
        return XDP_PASS;

    __u16 proto = read_be16(data + 12);
    __u32 offset = 14;

    if (is_vlan(proto)) {
        if (data + offset + 4 > data_end)
            return XDP_PASS;
        proto = read_be16(data + offset + 2);
        offset += 4;
    }
    if (is_vlan(proto)) {
        if (data + offset + 4 > data_end)
            return XDP_PASS;
        proto = read_be16(data + offset + 2);
        offset += 4;
    }
    if (proto != ETH_P_IP)
        return XDP_PASS;

    if (data + offset + 20 > data_end)
        return XDP_PASS;
    __u8 version_ihl = data[offset];
    if ((version_ihl >> 4) != 4 || (version_ihl & 0x0f) < 5)
        return XDP_PASS;

    struct throttle_key key = {
        .prefixlen = 32,
        .addr = 0,
    };
    __u8 *addr = (__u8 *)&key.addr;
    addr[0] = data[offset + 12];
    addr[1] = data[offset + 13];
    addr[2] = data[offset + 14];
    addr[3] = data[offset + 15];

    struct throttle_value *rule = bpf_map_lookup_elem(&throttle_rules, &key);
    if (!rule || rule->drop_percent == 0)
        return XDP_PASS;
    if (rule->expires_at_ns != 0 && bpf_ktime_get_ns() >= rule->expires_at_ns)
        return XDP_PASS;

    __u64 wire_len = (__u64)(data_end - data);
    __sync_fetch_and_add(&rule->seen_packets, 1);
    __sync_fetch_and_add(&rule->seen_bytes, wire_len);

    __u32 percent = rule->drop_percent;
    int drop = percent >= 100;
    if (!drop) {
        __u32 sample = bpf_get_prandom_u32();
        __u64 threshold = ((__u64)percent << 32) / 100;
        drop = (__u64)sample < threshold;
    }
    if (!drop)
        return XDP_PASS;

    __sync_fetch_and_add(&rule->dropped_packets, 1);
    __sync_fetch_and_add(&rule->dropped_bytes, wire_len);
    return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
