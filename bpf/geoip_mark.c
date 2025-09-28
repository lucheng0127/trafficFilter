//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>

// Key for LPM trie
struct lpm_key_v4 {
    __u32 prefixlen;
    __u32 addr;
};

// Map: CN网段前缀
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(max_entries, 200000);
    __type(key, struct lpm_key_v4);
    __type(value, __u8);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} cn_prefixes SEC(".maps");

// Map: fwmark配置
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} fwmark_conf SEC(".maps");

SEC("tc")
int geoip_mark(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void*)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *iph = (void *)(eth + 1);
    if ((void*)(iph + 1) > data_end)
        return TC_ACT_OK;

    struct lpm_key_v4 key = {};
    key.prefixlen = 32; // LPM trie会匹配最长前缀
    key.addr = iph->daddr;

    __u8 *val = bpf_map_lookup_elem(&cn_prefixes, &key);
    if (!val) {
        __u32 idx = 0;
        __u32 *mark = bpf_map_lookup_elem(&fwmark_conf, &idx);
        if (mark) {
            skb->mark = *mark;
        }
    }

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
