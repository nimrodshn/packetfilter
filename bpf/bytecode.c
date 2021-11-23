#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <uapi/linux/bpf.h>
#include <linux/netdevice.h>
#include <linux/version.h>
#include "bpf_helpers.h"

struct bpf_map_def SEC("maps/events") EVENTS = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u32),
    .max_entries = 1,
};

SEC("xdp")
int _xdp_ip_filter(struct xdp_md *ctx) {
    bpf_printk("got a packet\n");     
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    // check packet size
    if (eth + 1 > data_end) {
        return XDP_PASS;
    }

    // get the source address of the packet
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (iph + 1 > data_end) {
        return XDP_PASS;
    }

    __u32 ip_src = iph->saddr;
    bpf_printk("source ip address is %u\n", ip_src);

    // key of the maps
    __u32 key = 0;

    bpf_printk("starting xdp ip filter\n");
    // send the ip to the userspace program.
    bpf_map_update_elem(&EVENTS, &key, &ip_src, BPF_ANY);
    return XDP_PASS;
}


char _license[] SEC("license") = "GPL";

