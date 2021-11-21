#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include "bpf_helpers.h"

// A macro wrapping of bpf_trace_printk
#define bpf_printk(fmt, ...)				\
({							\
	BPF_PRINTK_FMT_MOD char ____fmt[] = fmt;	\
	bpf_trace_printk(____fmt, sizeof(____fmt),	\
			 ##__VA_ARGS__);		\
})


struct bpf_map_def SEC("maps") ip_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(__u32),
	.value_size  = sizeof(__u32),
	.max_entries = 1,
};

SEC("xdp")
int _xdp_ip_filter(struct xdp_md *ctx) {
    // // key of the maps
    // __u32 key = 0;
    // // the ip to filter
    // __u32 *ip;

    // bpf_printk("starting xdp ip filter\n");
    // // get the ip to filter from the ip_filtered map
    // ip = bpf_map_lookup_elem(&ip_map, &key);
    // if (!ip){
    //     return XDP_PASS;
    // }
    // bpf_printk("the ip address to filter is %u\n", ip);
    return XDP_PASS;
}


char _license[] SEC("license") = "GPL";

