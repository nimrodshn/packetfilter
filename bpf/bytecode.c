#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/bpf.h>
#include <linux/netdevice.h>
#include <net/ethernet.h>
#include <linux/version.h>
#include "bpf_helpers.h"

// source_ip_blacklist contains the IPv6 addresses to filter.
struct bpf_map_def SEC("maps/source_ip_blacklist") source_ip_blacklist = {
    .type        = BPF_MAP_TYPE_LPM_TRIE,
    .key_size    = sizeof(struct bpf_lpm_trie_key) + sizeof(__u32) * 4,
    .value_size  = sizeof(uint32_t),
    .max_entries = 10000,
    .map_flags   = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps/events") events = {
    .type        = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u32),
    .max_entries = 1024,
};

// ipv4_header is the subset of the ipv4 header which will get sent to 
// the user space.
struct ipv4_header {
    unsigned int src;
    unsigned int dst;
};

const int IPV6_ALEN = 16;

// ipv6_header is the header information sent to the user space.
struct ipv6_header {
    struct in6_addr src;
    struct in6_addr dst;
};

// ip_header is a union containing either an ipv6 or ipv4 header.
union ip_header {
    struct ipv4_header ipv4;
    struct ipv6_header ipv6;
};

// eth_packet is the Ethernet packet sent to the user space.
struct __attribute__((__packed__)) eth_packet {
    unsigned char h_dest[ETH_ALEN];
    unsigned char h_source[ETH_ALEN];
    u_int16_t h_protocol;
    union ip_header ipheader;
};

SEC("xdp")
int _xdp_ip_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    // check packet size
    if ((void*)eth + sizeof(*eth) > data_end) {
        return XDP_PASS;
    }

    // check packet size
    struct iphdr *ip = data + sizeof(*eth);
    if ((void*)ip + sizeof(*ip) > data_end) {
        return XDP_PASS;
    }

    struct eth_packet packet = {
        .h_protocol = eth->h_proto,
    };

    for (int i=0; i<ETH_ALEN; i++) {
        packet.h_source[i] = eth->h_source[i];
        packet.h_dest[i] = eth->h_dest[i];
    };

    if (packet.h_protocol == ntohs(ETH_P_IP)) {
        struct iphdr *ip = data + sizeof(*eth);
        if ((void*)ip + sizeof(*ip) <= data_end) {
            struct ipv4_header iphdr = {
                .src = ip->saddr,
                .dst = ip->daddr
            };
            packet.ipheader.ipv4 = iphdr;
        }
    }

    if (packet.h_protocol == ntohs(ETH_P_IPV6)) {
        struct ipv6hdr *ip = data + sizeof(*eth);
        if ((void*)ip + sizeof(*ip) <= data_end) { 
            // lookup struct is used for matching against blacklist.
            struct  __attribute__((__packed__)) key {
                struct bpf_lpm_trie_key base;
                __uint128_t data;
            } lookup;

            lookup.base.prefixlen = 128;
            memcpy(&lookup.data, &ip->saddr, sizeof(__uint128_t));
            uint32_t *val = bpf_map_lookup_elem(&source_ip_blacklist, &lookup);
            if (val != NULL) {
                bpf_printk("Found a match for packet blacklist, dropping..\n");
                return XDP_DROP;
            }

            struct ipv6_header iphdr;
            // iphdr struct is used for tracing
            memcpy(&iphdr.src, &ip->saddr, sizeof(ip->saddr));
            memcpy(&iphdr.dst, &ip->daddr, sizeof(ip->saddr));

            packet.ipheader.ipv6 = iphdr;
        }
    }

    // send the ethernet packet to the userspace program.
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &packet, sizeof(packet));
    return XDP_PASS;
}


char _license[] SEC("license") = "GPL";

