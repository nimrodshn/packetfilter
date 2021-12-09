#include <linux/if_ether.h>
#include <linux/ip.h>
#include <netinet/in.h>
#include <linux/bpf.h>
#include <linux/netdevice.h>
#include <net/ethernet.h>
#include <linux/version.h>
#include "bpf_helpers.h"

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

// ipv6hdr is the entire header for
// the ipv6 datagram - of which we only need the source and destination.
struct ipv6hdr {
    uint32_t 	vtc_flow;
    uint16_t 	payload_len;
    uint8_t 	proto;
    uint8_t 	hop_limits;
    uint8_t 	src_addr [IPV6_ALEN];
    uint8_t 	dst_addr [IPV6_ALEN];
};

// ipv6_header is the header information sent to the user space.
struct ipv6_header {
    uint8_t 	src_addr [IPV6_ALEN];
    uint8_t 	dst_addr [IPV6_ALEN];
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
    bpf_printk("got a packet\n");     
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

    if (packet.h_protocol == htons(ETH_P_IP)) {
        struct iphdr *ip = data + sizeof(*eth);
        if ((void*)ip + sizeof(*ip) <= data_end) {
            struct ipv4_header iphdr = {
                .src = ip->saddr,
                .dst = ip->daddr
            };
            packet.ipheader.ipv4 = iphdr;
        }
    }

    if (packet.h_protocol == htons(ETH_P_IPV6)) {
        struct ipv6hdr *ip = data + sizeof(*eth);
        if ((void*)ip + sizeof(*ip) <= data_end) { 
            struct ipv6_header iphdr;
            for (int i=0; i<IPV6_ALEN; i++) {
                iphdr.src_addr[i] = ip->src_addr[i];
                iphdr.dst_addr[i] = ip->dst_addr[i];
            };
            packet.ipheader.ipv6 = iphdr;
        }
    }

    // send the ethernet packet to the userspace program.
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &packet, sizeof(packet));
    return XDP_PASS;
}


char _license[] SEC("license") = "GPL";

