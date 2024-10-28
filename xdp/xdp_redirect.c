#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// 定义常量
#define SRC_IP_ENO1 0xAC142C51    // 172.20.44.81
#define SRC_PORT_C 3333
#define SRC_PORT_D 6666

#define DST_IP_ENO1 0xAC142C65    // 172.20.44.101
#define DST_PORT_A 1188
#define DST_PORT_B 8811

#define ENO1_IFINDEX 2    // 172.20.44.81 的网卡名名称是 eno1，索引是 2

// 从 172.20.44.81:3333 到 172.20.44.81:1188 的数据包修改为 从 172.20.44.81:6666 到 172.20.44.101:8811
// 从 172.20.44.101:8811 到 172.20.44.81:6666 的数据包修改为 从 172.20.44.81:1188 到 172.20.44.81:3333

static __always_inline void update_mac(struct ethhdr *eth, __u8 *src_mac, __u8 *dst_mac)
{
    __builtin_memcpy(eth->h_source, src_mac, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, dst_mac, ETH_ALEN);
}

static __always_inline __u16 ip_checksum(struct iphdr *ip, int ip_size)
{
    unsigned long csum = 0;
    csum = bpf_csum_diff(0, 0, (void *)ip, ip_size, 0);
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum = (csum & 0xFFFF) + (csum >> 16);
    return ~csum;
}

static __always_inline __u16 tcp_checksum(struct tcphdr *tcp, int tcp_size)
{
    unsigned long csum = 0;
    csum = bpf_csum_diff(0, 0, (void *)tcp, tcp_size, 0);
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum = (csum & 0xFFFF) + (csum >> 16);
    return ~csum;
}

SEC("xdp_prog")
int xdp_redirect(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
    {
        return XDP_PASS;
    }

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end || ip->protocol != IPPROTO_TCP)
    {
        return XDP_PASS;
    }

    struct tcphdr *tcp = (void *)ip + sizeof(*ip);
    if ((void *)tcp + sizeof(*tcp) > data_end)
    {
        return XDP_PASS;
    }

    bpf_printk("Received packet: src port=%d, dst port=%d\n", bpf_ntohs(tcp->source), bpf_ntohs(tcp->dest));

    // 从 172.20.44.81:3333 到 172.20.44.81:1188 的数据包修改为 从 172.20.44.81:6666 到 172.20.44.101:8811
    if (ip->saddr == bpf_htonl(SRC_IP_ENO1) && tcp->source == bpf_htons(SRC_PORT_C) && ip->daddr == bpf_htonl(SRC_IP_ENO1) && tcp->dest == bpf_htons(DST_PORT_A))
    {
        // 修改 MAC 地址
        __u8 eno1_mac[ETH_ALEN] = {0x58, 0x11, 0x22, 0xc3, 0x23, 0xe6};
        __u8 other_mac[ETH_ALEN] = {0xd0, 0x94, 0x66, 0xf1, 0x96, 0xae};
        update_mac(eth, eno1_mac, other_mac);

        ip->saddr = bpf_htonl(SRC_IP_ENO1);
        ip->daddr = bpf_htonl(DST_IP_ENO1);

        tcp->source = bpf_htons(SRC_PORT_D);
        tcp->dest = bpf_htons(DST_PORT_B);

        tcp->check = 0;
        ip->check = 0;
        tcp->check = bpf_csum_diff(0, 0, (void *)tcp, sizeof(struct tcphdr), tcp->check);
        ip->check = bpf_csum_diff(0, 0, (void *)ip, sizeof(struct iphdr), ip->check);

        bpf_printk("Redirecting eno1 to other: src port=%d, dst port=%d\n", bpf_ntohs(tcp->source), bpf_ntohs(tcp->dest));
        return bpf_redirect(ENO1_IFINDEX, 0);
        // return XDP_PASS;
    }
    // 从 172.20.44.101:8811 到 172.20.44.81:6666 的数据包修改为 从 172.20.44.81:1188 到 172.20.44.81:3333
    else if (ip->saddr == bpf_htonl(DST_IP_ENO1) && tcp->source == bpf_htons(DST_PORT_B) && ip->daddr == bpf_htonl(SRC_IP_ENO1) && tcp->dest == bpf_htons(SRC_PORT_D))
    {
        // 修改 MAC 地址
        __u8 eno1_mac[ETH_ALEN] = {0x58, 0x11, 0x22, 0xc3, 0x23, 0xe6};
        __u8 other_mac[ETH_ALEN] = {0xd0, 0x94, 0x66, 0xf1, 0x96, 0xae};

        update_mac(eth, eno1_mac, eno1_mac);

        ip->saddr = bpf_htonl(SRC_IP_ENO1);
        ip->daddr = bpf_htonl(SRC_IP_ENO1);

        tcp->source = bpf_htons(DST_PORT_A);
        tcp->dest = bpf_htons(SRC_PORT_C);

        tcp->check = 0;
        ip->check = 0;
        tcp->check = bpf_csum_diff(0, 0, (void *)tcp, sizeof(struct tcphdr), tcp->check);
        ip->check = bpf_csum_diff(0, 0, (void *)ip, sizeof(struct iphdr), ip->check);

        bpf_printk("Redirecting other to eno1: src port=%d, dst port=%d\n", bpf_ntohs(tcp->source), bpf_ntohs(tcp->dest));
        return bpf_redirect(ENO1_IFINDEX, 0);
        // return XDP_PASS;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";