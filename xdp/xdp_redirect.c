#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// 定义常量
#define SRC_IP 0xAC143E63    // // 172.20.62.99
#define SRC_PORT 3333

#define PROXY_IP 0xAC142C51    // 172.20.44.81
#define PROXY_PORT 6666

#define DST_IP 0xAC142C65    // 172.20.44.101
#define DST_PORT 8811

#define ENO1_IFINDEX 2    // 172.20.44.81 的网卡名名称是 eno1，索引是 2

// 从 172.20.62.99:3333 到 172.20.44.81:6666 的数据包修改为 从 172.20.44.81:6666 到 172.20.44.101:8811
// 从 172.20.44.101:8811 到 172.20.44.81:6666 的数据包修改为 从 172.20.44.81:6666 到 172.20.62.99:3333

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
    long ret;

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
    __u8 src_mac[ETH_ALEN] = {0x00, 0x0c, 0x29, 0x16, 0x61, 0x2d};
    __u8 proxy_mac[ETH_ALEN] = {0x58, 0x11, 0x22, 0xc3, 0x23, 0xe6};
    __u8 dst_mac[ETH_ALEN] = {0xd0, 0x94, 0x66, 0xf1, 0x96, 0xae};

    // bpf_printk("Received packet: src port=%d, dst port=%d\n", bpf_ntohs(tcp->source), bpf_ntohs(tcp->dest));

    // 从 172.20.62.99:3333 到 172.20.44.81:6666 的数据包修改为 从 172.20.44.81:6666 到 172.20.44.101:8811
    if (ip->saddr == bpf_htonl(SRC_IP) && tcp->source == bpf_htons(SRC_PORT) && ip->daddr == bpf_htonl(PROXY_IP) && tcp->dest == bpf_htons(PROXY_PORT))
    {
        // update mac
        update_mac(eth, proxy_mac, dst_mac);
        // update ip
        ip->saddr = bpf_htonl(PROXY_IP);
        ip->daddr = bpf_htonl(DST_IP);
        // update tcp
        tcp->source = bpf_htons(PROXY_PORT);
        tcp->dest = bpf_htons(DST_PORT);
        // checksum
        tcp->check = 0;
        ip->check = 0;
        tcp->check = tcp_checksum(tcp, sizeof(struct tcphdr));
        ip->check = ip_checksum(ip, sizeof(struct iphdr));
        // ret = bpf_redirect(ENO1_IFINDEX, 0);
        // ret = XDP_TX;
        ret = XDP_PASS;
        bpf_printk("Redirecting from src to dst: src port=%d, dst port=%d redirect ret=%d\n", bpf_ntohs(tcp->source), bpf_ntohs(tcp->dest), ret);
        return ret;
    }
    // 从 172.20.44.101:8811 到 172.20.44.81:6666 的数据包修改为 从 172.20.44.81:6666 到 172.20.62.99:3333
    else if (ip->saddr == bpf_htonl(DST_IP) && tcp->source == bpf_htons(DST_PORT) && ip->daddr == bpf_htonl(PROXY_IP) && tcp->dest == bpf_htons(PROXY_PORT))
    {
        // update mac
        update_mac(eth, proxy_mac, src_mac);
        // update ip
        ip->saddr = bpf_htonl(PROXY_IP);
        ip->daddr = bpf_htonl(SRC_IP);
        // update tcp
        tcp->source = bpf_htons(PROXY_PORT);
        tcp->dest = bpf_htons(SRC_PORT);
        // checksum
        tcp->check = 0;
        ip->check = 0;
        tcp->check = tcp_checksum(tcp, sizeof(struct tcphdr));
        ip->check = ip_checksum(ip, sizeof(struct iphdr));
        // ret = bpf_redirect(ENO1_IFINDEX, 0);
        // ret = XDP_TX;
        ret = XDP_PASS;
        bpf_printk("Redirecting from dst to src: src port=%d, dst port=%d redirect ret=%d\n", bpf_ntohs(tcp->source), bpf_ntohs(tcp->dest), ret);
        return ret;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
