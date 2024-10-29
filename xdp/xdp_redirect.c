#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

// 定义常量
#define SRC_IP 0xAC143E63    // 172.20.62.99
#define SRC_PORT 3333

#define PROXY_IP 0xAC142C51    // 172.20.44.81
#define PROXY_PORT 6666

#define DST_IP 0xAC142C65    // 172.20.44.101
#define DST_PORT 8811

#define ENO1_IFINDEX 2    // eno1 网卡的索引

// 更新 MAC 地址
static __always_inline void update_mac(struct ethhdr *eth, __u8 *src_mac, __u8 *dst_mac)
{
    __builtin_memcpy(eth->h_source, src_mac, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, dst_mac, ETH_ALEN);
}

static __always_inline __u16 csum_fold_helper(__u64 csum)
{
    int i;
#pragma unroll
    for (i = 0; i < 4; i++)
    {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

static __always_inline __u16 iph_csum(struct iphdr *iph)
{
    iph->check = 0;
    unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
    return csum_fold_helper(csum);
}
static __always_inline __u16 ip_checksum(struct iphdr *ip, int ip_size)
{
    unsigned long csum = bpf_csum_diff(0, 0, (void *)ip, ip_size, 0);
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum = (csum & 0xFFFF) + (csum >> 16);
    return ~csum;
}
static __always_inline __u16 csum_reduce_helper(__u32 csum)
{
    csum = ((csum & 0xffff0000) >> 16) + (csum & 0xffff);
    csum = ((csum & 0xffff0000) >> 16) + (csum & 0xffff);

    return csum;
}
#define NUM_SERVERS 2
#define HASH_SEED 0xDEADBEEF

#define MAX_OPT_WORDS 10    // 40 bytes for options
#define MAX_TARGET_COUNT 64
struct ipv4_psd_header
{
    __u32 src_addr; /* IP address of source host. */
    __u32 dst_addr; /* IP address of destination host. */
    __u8 zero;      /* zero. */
    __u8 proto;     /* L4 protocol type. */
    __u16 len;      /* L4 length. */
};
static __always_inline int compute_tcp_csum(struct iphdr *ip, struct tcphdr *tcp, void *data_end)
{
    struct ipv4_psd_header psdh;
    __u32 csum;
    int ret = 0;

    tcp->check = 0;
    csum = bpf_csum_diff(0, 0, (__be32 *)tcp, sizeof(struct tcphdr), 0);
    psdh.src_addr = ip->saddr;
    psdh.dst_addr = ip->daddr;
    psdh.zero = 0;
    psdh.proto = IPPROTO_TCP;
    psdh.len = bpf_htons(bpf_ntohs(ip->tot_len) - sizeof(struct iphdr));
    csum = bpf_csum_diff(0, 0, (__be32 *)&psdh, sizeof(struct ipv4_psd_header), csum);
    __u32 tcphdrlen = tcp->doff * 4;

    if (tcphdrlen == sizeof(struct tcphdr))
        goto OUT;

    /* There are TCP options */
    __u32 *opt = (__u32 *)(tcp + 1);
    __u32 parsed = sizeof(struct tcphdr);
    for (int i = 0; i < MAX_OPT_WORDS; i++)
    {
        if ((void *)(opt + 1) > data_end)
        {
            ret = -1;
            goto OUT;
        }

        csum = bpf_csum_diff(0, 0, (__be32 *)opt, sizeof(__u32), csum);

        parsed += sizeof(__u32);
        if (parsed == tcphdrlen)
            break;
        opt++;
    }

OUT:
    tcp->check = ~csum_reduce_helper(csum);
    return ret;
}
static __always_inline __u16 tcp_checksum(struct tcphdr *tcp, int tcp_size)
{
    unsigned long csum = bpf_csum_diff(0, 0, (void *)tcp, tcp_size, 0);
    csum = (csum & 0xFFFF) + (csum >> 16);
    csum = (csum & 0xFFFF) + (csum >> 16);
    return ~csum;
}

// 更新数据包的头部
static __always_inline void update_headers(
    struct ethhdr *eth, struct iphdr *ip, struct tcphdr *tcp, __u8 *new_src_mac, __u8 *new_dst_mac, __u32 new_src_ip, __u32 new_dst_ip, __u16 new_src_port, __u16 new_dst_port, void *data_end)
{
    // 更新 MAC 地址
    update_mac(eth, new_src_mac, new_dst_mac);
    // 更新 IP 地址
    ip->saddr = bpf_htonl(new_src_ip);
    ip->daddr = bpf_htonl(new_dst_ip);
    // 更新 TCP 端口
    tcp->source = bpf_htons(new_src_port);
    tcp->dest = bpf_htons(new_dst_port);
    // 计算新的校验和

    ip->check = 0;
    __u32 csum = 0;
    __u16 *next_iph_u16 = (__u16 *)ip;
    for (int i = 0; i < sizeof(struct iphdr) / 2; i++)
    {
        csum += *next_iph_u16++;
    }
    ip->check = ~((csum & 0xffff) + (csum >> 16));
    tcp->check = 0;
    compute_tcp_csum(ip, tcp, data_end);
}

SEC("xdp_prog")
int xdp_redirect(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    long ret;

    // 解析以太网头
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
    {
        return XDP_PASS;    // 数据包不完整，跳过
    }

    // 解析 IP 头
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end || ip->protocol != IPPROTO_TCP)
    {
        return XDP_PASS;    // 不是 TCP 数据包，跳过
    }

    // 解析 TCP 头
    struct tcphdr *tcp = (void *)ip + sizeof(*ip);
    if ((void *)tcp + sizeof(*tcp) > data_end)
    {
        return XDP_PASS;    // 数据包不完整，跳过
    }

    // MAC 地址定义
    __u8 src_mac[ETH_ALEN] = {0x98, 0xa9, 0x2d, 0x4f, 0x42, 0x8b};      // 源方向最近一跳的 MAC
    __u8 proxy_mac[ETH_ALEN] = {0x58, 0x11, 0x22, 0xc3, 0x23, 0xe6};    // 代理 MAC
    __u8 dst_mac[ETH_ALEN] = {0x98, 0xa9, 0x2d, 0x4f, 0x42, 0x8b};      // 目标方向最近一跳 MAC

    // 从 172.20.62.99:3333 到 172.20.44.81:6666 的重定向
    if (ip->saddr == bpf_htonl(SRC_IP) && tcp->source == bpf_htons(SRC_PORT) && ip->daddr == bpf_htonl(PROXY_IP) && tcp->dest == bpf_htons(PROXY_PORT))
    {
        update_headers(eth, ip, tcp, proxy_mac, dst_mac, PROXY_IP, DST_IP, PROXY_PORT, DST_PORT, data_end);
        ret = bpf_redirect(ENO1_IFINDEX, 0);
        bpf_printk("Redirecting from src to dst: src port=%d, dst port=%d\n", bpf_ntohs(tcp->source), bpf_ntohs(tcp->dest));
        return ret;    // 重定向
    }
    // 从 172.20.44.101:8811 到 172.20.44.81:6666 的重定向
    else if (ip->saddr == bpf_htonl(DST_IP) && tcp->source == bpf_htons(DST_PORT) && ip->daddr == bpf_htonl(PROXY_IP) && tcp->dest == bpf_htons(PROXY_PORT))
    {
        update_headers(eth, ip, tcp, proxy_mac, src_mac, PROXY_IP, SRC_IP, PROXY_PORT, SRC_PORT, data_end);
        ret = bpf_redirect(ENO1_IFINDEX, 0);
        bpf_printk("Redirecting from dst to src: src port=%d, dst port=%d\n", bpf_ntohs(tcp->source), bpf_ntohs(tcp->dest));
        return ret;    // 重定向
    }

    return XDP_PASS;    // 如果没有匹配，允许数据包通过
}

char _license[] SEC("license") = "GPL";    // 许可证信息
