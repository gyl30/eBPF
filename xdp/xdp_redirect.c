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
#define SRC_IP 0xAC143E63      // 172.20.62.99
#define PROXY_IP 0xAC142C51    // 172.20.44.81
#define DST_IP 0xAC142C65      // 172.20.44.101
#define TARGET_PORT 8811       // 目标端口，遇到此端口的数据包才进行处理
#define DEVICE_IFINDEX 2       // 转发网卡的索引
//
static __always_inline void update_mac(struct ethhdr *eth, __u8 *src_mac, __u8 *dst_mac)
{
    __builtin_memcpy(eth->h_source, src_mac, ETH_ALEN);
    __builtin_memcpy(eth->h_dest, dst_mac, ETH_ALEN);
}

static __u16 csum_fold_helper(__u64 csum)
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
static __always_inline void iph_csum(struct iphdr *iph)
{
    __u16 *next_iph_u16 = (__u16 *)iph;
    __u32 csum = 0;
    iph->check = 0;
#pragma clang loop unroll(full)
    for (__u32 i = 0; i < sizeof(*iph) >> 1; i++)
    {
        csum += *next_iph_u16++;
    }

    iph->check = ~((csum & 0xffff) + (csum >> 16));
}

static __always_inline __u32 csum_add(__u32 addend, __u32 csum)
{
    __u32 res = csum;
    res += addend;
    return (res + (res < addend));
}

static __always_inline __u32 csum_sub(__u32 addend, __u32 csum) { return csum_add(csum, ~addend); }

static __always_inline __u16 csum_diff4(__u32 from, __u32 to, __u16 csum)
{
    __u32 tmp = csum_sub(from, ~((__u32)csum));
    return csum_fold_helper(csum_add(to, tmp));
}

static __always_inline void update_headers(void *data,
                                           void *data_end,
                                           struct ethhdr *eth,
                                           struct iphdr *ip,
                                           struct tcphdr *tcp,
                                           __u8 *new_src_mac,
                                           __u8 *new_dst_mac,
                                           __u32 new_src_ip,
                                           __u32 new_dst_ip,
                                           __u16 new_src_port,
                                           __u16 new_dst_port)
{
    // 更新 MAC 地址
    update_mac(eth, new_src_mac, new_dst_mac);
    // 更新 SRC IP and CHECKSUM
    __u16 tcp_len = bpf_ntohs(ip->tot_len) - (ip->ihl << 2);
    __u32 olddestaddr = ip->daddr;
    __u32 oldsrcaddr = ip->saddr;
    ip->saddr = new_src_ip;
    ip->daddr = new_dst_ip;
    iph_csum(ip);
    __u16 old_tcp_csum = tcp->check;
    tcp->check = csum_diff4(olddestaddr, ip->daddr, tcp->check);
    tcp->check = csum_diff4(oldsrcaddr, ip->saddr, tcp->check);
    __u16 oldsrcport = tcp->source;
    __u16 olddstport = tcp->dest;
    tcp->source = new_src_port;
    tcp->dest = new_dst_port;
    tcp->check = csum_diff4(oldsrcport, tcp->source, tcp->check);
    tcp->check = csum_diff4(olddstport, tcp->dest, tcp->check);
    // bpf_printk("TCP checksum updated from %x to %x\n", old_tcp_csum, tcp->check);
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
    //
    // SRC --> PROXY --> DST
    if (ip->saddr == bpf_htonl(SRC_IP) && ip->daddr == bpf_htonl(PROXY_IP) && tcp->dest == bpf_htons(TARGET_PORT))
    {
        __u32 old_tcp_csum = tcp->check;
        __u32 old_ip_csum = ip->check;
        __u16 PROXY_PORT = bpf_ntohs(tcp->source);
        __u16 DST_PORT = bpf_ntohs(tcp->dest);
        update_headers(data, data_end, eth, ip, tcp, proxy_mac, dst_mac, bpf_htonl(PROXY_IP), bpf_htonl(DST_IP), bpf_htons(PROXY_PORT), bpf_htons(DST_PORT));
        __u32 new_tcp_csum = tcp->check;
        __u32 new_ip_csum = ip->check;
        ret = bpf_redirect(DEVICE_IFINDEX, 0);
        bpf_printk("redirecting from src to dst: src port %d dst port %d ret %d\n", bpf_ntohs(tcp->source), bpf_ntohs(tcp->dest), ret);
        return ret;
    }
    // DST --> PROXY --> SRC
    else if (ip->saddr == bpf_htonl(DST_IP) && tcp->source == bpf_htons(TARGET_PORT) && ip->daddr == bpf_htonl(PROXY_IP))
    {
        __u32 old_tcp_csum = tcp->check;
        __u32 old_ip_csum = ip->check;
        __u16 PROXY_PORT = bpf_ntohs(tcp->source);
        __u16 SRC_PORT = bpf_ntohs(tcp->dest);
        update_headers(data, data_end, eth, ip, tcp, proxy_mac, src_mac, bpf_htonl(PROXY_IP), bpf_htonl(SRC_IP), bpf_htons(PROXY_PORT), bpf_htons(SRC_PORT));
        __u32 new_tcp_csum = tcp->check;
        __u32 new_ip_csum = ip->check;
        ret = bpf_redirect(DEVICE_IFINDEX, 0);
        bpf_printk("redirecting from dst to src: src port %d dst port %d ret %d\n", bpf_ntohs(tcp->source), bpf_ntohs(tcp->dest), ret);
        return ret;
    }

    return XDP_PASS;    // 如果没有匹配，允许数据包通过
}

char _license[] SEC("license") = "GPL";    // 许可证信息
