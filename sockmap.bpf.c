#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include "sockmap.h"
struct
{
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(max_entries, 65535);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
} sock_map_rx SEC(".maps");    // 简单的根据源端口获取转发目标的 fd

SEC("sk_skb/stream_parser")
int bpf_prog_parser(struct __sk_buff *skb)
{
    return skb->len;    // NOLINT
}

SEC("sk_skb/stream_verdict")
int bpf_prog_verdict(struct __sk_buff *skb)
{
    __u32 local_port;
    __u32 remote_port;
    if (skb->len > 256)
    {
        return SK_PASS;
    }
    local_port = bpf_htonl(skb->local_port);
    remote_port = skb->remote_port;
    bpf_printk("bpf prog verdict local_port %d remote_port %d\n", local_port, remote_port);
    return SK_PASS;
}

char LICENSE[] SEC("license") = "GPL";
