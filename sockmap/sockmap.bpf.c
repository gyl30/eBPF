#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "sockmap.h"
struct
{
    __uint(type, BPF_MAP_TYPE_SOCKMAP);
    __uint(max_entries, 65535);
    __type(key, int);
    __type(value, int);
} sock_map SEC(".maps");    // 简单的根据源端口获取转发目标的 fd
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, int);
    __type(value, int);
} sock_hash SEC(".maps");

SEC("sk_skb/stream_parser")
int bpf_prog_parser(struct __sk_buff *skb)
{
    __u32 local_port;
    __u32 remote_port;
    void *index;
    local_port = skb->local_port;
    remote_port = bpf_ntohl(skb->remote_port);
    index = bpf_map_lookup_elem(&sock_hash, &remote_port);
    if (index == NULL)
    {
        bpf_printk("----------- bpf prog verdict local_port %d remote_port %d\n", local_port, remote_port);
        return skb->len;    // NOLINT
    }
    bpf_printk("bpf prog parse local_port %d remote_port %d index %d skb len %d\n", local_port, remote_port, *(int *)index, skb->len);
    return skb->len;    // NOLINT
}

SEC("sk_skb/stream_verdict")
int bpf_prog_verdict(struct __sk_buff *skb)
{
    __u32 local_port;
    __u32 remote_port;
    __u32 *index;
    local_port = skb->local_port;
    remote_port = bpf_ntohl(skb->remote_port);
    index = bpf_map_lookup_elem(&sock_hash, &remote_port);
    if (index == NULL)
    {
        bpf_printk("----------- bpf prog verdict local_port %d remote_port %d\n", local_port, remote_port);
        return bpf_sk_redirect_map(skb, &sock_map, 0, 0);
    }
    bpf_printk("bpf prog verdict local_port %d remote_port %d map index %d\n", local_port, remote_port, *index);
    return bpf_sk_redirect_map(skb, &sock_map, *index, 0);
}

char LICENSE[] SEC("license") = "GPL";
