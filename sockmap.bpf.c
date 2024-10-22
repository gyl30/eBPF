#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include "sockmap.h"
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, int);
    __type(value, int);
} sock_map_rx SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("sk_skb/stream_parser")
int bpf_prog_parser(struct __sk_buff *skb)
{
    return skb->len;    // NOLINT
}

SEC("sk_skb/stream_verdict")
int bpf_prog_verdict(struct __sk_buff *skb)
{
    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e == NULL)
    {
        bpf_printk("bpf_ringbuf_reserve failed\n");
        return SK_PASS;
    }

    e->op = 1;
    e->key = bpf_ntohl(skb->local_port);
    e->value = skb->remote_port;

    bpf_printk("BPF triggered key %d value %d\n", e->key, e->value);
    bpf_ringbuf_submit(e, 0);
    return SK_PASS;
}

char LICENSE[] SEC("license") = "GPL";
