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

SEC("sk_msg")
int bpf_redir(struct sk_msg_md *msg)
{
    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e == NULL)
    {
        bpf_printk("bpf_ringbuf_reserve failed\n");
        return 0;
    }

    e->op = 1;
    e->key = msg->local_port;
    e->value = msg->remote_port;

    bpf_printk("BPF triggered from PID %d.\n", e->key);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
