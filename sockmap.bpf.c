#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_tracing.h>
#include "sockmap.h"
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65535);
    __type(key, int);          // key : local port
    __type(value, int);        // value : fd
} sock_map_rx SEC(".maps");    // 简单的根据源端口获取转发目标的 fd

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tp/syscalls/sys_enter_write")
int handle_tp(void *ctx)
{
    struct event *e;
    __u64 pid = bpf_get_current_pid_tgid() >> 32;
    // 防止事件太多，仅处理 pid 小于 1000 的进程产生的事件
    if (pid > 1000)
    {
        return 0;
    }

    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e == NULL)
    {
        bpf_printk("bpf_ringbuf_reserve failed\n");
        return SK_PASS;
    }
    // 将事件信息发送到用户空间
    e->op = 1;
    e->key = pid;
    e->value = 0;

    bpf_printk("BPF triggered key %d value %d\n", e->key, e->value);
    bpf_ringbuf_submit(e, 0);

    return 0;
}

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
    // 将数据包端口信息发送到用户空间，后续通过在 map 中查找 fd 进行转发
    e->op = 1;
    e->key = bpf_ntohl(skb->local_port);
    e->value = skb->remote_port;

    bpf_printk("BPF triggered key %d value %d\n", e->key, e->value);
    bpf_ringbuf_submit(e, 0);
    return SK_PASS;
}

char LICENSE[] SEC("license") = "GPL";
