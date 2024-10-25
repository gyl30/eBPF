#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#include "sockdirect.h"

struct
{
    __uint(type, BPF_MAP_TYPE_SOCKHASH);
    __uint(key_size, sizeof(__u64));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 65535);
} sockhash SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u64));
    __uint(value_size, sizeof(u64));
    __uint(max_entries, 65535);
} connection_list SEC(".maps");

SEC("sk_skb/stream_parser")
int prog_parser(struct __sk_buff *skb) { return skb->len; }

SEC("sk_skb/stream_verdict")
int prog_verdict(struct __sk_buff *skb)
{
    __u64 self_key;
    self_key = bpf_ntohl(skb->remote_port);
    self_key = self_key << 32 | skb->local_port;
    // bpf_printk("verdict self_key: %llu\n", self_key);
    int err = bpf_sk_redirect_hash(skb, &sockhash, &self_key, 0);
    return err;
}

SEC("sockops")
int sock_ops(struct bpf_sock_ops *ops)
{
    __u32 op;
    __u64 self_key;
    __u64 *target_key;
    __u32 remote_port;
    __u32 local_port;
    op = ops->op;

    local_port = ops->local_port;
    remote_port = bpf_ntohl(ops->remote_port);
    // 过滤掉无关的数据包，从 connection_list 中查找也是可以的
    if (local_port != 8811 && local_port != 1188 && remote_port != 8811 && remote_port != 1188)
    {
        bpf_printk("local_port %d remote_port %d\n", local_port, remote_port);
        return 0;
    }

    self_key = remote_port;
    self_key = self_key << 32 | ops->local_port;

    target_key = bpf_map_lookup_elem(&connection_list, &self_key);
    if (target_key == NULL)
    {
        bpf_printk("not found elem local_port %d remote_port %d key %llu\n", local_port, remote_port, self_key);
        return 0;
    }
    // TCP_CLOSE
    if (op == BPF_SOCK_OPS_STATE_CB && ops->args[1] == 7)
    {
        bpf_printk("del connection local_port %d remote_port %d\n", local_port, remote_port);
        bpf_map_delete_elem(&connection_list, &self_key);
        return 0;
    }

    if (op == BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB || op == BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB)
    {
        bpf_printk("new connection local_port %d remote_port %d %llu\n", local_port, remote_port, target_key);
        bpf_sock_ops_cb_flags_set(ops, ops->bpf_sock_ops_cb_flags | BPF_SOCK_OPS_STATE_CB_FLAG);
        bpf_sock_hash_update(ops, &sockhash, target_key, 0);
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
