#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define AF_INET 2
#define AF_INET6 10
#define MAX_ENTRIES 8192
#define MAX_PORTS 64
#define TASK_COMM_LEN 16
#define ETH_HLEN 14     /* Total octets in header.	 */
#define ETH_P_IP 0x0800 /* Internet Protocol packet	*/

#define TCP_CONNECT_XX 1
#define TCP_ACCEPT_XX 2
#define TCP_STATE_CHANGE_XX 3
#define TCP_BIND_XX 4
#define TCP_LISTEN_STOP_XX 5
#define TCP_LISTEN_START_XX 6
#define TLS_SNI_XX 7

#define TLS_CONTENT_TYPE_HANDSHAKE 0x16
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 0x1
#define TLS_EXTENSION_SERVER_NAME 0x0
// TODO: Figure out real max number according to RFC.
#define TLS_MAX_EXTENSION_COUNT 20
// TODO: figure out the right value.
#define TLS_MAX_SERVER_NAME_LEN 128

// The length of the session ID length field.
#define TLS_SESSION_ID_LENGTH_LEN 1
// The length of the cipher suites length field.
#define TLS_CIPHER_SUITES_LENGTH_LEN 2
// The length of the compression methods length field.
#define TLS_COMPRESSION_METHODS_LENGTH_LEN 1
// The length of the extensions length field.
#define TLS_EXTENSIONS_LENGTH_LEN 2
// The length of the extension type field.
#define TLS_EXTENSION_TYPE_LEN 2
// The length of the extension length field (a single extension).
#define TLS_EXTENSION_LENGTH_LEN 2

// The offset of the server name length field from the start of the server_name
// TLS extension.
#define TLS_SERVER_NAME_LENGTH_OFF 7
// The offset of the server name field from the start of the server_name TLS
// extension.
#define TLS_SERVER_NAME_OFF 9

// The offset of the handshake type field from the start of the TLS payload.
#define TLS_HANDSHAKE_TYPE_OFF 5
// The offset of the session ID length field from the start of the TLS payload.
#define TLS_SESSION_ID_LENGTH_OFF 43

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, u32);
  __type(value, struct sock *);
} sockets SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, u32);
  __type(value, struct sock *);
} bind_sockets SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, struct sock *);
  __type(value, __u64);
} listen_timestamps SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_ENTRIES);
  __type(key, struct sock *);
  __type(value, __u64);
} timestamps SEC(".maps");

struct emit_event {
  __u32 saddr_v4;
  __u8 saddr_v6[16];
  __u32 daddr_v4;
  __u8 daddr_v6[16];
  __u8 type;
  __u8 oldstate;
  __u8 newstate;
  __u8 padding;
  __u8 task[TASK_COMM_LEN];
  __u8 sni[TLS_MAX_SERVER_NAME_LEN];
  __u64 ts_us;
  __u64 delta_us;
  __u32 af; // AF_INET or AF_INET6
  __u32 pid;
  __u32 uid;
  __u16 protocol;
  __u16 sport;
  __u16 dport;
  __u64 rx_b;
  __u64 tx_b;
  __u64 bytes_retrans;
  __u32 total_retrans;
};

struct emit_event *unused_event __attribute__((unused));

static __always_inline bool fill_address(struct emit_event *e, struct sock *sk,
                                         int family) {
  struct inet_sock *sockp = (struct inet_sock *)sk;
  e->af = BPF_CORE_READ(sk, __sk_common.skc_family);
  switch (e->af) {
  case AF_INET:
    BPF_CORE_READ_INTO(&e->saddr_v4, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&e->daddr_v4, sk, __sk_common.skc_daddr);
    break;
  case AF_INET6:
    BPF_CORE_READ_INTO(&e->saddr_v6, sk,
                       __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
    BPF_CORE_READ_INTO(&e->daddr_v6, sk,
                       __sk_common.skc_v6_daddr.in6_u.u6_addr32);
    break;
  default:
    return false;
  }

  BPF_CORE_READ_INTO(&e->dport, sk, __sk_common.skc_dport);
  BPF_CORE_READ_INTO(&e->sport, sockp, inet_sport);
  return true;
}
static __always_inline void trace_connect_v4(struct pt_regs *ctx, pid_t pid,
                                             struct sock *sk) {

  struct emit_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct emit_event), 0);
  if (!event) {
    return;
  }
  event->type = TCP_CONNECT_XX;
  event->af = AF_INET;
  event->pid = pid;
  event->uid = bpf_get_current_uid_gid();
  event->ts_us = bpf_ktime_get_ns() / 1000;
  fill_address(event, sk, AF_INET);
  BPF_CORE_READ_INTO(&event->sport, sk, __sk_common.skc_num);
  BPF_CORE_READ_INTO(&event->dport, sk, __sk_common.skc_dport);
  bpf_get_current_comm(event->task, sizeof(event->task));
  bpf_ringbuf_submit(event, 0);
}

static __always_inline void trace_connect_v6(struct pt_regs *ctx, pid_t pid,
                                             struct sock *sk) {
  struct emit_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct emit_event), 0);
  if (!event) {
    return;
  }

  event->type = TCP_CONNECT_XX;
  event->af = AF_INET6;
  event->pid = pid;
  event->uid = bpf_get_current_uid_gid();
  event->ts_us = bpf_ktime_get_ns() / 1000;
  fill_address(event, sk, AF_INET6);
  BPF_CORE_READ_INTO(&event->sport, sk, __sk_common.skc_num);
  BPF_CORE_READ_INTO(&event->dport, sk, __sk_common.skc_dport);
  bpf_get_current_comm(event->task, sizeof(event->task));
  bpf_ringbuf_submit(event, 0);
}
static __always_inline int trace_connect(struct pt_regs *ctx, struct sock *sk,
                                         int ip_ver) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = pid_tgid >> 32;
  if (ip_ver == 4) {
    trace_connect_v4(ctx, (pid_t)pid, sk);
  } else {
    trace_connect_v6(ctx, (pid_t)pid, sk);
  }
  return 0;
}
static __always_inline int exit_tcp_connect(struct pt_regs *ctx, int ret,
                                            int ip_ver) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 tid = pid_tgid;
  struct sock **skpp;
  struct sock *sk;
  skpp = bpf_map_lookup_elem(&sockets, &tid);
  if (!skpp) {
    return 0;
  }

  if (ret) {
    goto end;
  }

  sk = *skpp;

  trace_connect(ctx, sk, ip_ver);
end:
  bpf_map_delete_elem(&sockets, &tid);
  return 0;
}

static __always_inline int enter_tcp_connect(struct sock *sk) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 tid = pid_tgid;
  bpf_map_update_elem(&sockets, &tid, &sk, 0);
  return 0;
}

static __always_inline int
tcp_state_change(struct trace_event_raw_inet_sock_set_state *ctx) {
  struct sock *sk = (struct sock *)BPF_CORE_READ(ctx, skaddr);

  __u16 family = ctx->family;

  __u16 sport;
  __u16 dport;
  __u64 *tsp;
  __u64 delta_us;
  __u64 ts;
  struct tcp_sock *tp;
  sport = BPF_CORE_READ(ctx, sport);
  dport = BPF_CORE_READ(ctx, dport);

  if (BPF_CORE_READ(ctx, protocol) != IPPROTO_TCP) {
    return 0;
  }
  tsp = bpf_map_lookup_elem(&timestamps, &sk);
  ts = bpf_ktime_get_ns();
  if (!tsp) {
    delta_us = 0;
  } else {
    delta_us = (ts - *tsp) / 1000;
  }
  struct emit_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct emit_event), 0);
  if (!event) {
    return 0;
  }

  event->type = TCP_STATE_CHANGE_XX;
  event->ts_us = ts / 1000;
  event->delta_us = delta_us;
  event->pid = bpf_get_current_pid_tgid() >> 32;
  event->oldstate = BPF_CORE_READ(ctx, oldstate);
  event->newstate = BPF_CORE_READ(ctx, newstate);
  event->af = family;
  fill_address(event, sk, family);
  event->sport = sport;
  event->dport = dport;
  bpf_get_current_comm(&event->task, sizeof(event->task));

  if (event->newstate == TCP_CLOSE) {
    tp = (struct tcp_sock *)sk;
    event->rx_b = BPF_CORE_READ(tp, bytes_received);
    event->tx_b = BPF_CORE_READ(tp, bytes_acked);
    event->bytes_retrans = BPF_CORE_READ(tp, bytes_retrans);
    event->total_retrans = BPF_CORE_READ(tp, total_retrans);
    bpf_map_delete_elem(&timestamps, &sk);
  } else {
    bpf_map_update_elem(&timestamps, &sk, &ts, BPF_ANY);
  }
  bpf_ringbuf_submit(event, 0);
  return 0;
}
static int handle_bind_entry(struct pt_regs *ctx, struct socket *socket) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 tid = (__u32)pid_tgid;
  __u64 ts = bpf_ktime_get_ns();
  if (bpf_map_update_elem(&bind_sockets, &tid, &socket, BPF_ANY) != 0) {
    bpf_printk("bind_sockets update failed\n");
  }
  return 0;
}

static int handle_bind_exit(struct pt_regs *ctx, short ver) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = pid_tgid >> 32;
  __u32 tid = (__u32)pid_tgid;
  __u64 uid_gid = bpf_get_current_uid_gid();
  u64 mntns_id;
  struct socket **socketp, *socket;
  struct inet_sock *inet_sock;
  struct sock *sock;
  int ret;

  socketp = bpf_map_lookup_elem(&bind_sockets, &tid);
  if (!socketp) {
    return 0;
  }

  ret = PT_REGS_RC(ctx);
  socket = *socketp;
  sock = BPF_CORE_READ(socket, sk);
  inet_sock = (struct inet_sock *)sock;

  struct emit_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct emit_event), 0);
  if (!event) {
    return 0;
  }

  event->pid = pid;
  event->uid = (u32)uid_gid;
  event->type = TCP_BIND_XX;
  event->af = ver == 4 ? AF_INET : AF_INET6;
  event->ts_us = bpf_ktime_get_ns() / 1000;
  bpf_get_current_comm(&event->task, sizeof(event->task));
  event->oldstate = BPF_CORE_READ(sock, __sk_common.skc_bound_dev_if);
  event->newstate = ret;
  event->sport = bpf_ntohs(BPF_CORE_READ(inet_sock, inet_sport));
  event->protocol = BPF_CORE_READ_BITFIELD_PROBED(sock, sk_protocol);
  if (ver == 4) {
    bpf_probe_read_kernel(&event->saddr_v4, sizeof(event->saddr_v4),
                          &inet_sock->inet_saddr);
  } else {
    bpf_probe_read_kernel(&event->saddr_v6, sizeof(event->saddr_v6),
                          sock->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
  }

  bpf_ringbuf_submit(event, 0);

  bpf_map_delete_elem(&bind_sockets, &tid);
  return 0;
}
SEC("kprobe/inet_listen")
int BPF_KPROBE(inet_listen_entry, struct socket *sock, int backlog) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = pid_tgid >> 32;
  __u32 tid = (__u32)pid_tgid;
  struct emit_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct emit_event), 0);
  if (!event) {
    return 0;
  }
  event->type = TCP_LISTEN_START_XX;
  event->pid = pid;
  struct sock *sk = BPF_CORE_READ(sock, sk);
  struct inet_sock *inet = (struct inet_sock *)sk;
  int type = BPF_CORE_READ(sock, type);
  event->af = BPF_CORE_READ(sk, __sk_common.skc_family);
  event->protocol = ((__u32)event->af << 16) | type;
  event->sport = bpf_ntohs(BPF_CORE_READ(inet, inet_sport));
  if (event->af == AF_INET) {
    event->saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
  } else if (event->af == AF_INET6) {
    BPF_CORE_READ_INTO(event->saddr_v6, sk,
                       __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
  }

  __u64 ts = bpf_ktime_get_ns();
  event->ts_us = ts / 1000;
  if (bpf_map_update_elem(&listen_timestamps, &sk, &ts, BPF_ANY) != 0) {
    bpf_printk("listen_timestamps update failed\n");
  }

  bpf_ringbuf_submit(event, 0);
  return 0;
}

SEC("kprobe/inet_csk_listen_stop")
int BPF_KPROBE(inet_csk_listen_stop, struct sock *sk) {

  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = pid_tgid >> 32;
  __u32 tid = (__u32)pid_tgid;
  __u64 delta_us;
  __u64 ts = bpf_ktime_get_ns();
  __u64 *tsp = bpf_map_lookup_elem(&listen_timestamps, &sk);
  if (!tsp) {
    delta_us = 0;
  } else {
    delta_us = (ts - *tsp) / 1000;
  }

  bpf_map_delete_elem(&listen_timestamps, &sk);
  struct emit_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct emit_event), 0);
  if (!event) {
    return 0;
  }
  __u64 uid_gid = bpf_get_current_uid_gid();
  event->pid = pid;
  event->uid = (u32)uid_gid;
  event->type = TCP_LISTEN_STOP_XX;
  event->ts_us = bpf_ktime_get_ns() / 1000;
  event->delta_us = delta_us;
  event->af = BPF_CORE_READ(sk, __sk_common.skc_family);
  bpf_get_current_comm(&event->task, sizeof(event->task));
  event->oldstate = BPF_CORE_READ(sk, __sk_common.skc_bound_dev_if);
  struct inet_sock *inet_sock = (struct inet_sock *)sk;
  event->sport = bpf_ntohs(BPF_CORE_READ(inet_sock, inet_sport));
  event->protocol = BPF_CORE_READ_BITFIELD_PROBED(sk, sk_protocol);
  if (event->af == AF_INET) {
    event->saddr_v4 = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
  } else if (event->af == AF_INET6) {
    BPF_CORE_READ_INTO(event->saddr_v6, sk,
                       __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
  }
  bpf_ringbuf_submit(event, 0);
  return 0;
}

SEC("kprobe/inet_bind")
int BPF_KPROBE(bind_ipv4_entry, struct socket *socket) {
  return handle_bind_entry(ctx, socket);
}

SEC("kretprobe/inet_bind")
int BPF_KRETPROBE(bind_ipv4_exit) { return handle_bind_exit(ctx, 4); }

SEC("kprobe/inet6_bind")
int BPF_KPROBE(bind_ipv6_entry, struct socket *socket) {
  return handle_bind_entry(ctx, socket);
}

SEC("kretprobe/inet6_bind")
int BPF_KRETPROBE(bind_ipv6_exit) { return handle_bind_exit(ctx, 6); }
SEC("tracepoint/sock/inet_sock_set_state")
int handle_set_state(struct trace_event_raw_inet_sock_set_state *ctx) {
  tcp_state_change(ctx);
  return 0;
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(exit_inet_csk_accept) {
  __u64 pid_tgid = bpf_get_current_pid_tgid();
  __u32 pid = pid_tgid >> 32;
  __u64 uid_gid = bpf_get_current_uid_gid();
  __u32 uid = uid_gid;
  __u16 family;

  struct sock *sk = (struct sock *)PT_REGS_RC(ctx);
  if (!sk) {
    return 0;
  }

  family = BPF_CORE_READ(sk, __sk_common.skc_family);

  struct emit_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct emit_event), 0);
  if (!event) {
    return 0;
  }

  event->type = TCP_ACCEPT_XX;
  event->pid = pid;
  event->af = family;
  event->uid = uid;
  event->ts_us = bpf_ktime_get_ns() / 1000;
  bpf_get_current_comm(&event->task, sizeof(event->task));
  fill_address(event, sk, family);
  event->sport = bpf_ntohs(event->sport);
  bpf_ringbuf_submit(event, 0);
  return 0;
}
static inline int parse_sni(struct __sk_buff *skb, int data_offset, char *out) {
  // Verify TLS content type.
  __u8 content_type;
  bpf_skb_load_bytes(skb, data_offset, &content_type, 1);
  if (content_type != TLS_CONTENT_TYPE_HANDSHAKE) {

    return 0;
  }

  // Verify TLS handshake type.
  __u8 handshake_type;
  bpf_skb_load_bytes(skb, data_offset + TLS_HANDSHAKE_TYPE_OFF, &handshake_type,
                     1);
  if (handshake_type != TLS_HANDSHAKE_TYPE_CLIENT_HELLO)
    return 0;

  int session_id_len_off = data_offset + TLS_SESSION_ID_LENGTH_OFF;
  __u8 session_id_len;
  bpf_skb_load_bytes(skb, session_id_len_off, &session_id_len, 1);

  int cipher_suites_len_off =
      session_id_len_off + TLS_SESSION_ID_LENGTH_LEN + session_id_len;
  __u16 cipher_suites_len_be;
  bpf_skb_load_bytes(skb, cipher_suites_len_off, &cipher_suites_len_be, 2);

  int compression_methods_len_off = cipher_suites_len_off +
                                    TLS_CIPHER_SUITES_LENGTH_LEN +
                                    bpf_ntohs(cipher_suites_len_be);

  __u8 compression_methods_len;
  bpf_skb_load_bytes(skb, compression_methods_len_off, &compression_methods_len,
                     1);

  int extensions_len_off = compression_methods_len_off +
                           TLS_COMPRESSION_METHODS_LENGTH_LEN +
                           compression_methods_len;

  int extensions_off = extensions_len_off + TLS_EXTENSIONS_LENGTH_LEN;

  // TODO: Ensure the cursor doesn't surpass the extensions length value?
  __u16 cur = 0;
  __u16 server_name_ext_off = 0;
  for (int i = 0; i < TLS_MAX_EXTENSION_COUNT; i++) {
    __u16 curr_ext_type_be;
    bpf_skb_load_bytes(skb, extensions_off + cur, &curr_ext_type_be, 2);
    if (bpf_ntohs(curr_ext_type_be) == TLS_EXTENSION_SERVER_NAME) {
      server_name_ext_off = extensions_off + cur;
      break;
    }
    // Skip the extension type field to get to the extension length field.
    cur += TLS_EXTENSION_TYPE_LEN;

    // Read the extension length and skip the extension length field as well as
    // the rest of the extension to get to the next extension.
    __u16 len_be;
    bpf_skb_load_bytes(skb, extensions_off + cur, &len_be, 2);
    cur += TLS_EXTENSION_LENGTH_LEN + bpf_ntohs(len_be);
  }

  if (server_name_ext_off == 0) // Couldn't find server name extension.
    return 0;

  __u16 server_name_len_be;
  bpf_skb_load_bytes(skb, server_name_ext_off + TLS_SERVER_NAME_LENGTH_OFF,
                     &server_name_len_be, 2);
  __u16 server_name_len = bpf_ntohs(server_name_len_be);
  if (server_name_len == 0 || server_name_len > TLS_MAX_SERVER_NAME_LEN)
    return 0;

  // The server name field under the server name extension.
  __u16 server_name_off = server_name_ext_off + TLS_SERVER_NAME_OFF;

  // Read the server name field.
  int counter = 0;
  for (int i = 0; i < TLS_MAX_SERVER_NAME_LEN; i++) {
    if (!out)
      break;
    if (i >= server_name_len)
      break;
    char b;
    bpf_skb_load_bytes(skb, server_name_off + i, &b, 1);
    if (b == '\0')
      break;
    out[i] = b;
    counter++;
  }
  return counter;
}
SEC("cgroup_skb/egress")
int ig_trace_sni(struct __sk_buff *skb) {
  // Skip frames with non-IP Ethernet protocol.
  struct ethhdr ethh;
  if (bpf_skb_load_bytes(skb, 0, &ethh, sizeof ethh))
    return 1;
  if (bpf_ntohs(ethh.h_proto) != ETH_P_IP)
    return 1;

  int ip_off = ETH_HLEN;
  // Read the IP header.
  struct iphdr iph;
  if (bpf_skb_load_bytes(skb, ip_off, &iph, sizeof iph))
    return 1;

  // Skip packets with IP protocol other than TCP.
  if (iph.protocol != IPPROTO_TCP)
    return 1;

  __u8 ip_header_len = iph.ihl * 4;
  int tcp_off = ip_off + ip_header_len;

  // Read the TCP header.
  struct tcphdr tcph;
  if (bpf_skb_load_bytes(skb, tcp_off, &tcph, sizeof tcph))
    return 1;

  if (!tcph.psh)
    return 1;

  // The data offset field in the header is specified in 32-bit words. We
  // have to multiply this value by 4 to get the TCP header length in bytes.
  __u8 tcp_header_len = tcph.doff * 4;
  // TLS data starts at this offset.
  int payload_off = tcp_off + tcp_header_len;

  // Parse SNI.
  char sni[TLS_MAX_SERVER_NAME_LEN] = {};
  int read = parse_sni(skb, payload_off, sni);
  if (read == 0) {
    return 1;
  }
  struct emit_event *event =
      bpf_ringbuf_reserve(&events, sizeof(struct emit_event), 0);
  if (!event) {
    return 1;
  }
  event->type = TLS_SNI_XX;
  for (int i = 0; i < TLS_MAX_SERVER_NAME_LEN; i++) {
    if (sni[i] == '\0')
      break;
    event->sni[i] = sni[i];
  }
  bpf_ringbuf_submit(event, 0);
  return 1;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, struct sock *sk) {
  return enter_tcp_connect(sk);
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(tcp_v6_connect, struct sock *sk) {
  return enter_tcp_connect(sk);
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(tcp_v4_connect_ret, int ret) {
  return exit_tcp_connect(ctx, ret, 4);
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(tcp_v6_connect_ret, int ret) {
  return exit_tcp_connect(ctx, ret, 6);
}

char LICENSE[] SEC("license") = "GPL";
