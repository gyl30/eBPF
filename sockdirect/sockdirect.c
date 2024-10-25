#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <signal.h>
#include <unistd.h>
#include <sys/resource.h>
#include <netinet/tcp.h>
#include <sys/select.h>
#include "sockdirect.h"
#include "sockdirect.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args) { return vfprintf(stderr, format, args); }
static volatile sig_atomic_t exiting;

static void sig_handler(int sig)
{
    (void)sig;
    exiting = 1;
}

int main(int argc, char **argv)
{
    struct rlimit rlim_new = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    int ret = setrlimit(RLIMIT_MEMLOCK, &rlim_new);
    if (ret != 0)
    {
        printf("failed to set RLIMIT_MEMLOCK\n");
        return 0;
    }
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    struct sockdirect_bpf *obj = sockdirect_bpf__open_and_load();

    int cg_fd = open("/sys/fs/cgroup", __O_DIRECTORY, O_RDONLY);
    if (cg_fd < 0)
    {
        fprintf(stderr, "open cgroup failed: %s\n", strerror(errno));
        return -1;
    }
    int sockops_fd = bpf_program__fd(obj->progs.sock_ops);
    int err = bpf_prog_attach(sockops_fd, cg_fd, BPF_CGROUP_SOCK_OPS, 0);
    if (err < 0)
    {
        fprintf(stderr, "failed to attach sockops: %s\n", strerror(errno));
        return -1;
    }

    int sockhash_fd = bpf_map__fd(obj->maps.sockhash);
    //
    int parser_fd = bpf_program__fd(obj->progs.prog_parser);
    err = bpf_prog_attach(parser_fd, sockhash_fd, BPF_SK_SKB_STREAM_PARSER, 0);
    if (err < 0)
    {
        fprintf(stderr, "failed to attach parser: %s\n", strerror(errno));
        return -1;
    }
    //
    int verdict_fd = bpf_program__fd(obj->progs.prog_verdict);
    err = bpf_prog_attach(verdict_fd, sockhash_fd, BPF_SK_SKB_STREAM_VERDICT, 0);
    if (err < 0)
    {
        fprintf(stderr, "failed to attach verdict: %s\n", strerror(errno));
        return -1;
    }

    int connection_list_fd = bpf_map__fd(obj->maps.connection_list);

    uint32_t left_local_port = 3333;
    uint32_t left_remote_port = 1188;
    uint32_t right_local_port = 6666;
    uint32_t right_remote_port = 8888;
    // left local 3333  连接 left remote 1188
    // right local 6666 连接 right remote 8888
    // 实现的效果是 left local 和 right remote 上的数据包互相转发
    uint64_t left_key = left_local_port;
    left_key = left_key << 32 | left_remote_port;
    //
    uint64_t right_key = right_local_port;
    right_key = right_key << 32 | right_remote_port;

    uint64_t left_value = right_key;
    uint64_t right_value = left_key;
    err = bpf_map_update_elem(connection_list_fd, &left_key, &left_value, BPF_ANY);
    if (err < 0)
    {
        fprintf(stderr, " pdate connection failed left %lu right %lu %d\n", left_key, right_key, err);
        return -1;
    }
    printf("update left connection %lu %lu\n", left_key, left_value);
    err = bpf_map_update_elem(connection_list_fd, &right_key, &right_value, BPF_ANY);
    if (err < 0)
    {
        fprintf(stderr, " pdate connection failed left %lu right %lu %d\n", left_key, right_key, err);
        return -1;
    }

    printf("update right connection %lu %lu\n", right_key, right_value);
    while (!exiting)
    {
        sleep(1);
    }
    printf("exiting\n");
    // bpf_prog_detach(sockops_fd, BPF_CGROUP_SOCK_OPS);
    printf("detach cgroup sockops\n");
    bpf_prog_detach(parser_fd, BPF_SK_SKB_STREAM_PARSER);
    printf("detach stream parser\n");
    bpf_prog_detach(verdict_fd, BPF_SK_SKB_STREAM_VERDICT);
    printf("detach stream verdict\n");
    // close(cg_fd);
    sockdirect_bpf__destroy(obj);
    return 0;
}
