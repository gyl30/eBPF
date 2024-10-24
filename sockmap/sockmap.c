#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <stdio.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <signal.h>
#include "sockmap.h"
#include "sockmap.skel.h"

static volatile sig_atomic_t exiting;

static void sig_handler(int sig)
{
    (void)sig;
    exiting = 1;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG)
    {
        return 0;
    }
    return vfprintf(stderr, format, args);
}
int update_map_elem(int map_fd, int key, int value)
{
    int lookup_key = 10;
    int lookup_value = 0;
    int ret = bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
    if (ret != 0)
    {
        printf("failed update map key %d value %d ret %d\n", key, value, ret);
        return ret;
    }
    printf("update map key %d value %d\n", key, value);
    ret = bpf_map_lookup_elem(map_fd, &key, &lookup_value);
    if (ret != 0)
    {
        printf("failed lookup map key %d ret %d\n", key, ret);
        return ret;
    }
    printf("lookup map key %d value %d\n", key, lookup_value);
    return 0;
}
int connect_to_remote(const char *addr, uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct hostent *addr_name = gethostbyname(addr);
    struct sockaddr_in addr_in;
    bzero(&addr_in, sizeof(struct sockaddr_in));
    addr_in.sin_family = AF_INET;
    addr_in.sin_port = htons(port);
    addr_in.sin_addr = *((struct in_addr *)addr_name->h_addr);
    int ret = connect(fd, (struct sockaddr *)&addr_in, sizeof(struct sockaddr));    // NOLINT
    if (ret != 0)
    {
        printf("failed connect to %s:%d ret %d %s\n", addr, port, ret, strerror(errno));
        return -1;
    }
    return fd;
}
int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;

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

    struct sockmap_bpf *obj = sockmap_bpf__open_and_load();
    if (obj == NULL)
    {
        printf("failed to open and load BPF object\n");
        return 0;
    }
    int sock_map = bpf_map__fd(obj->maps.sock_map);
    if (sock_map < 0)
    {
        printf("failed to open BPF map\n");
        return 0;
    }
    int sock_hash = bpf_map__fd(obj->maps.sock_hash);
    if (sock_hash < 0)
    {
        printf("failed to open BPF map\n");
        return 0;
    }

    int parser_fd = bpf_program__fd(obj->progs.bpf_prog_parser);
    ret = bpf_prog_attach(parser_fd, sock_map, BPF_SK_SKB_STREAM_PARSER, 0);
    if (ret)
    {
        printf("bpf_prog_attach parser failed %d (%s)\n", ret, strerror(errno));
        return -1;
    }

    int verdict_fd = bpf_program__fd(obj->progs.bpf_prog_verdict);
    ret = bpf_prog_attach(verdict_fd, sock_map, BPF_SK_SKB_STREAM_VERDICT, 0);
    if (ret != 0)
    {
        printf("bpf_prog_attach verdict failed %d (%s)\n", ret, strerror(errno));
        return -1;
    }
    // left(1188) <----> proxy <----> right(8811)
    uint16_t left_remote_port = 1188;
    uint16_t right_remote_port = 8811;
    int left_fd = connect_to_remote("127.0.0.1", left_remote_port);
    int right_fd = connect_to_remote("127.0.0.1", right_remote_port);
    assert(left_fd != -1 && right_fd != -1);

    // 在 map_fd 对应的 map 中, 下标为 map_index 的元素的值为 right_fd
    int map_index = 0;
    ret = bpf_map_update_elem(sock_map, &map_index, &left_fd, BPF_ANY);
    assert(ret == 0);
    // 来自 right_remote_port 的数据包
    // map_index = hash_map[right_remote_port];
    // map_fd[map_index]
    ret = update_map_elem(sock_hash, right_remote_port, map_index);
    assert(ret == 0);
    printf("map index %d left fd %d remote port %d\n", map_index, left_fd, left_remote_port);

    map_index = 1;
    ret = bpf_map_update_elem(sock_map, &map_index, &right_fd, BPF_ANY);
    assert(ret == 0);
    // hash fd 对应的 hash map 中, 下标为 port 的元素的值为 map_index
    ret = update_map_elem(sock_hash, left_remote_port, map_index);
    assert(ret == 0);
    printf("map index %d right fd %d remote port %d\n", map_index, right_fd, right_remote_port);

    while (!exiting)
    {
        sleep(1);
    }
    bpf_prog_detach(parser_fd, BPF_SK_SKB_STREAM_PARSER);
    bpf_prog_detach(verdict_fd, BPF_SK_SKB_STREAM_VERDICT);
    sockmap_bpf__destroy(obj);
    return 0;
}
