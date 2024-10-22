#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include "sockmap.h"
#include "sockmap.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG)
    {
        return 0;
    }
    return vfprintf(stderr, format, args);
}
int connect_peer(const char *addr, uint16_t port)
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
// 更新 map 中的值
int update_map_elem(int map_fd, int key, int value)
{
    int lookup_value = 0;
    int ret = bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
    if (ret != 0)
    {
        printf("failed update map key %d value %d ret %d\n", key, value, ret);
        return ret;
    }
    printf("update map key %d value %d\n", key, value);
    // ret = bpf_map_lookup_elem(map_fd, &key, &lookup_value);
    // if (ret != 0)
    // {
    //     printf("failed lookup map key %d ret %d\n", key, ret);
    //     return ret;
    // }
    // printf("lookup map key %d value %d\n", key, lookup_value);
    return 0;
}
int setup_proxy_connection(int map_fd, const char *left_addr, uint16_t left_port, const char *right_addr, uint16_t right_port)
{
    // left <----> proxy <----> right
    int left_fd = connect_peer(left_addr, left_port);
    if (left_fd == -1)
    {
        printf("failed connect to %s:%d\n", left_addr, left_port);
        return -1;
    }
    printf("connect to %s:%d fd %d\n", left_addr, left_port, left_fd);
    int right_fd = connect_peer(right_addr, right_port);
    if (right_fd == -1)
    {
        printf("failed connect to %s:%d\n", right_addr, right_port);
        return -1;
    }
    printf("connect to %s:%d fd %d\n", right_addr, right_port, right_fd);
    // 如果数据包的 local port 是 left_port 说明是从 left 发出，需要转发至 right
    int err = update_map_elem(map_fd, left_port, right_fd);
    if (err != 0)
    {
        printf("failed update map lef to right\n");
        return -1;
    }
    printf("update map lef to right port %d fd %d\n", left_port, right_fd);
    // 如果数据包的 local port 是 right_port 说明是从 right 发出，需要转发至 left
    err = update_map_elem(map_fd, right_port, left_fd);
    if (err != 0)
    {
        printf("failed update map right to left\n");
        return -1;
    }
    printf("update map right to left port %d fd %d\n", right_port, left_fd);
    return 0;
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

    struct sockmap_bpf *obj = sockmap_bpf__open_and_load();
    if (obj == NULL)
    {
        printf("failed to open and load BPF object\n");
        return 0;
    }
    int map_fd = bpf_map__fd(obj->maps.sock_map_rx);
    if (map_fd < 0)
    {
        printf("failed to open BPF map\n");
        return 0;
    }

    int parser_fd = bpf_program__fd(obj->progs.bpf_prog_parser);
    ret = bpf_prog_attach(parser_fd, map_fd, BPF_SK_SKB_STREAM_PARSER, 0);
    if (ret)
    {
        printf("bpf_prog_attach parser failed %d (%s)\n", ret, strerror(errno));
        return -1;
    }

    int verdict_fd = bpf_program__fd(obj->progs.bpf_prog_verdict);
    ret = bpf_prog_attach(verdict_fd, map_fd, BPF_SK_SKB_STREAM_VERDICT, 0);
    if (ret)
    {
        printf("bpf_prog_attach verdict failed %d (%s)\n", ret, strerror(errno));
        return -1;
    }
    // left(1188) <----> proxy <----> right(8811)
    ret = setup_proxy_connection(map_fd, "127.0.0.1", 1188, "127.0.0.1", 8811);
    if (ret != 0)
    {
        printf("setup_proxy_connection failed\n");
        return -1;
    }
    while (1)
    {
        sleep(1);
    }
    sockmap_bpf__destroy(obj);
    return 0;
}
