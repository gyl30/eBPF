#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <stdio.h>
#include <assert.h>
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
    ret = bpf_map_update_elem(map_fd, &left_remote_port, &right_fd, BPF_ANY);
    assert(ret == 0);
    ret = bpf_map_update_elem(map_fd, &right_remote_port, &left_fd, BPF_ANY);
    assert(ret == 0);
    while (1)
    {
        sleep(1);
    }
    sockmap_bpf__destroy(obj);
    return 0;
}
