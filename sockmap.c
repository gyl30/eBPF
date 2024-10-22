#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <stdio.h>
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
static int handle_event(void *ctx, void *data, size_t data_size)
{
    (void)ctx;
    (void)data_size;
    const struct event *e = data;
    if (data != NULL)
    {
        printf("op %d key %d value %d\n", e->op, e->key, e->value);
    }
    return 0;
}
// 更新 map 中的值
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
    int rx_hash_fd = bpf_map__fd(obj->maps.sock_map_rx);
    if (rx_hash_fd < 0)
    {
        printf("failed to open BPF map\n");
        return 0;
    }

    ret = sockmap_bpf__attach(obj);
    if (ret < 0)
    {
        printf("failed to attach BPF object\n");
        return 0;
    }

    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(obj->maps.rb), handle_event, NULL, NULL);
    if (!rb)
    {
        fprintf(stderr, "failed to create ring buffer\n");
        return 0;
    }
    int i = 0;
    while (1)
    {
        int err = ring_buffer__poll(rb, 1000);
        if (err == -EINTR)
        {
            err = 0;
            break;
        }
        if (err < 0)
        {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
        if (i == 10)
        {
            i = 0;
        }
        update_map_elem(rx_hash_fd, i, i + 1);
        i++;
    }
    ring_buffer__free(rb);
    sockmap_bpf__destroy(obj);
    return 0;
}
