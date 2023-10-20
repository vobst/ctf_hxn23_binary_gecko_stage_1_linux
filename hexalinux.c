#include <stdio.h>
#include <unistd.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>

#include <bpf/bpf.h>

#include "hexalinux.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args)
{
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    struct hexalinux_bpf *skel = NULL;
    int err = 0;

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    skel = hexalinux_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    err = hexalinux_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    err = hexalinux_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    err =
        bpf_link__pin(skel->links.tp_sys_enter_write, "/sys/fs/bpf/hexalinux");
    if (err) {
        fprintf(stderr, "Failed to pin BPF link (%d)\n", err);
        goto cleanup;
    }

    return 0;

cleanup:
    hexalinux_bpf__destroy(skel);
    return -err;
}
