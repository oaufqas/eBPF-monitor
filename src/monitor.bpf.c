#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

#define MAX_ARG_LOOP 10

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");


SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    u32 uid = (u32)bpf_get_current_uid_gid();

    struct event_data *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) return 0;

    (*e).pid = bpf_get_current_pid_tgid() >> 32;
    (*e).uid = uid;
    (*e).type = EVENT_EXEC;

    const char *filename_ptr = (const char *)ctx->args[0];
    bpf_probe_read_user_str((*e).path, sizeof(e->path), filename_ptr);


    const char **argv_base = (const char **)ctx->args[1];
    u32 offset = 0;

    char tmp[MAX_ARGS_LEN];
    
    #pragma unroll
    for (u32 i = 1; i < MAX_ARG_LOOP; i++) {
        const char *arg_ptr = NULL;

        long err = bpf_probe_read_user(&arg_ptr, sizeof(arg_ptr), argv_base + i);

        if (arg_ptr == NULL || offset > MAX_ARGS_LEN - 2) break;
        if (offset >= sizeof(e->args) - 1) break;

        long bytes = bpf_probe_read_user_str(tmp, sizeof(tmp), arg_ptr);

        if (bytes <= 0) break;

        u32 n = bytes - 1;
        if (n == 0) continue;

        if (offset > 0 && offset < sizeof(e->args) - 1) {
            e->args[offset++] = ' ';
        }

        #pragma unroll
        for (u32 j = 0; j < MAX_ARGS_LEN; j++) {
            if (j < n && offset < sizeof(e->args) - 1) e->args[offset++] = tmp[j];
        }
    }

    if (offset == 0) {
        __builtin_memcpy((*e).args, "none", 5); 
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int handle_openat(void *ctx) {
    u32 uid = (u32)bpf_get_current_uid_gid();

    struct trace_event_raw_sys_enter *args = ctx;
    const char *filename_ptr = (const char *)(*args).args[1];

    char path_check[MAX_PATH_LEN] = {};
    bpf_probe_read_user_str(path_check, sizeof(path_check), filename_ptr);

    if (path_check[0] == '\0') {
        return 0;
    }

    if (path_check[0] == '/' && path_check[1] == 'u' &&
        path_check[2] == 's' && path_check[3] == 'r' &&
        (path_check[9] == 'l' || path_check[11] == 'l') &&
        (path_check[10] == 'o' || path_check[12] == 'o') &&
        (path_check[11] == 'c' || path_check[13] == 'c')) {
        return 0;
    }

    if (uid == 0) {
        if (!(path_check[0] == '/' && path_check[1] == 'e' && path_check[2] == 't' && path_check[3] == 'c')) {
            return 0;
        }
    }

    struct event_data *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    bpf_get_current_comm((*e).args, sizeof((*e).args));

    (*e).pid = bpf_get_current_pid_tgid() >> 32;
    (*e).uid = uid;
    (*e).type = EVENT_OPEN;
    
    #pragma unroll
    for (int i = 0; i < MAX_PATH_LEN; i++) {
        (*e).path[i] = path_check[i];
        if (path_check[i] == '\0') break;
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}