#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");


SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(void *ctx) {
    u32 uid = (u32)bpf_get_current_uid_gid();

    struct event_data *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (!e) {
        return 0;
    }

    (*e).pid = bpf_get_current_pid_tgid() >> 32;
    (*e).uid = uid;
    (*e).type = EVENT_EXEC;

    bpf_get_current_comm((*e).comm, sizeof((*e).comm));

    struct trace_event_raw_sys_enter *args = ctx;
    const char *filename_ptr = (const char *)(*args).args[0];
    bpf_probe_read_user_str((*e).path, sizeof((*e).path), filename_ptr);

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

    bpf_get_current_comm((*e).comm, sizeof((*e).comm));

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