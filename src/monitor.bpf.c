#include "../vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";


SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(void *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    bpf_trace_printk("Hello from Kernel! Process launched, PID: %d\n", pid);

    return 0;
}