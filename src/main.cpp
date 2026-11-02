#include <iostream>
#include <string>
#include <iomanip>
#include <csignal>
#include <thread>
#include <bpf/libbpf.h>
#include "monitor.skel.h"
#include "common.h"
#include "app_context.h"
#include "prometheus-exporter.h"

static AppContext& app_ctx = AppContext::get();

void err_handler(const std::string err_log) {
    std::cerr << "[ERR]: " << err_log << std::endl;
}

void sig_handler(int sig) {
    app_ctx.keep_running = false;
}


void console_log (bool ExecTrueOpenFalse, const std::string& action, unsigned int pid, unsigned int uid, std::string_view path, std::string_view args) {
    if (ExecTrueOpenFalse)
    std::cout << action
              << " PID: " << std::left << std::setw(6) << pid
              << " UID: " << std::left << std::setw(5) << uid
              << " Path: " << path 
              << " Args: " << args << "\n";
    else {
    std::cout << action
                << " PID: " << std::left << std::setw(6) << pid
                << " UID: " << std::left << std::setw(5) << uid
                << " Path: " << path 
                << " Binary: " << args << "\n";
    }
}


int handle_event(void *ctx, void *data, size_t data_sz) {
    if (data_sz < sizeof(struct event_data)) return 0;

    auto *e = static_cast<struct event_data*>(data);
    // e->comm[TASK_COMM_LEN - 1] = '\0';
    // e->path[MAX_PATH_LEN - 1] = '\0';

    std::string_view path(e->path);

    if ((*e).type == EVENT_EXEC) {
        app_ctx.metrics_exec_total++;
        if (e->uid == 0) {
            app_ctx.metrics_root_actions++;
            console_log(true, "[ROOT EXEC]", e->pid, e->uid, e->path, e->args);
        } else if (path == "/usr/bin/sudo" || path == "/bin/sudo") {
            app_ctx.metrics_sudo_actions++;
            console_log(true, "[SUDO ACTION EXEC]", e->pid, e->uid, e->path, e->args);
        } else {
            // console_log("[EXEC]", e->pid, e->uid, e->comm, e->path);
        }
    }

    else if ((*e).type == EVENT_OPEN) {
        app_ctx.metrics_open_total++;
        if (path == "/etc/shadow" || path == "/etc/sudoers" || path == "/etc/passwd") {
            app_ctx.sensitive_files_opened++;
            console_log(false, "[SENSITIVE FILE OPEN]", e->pid, e->uid, e->path, e->args);
        } else if (e->uid == 0) {
            app_ctx.metrics_root_actions++;
            console_log(false, "[ROOT OPEN]", e->pid, e->uid, e->path, e->args);
        } else {
            // console_log("[OPEN]", e->pid, e->uid, e->comm, e->path);
        }
    }
    return 0;
}


int main () {
    std::signal(SIGINT, sig_handler);

    std::cout << "Starting eBPF monitoring agent..." << std::endl;

    struct monitor_bpf *skel = nullptr;

    skel = monitor_bpf__open();
    if (!skel) {
        err_handler("Failed to open eBPF skeleton!");
        return 1;
    }

    int err = monitor_bpf__load(skel);
    if (err) {
        err_handler("The verifier rejected the eBPF code!");
        std::cerr << err << std::endl;
        monitor_bpf__destroy(skel);
        return 1;
    }

    err = monitor_bpf__attach(skel);
    if (err) {
        err_handler("Failed to attach the eBPF program to the hook!");
        monitor_bpf__destroy(skel);
        return 1;
    }

    struct ring_buffer *rb = nullptr;
    rb = ring_buffer__new(bpf_map__fd((*skel).maps.rb), handle_event, nullptr, nullptr);
    if (!rb) {
        std::cerr << "Failed to initialize user-space Ring Buffer" << std::endl;
        monitor_bpf__destroy(skel);
        return 1;
    }

    std::thread server_thr(prometheus_endpoint);

    std::cout << "The eBPF program has been successfully loaded into the kernel and the Prometheus exporter was started on port " << app_ctx.PORT << std::endl;


    while (app_ctx.keep_running) {
        int err = ring_buffer__poll(rb, 100);

        if (err == -EINTR) {
            break;
        }
        if (err < 0) {
            std::cerr << "Error polling ring buffer: " << err << std::endl;
            break;
        }
    }

    std::cout << "Unloading the eBPF program from the kernel and shutting down the Prometheus exporter.." << std::endl;
    server_thr.join();

    monitor_bpf__destroy(skel);
    ring_buffer__free(rb);

    std::cout << "eBPF program was successfully unloaded from the kernel, and the Prometheus exporter was stopped.." << std::endl;

    return 0;
}