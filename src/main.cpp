#include <iostream>
#include <string>
#include <iomanip>
#include <csignal>
#include <unistd.h>
#include <bpf/libbpf.h>
#include "monitor.skel.h"
#include "common.h"

static volatile bool keep_running = true;

void err_handler(const std::string err_log) {
    std::cerr << "[ERR]: " << err_log << std::endl;
}

void sig_handler(int sig) {
    keep_running = false;
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
    if (data_sz < sizeof(struct event_data)) {
        std::cerr << "Received corrupted data block (too small)" << std::endl;
        return 0;
    }

    auto *e = static_cast<struct event_data *>(data);

    if ((*e).type == EVENT_EXEC) {
        std::cout << "[EXEC] "
                  << "PID: " << std::left << std::setw(6) << e->pid 
                  << " | UID: " << std::left << std::setw(5) << e->uid
                  << " | Comm: "  << e->comm 
                  << " | Binary: " << e->path << "\n";
    }
    else if (e->type == EVENT_OPEN) {
        std::cout << "[OPEN] "
                  << "PID: " << std::left << std::setw(6) << e->pid 
                  << " | UID: " << std::left << std::setw(5) << e->uid
                  << " | Comm: " << e->comm 
                  << " | File: " << e->path << "\n";
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

    std::cout << "The eBPF program has been successfully loaded into the kernel and is active." << std::endl;

    while (keep_running) {
        int err = ring_buffer__poll(rb, 100);

        if (err == -EINTR) {
            break;
        }
        if (err < 0) {
            std::cerr << "Error polling ring buffer: " << err << std::endl;
            break;
        }
    }

    std::cout << "Unloading the eBPF program from the kernel and shutting down..." << std::endl;
    monitor_bpf__destroy(skel);
    ring_buffer__free(rb);

    return 0;
}