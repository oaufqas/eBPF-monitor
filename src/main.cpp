#include <iostream>
#include <string>
#include <iomanip>
#include <csignal>
#include <thread>
#include <vector>
#include <sys/epoll.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <bpf/libbpf.h>
#include "monitor.skel.h"
#include "common.h"

static const int PORT = 4444;
static const in_addr_t ADDR = INADDR_ANY;
static volatile bool keep_running = true;

void err_handler(const std::string err_log) {
    std::cerr << "[ERR]: " << err_log << std::endl;
}

void sig_handler(int sig) {
    keep_running = false;
}

static std::atomic<uint64_t> metrics_exec_total{0};
static std::atomic<uint64_t> metrics_open_total{0};
static std::atomic<uint64_t> metrics_sudo_actions{0};
static std::atomic<uint64_t> metrics_root_actions{0};
static std::atomic<uint64_t> sensitive_files_opened{0};



void console_log (const std::string& action, unsigned int pid, unsigned int uid, std::string_view comm, std::string_view path) {
    std::cout << action
              << " PID: " << std::left << std::setw(6) << pid
              << " UID: " << std::left << std::setw(5) << uid
              << " Comm: " << comm
              << " Path: " << path << "\n";
}


static int handle_event(void *ctx, void *data, size_t data_sz) {
    if (data_sz < sizeof(struct event_data)) return 0;

    auto *e = static_cast<struct event_data*>(data);
    // e->comm[TASK_COMM_LEN - 1] = '\0';
    // e->path[MAX_PATH_LEN - 1] = '\0';

    std::string_view path(e->path);

    if ((*e).type == EVENT_EXEC) {
        metrics_exec_total++;
        if (e->uid == 0) {
            metrics_root_actions++;
            console_log("[ROOT EXEC]", e->pid, e->uid, e->comm, e->path);
        } else if (path == "/usr/bin/sudo" || path == "/bin/sudo") {
            metrics_sudo_actions++;
            console_log("[SUDO ACTION EXEC]", e->pid, e->uid, e->comm, e->path);
        } else {
            // console_log("[EXEC]", e->pid, e->uid, e->comm, e->path);
        }
    }
    else if ((*e).type == EVENT_OPEN) {
        metrics_open_total++;
        if (path == "/etc/shadow" || path == "/etc/sudoers" || path == "/etc/passwd") {
            sensitive_files_opened++;
            console_log("[SENSITIVE FILE OPEN]", e->pid, e->uid, e->comm, e->path);
        } else if (e->uid == 0) {
            metrics_root_actions++;
            console_log("[ROOT OPEN]", e->pid, e->uid, e->comm, e->path);
        } else {
            // console_log("[OPEN]", e->pid, e->uid, e->comm, e->path);
        }
    }
    return 0;
}

void export_metrics(int fd, int epoll_fd) {
    char buf[1024];
    int bytes = recv(fd, buf, sizeof(buf)-1, 0);

    std::string body = 
        "# HELP ebpf_exec_total Total number of process executions caught by eBPF.\n"
        "# TYPE ebpf_exec_total counter\n"
        "ebpf_exec_total " + std::to_string(metrics_exec_total.load()) + "\n\n"
        
        "# HELP ebpf_open_total Total number of file openings caught by eBPF.\n"
        "# TYPE ebpf_open_total counter\n"
        "ebpf_open_total " + std::to_string(metrics_open_total.load()) + "\n\n"
        
        "# HELP ebpf_security_sudo_alerts_total Total number of critical sudo invocations.\n"
        "# TYPE ebpf_security_sudo_alerts_total counter\n"
        "ebpf_security_sudo_alerts_total " + std::to_string(metrics_sudo_actions.load()) + "\n\n"
        
        "# HELP ebpf_root_actions_total Total number of actions performed by UID 0.\n"
        "# TYPE ebpf_root_actions_total counter\n"
        "ebpf_root_actions_total " + std::to_string(metrics_root_actions.load()) + "\n\n"

        "# HELP ebpf_sensitive_file_opened Total number of open sensetive files.\n"
        "# TYPE ebpf_sensitive_file_opened counter\n"
        "ebpf_sensitive_file_opened " + std::to_string(sensitive_files_opened.load()) + "\n";

    std::string response = 
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
        "Content-Length: " + std::to_string(body.length()) + "\r\n"
        "Connection: close\r\n\r\n" + body;

    send(fd, response.c_str(), response.length(), 0);
    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
    close(fd);
}


void prometheus_endpoint () {
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = htonl(ADDR);

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { perror("create socket"); }

    int opt = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    int res = bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    if (res < 0) { perror("bind socket"); }
    
    res = listen(fd, SOMAXCONN);
    if (res < 0) { perror("listen socket"); }

    int epoll_fd = epoll_create1(0);
    epoll_event ev{};
    ev.events = EPOLLIN | EPOLLRDHUP;
    ev.data.fd = fd;

    epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &ev);
    
    std::vector<struct epoll_event> ready_events(100);

    while (keep_running) {
        int num_fd = epoll_wait(epoll_fd, ready_events.data(), ready_events.size(), 100);
        if (num_fd < 0) { perror("epoll wait"); break; }

        for (int i = 0; i < num_fd; i++){
            int current_fd = ready_events[i].data.fd;
            if (current_fd == fd) {
                sockaddr_in client_addr{};
                socklen_t client_len = sizeof(client_addr);

                int client_fd = accept(fd, reinterpret_cast<sockaddr*>(&client_addr), &client_len);
                if (client_fd < 0) { perror("accept client"); continue; }

                epoll_event client_ev{};
                client_ev.events = EPOLLIN | EPOLLRDHUP;
                client_ev.data.fd = client_fd;

                res = epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &client_ev);
                if (res == -1) { perror("epoll_ctl add"); close(client_fd); continue; }

                std::cout << "Prometheus connected.." << std::endl;
            } else {
                if (ready_events[i].events & (EPOLLRDHUP | EPOLLHUP | EPOLLERR)) {
                    std::cout << "Prometheus disconnected..";
                    epoll_ctl(epoll_fd, EPOLL_CTL_DEL, current_fd, nullptr);
                    close(current_fd);
                }
                else if (ready_events[i].events & EPOLLIN) {
                    export_metrics(current_fd, epoll_fd);
                }
            }
        }
    }
    close(fd);
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

    std::cout << "The eBPF program has been successfully loaded into the kernel and the Prometheus exporter was started on port " << PORT << std::endl;


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

    std::cout << "Unloading the eBPF program from the kernel and shutting down the Prometheus exporter.." << std::endl;
    server_thr.join();

    monitor_bpf__destroy(skel);
    ring_buffer__free(rb);

    std::cout << "eBPF program was successfully unloaded from the kernel, and the Prometheus exporter was stopped.." << std::endl;

    return 0;
}