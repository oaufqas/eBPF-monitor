#include <iostream>
#include <string>
#include <vector>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include "app_context.h"

AppContext& app_ctx = AppContext::get();


static void export_metrics(int fd, int epoll_fd) {
    char buf[1024];
    int bytes = recv(fd, buf, sizeof(buf)-1, 0);

    std::string body = 
        "# HELP " + std::string(MetricsName::exec_process) + " Total number of process executions caught by eBPF.\n"
        "# TYPE " + std::string(MetricsName::exec_process) + " counter\n" +
        std::string(MetricsName::exec_process) + " " + std::to_string(app_ctx.metrics_exec_total.load()) + "\n\n"
        
        "# HELP " + std::string(MetricsName::open_files) + " Total number of file openings caught by eBPF.\n"
        "# TYPE " + std::string(MetricsName::open_files) + " counter\n" +
        std::string(MetricsName::open_files) + " " + std::to_string(app_ctx.metrics_open_total.load()) + "\n\n"
        
        "# HELP " + std::string(MetricsName::sudo_actions) + " Total number of critical sudo invocations.\n"
        "# TYPE " + std::string(MetricsName::sudo_actions) + " counter\n" +
        std::string(MetricsName::sudo_actions) + " " + std::to_string(app_ctx.metrics_sudo_actions.load()) + "\n\n"
        
        "# HELP " + std::string(MetricsName::root_actions) + " Total number of actions performed by UID 0.\n"
        "# TYPE " + std::string(MetricsName::root_actions) + " counter\n" +
        std::string(MetricsName::root_actions) + " " + std::to_string(app_ctx.metrics_root_actions.load()) + "\n\n"

        "# HELP " + std::string(MetricsName::sensitive_files) + " Total number of open sensetive files.\n"
        "# TYPE " + std::string(MetricsName::sensitive_files) + " counter\n" +
        std::string(MetricsName::sensitive_files) + " " + std::to_string(app_ctx.sensitive_files_opened.load()) + "\n";

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
    addr.sin_port = htons(app_ctx.PORT);
    addr.sin_addr.s_addr = htonl(app_ctx.ADDR);

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

    while (app_ctx.keep_running) {
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