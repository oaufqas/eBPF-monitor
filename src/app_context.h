#pragma once
#include <string>
#include <atomic>
#include <netinet/in.h>

struct AppContext {
    volatile bool keep_running = true;
    const bool extended_logs = false;

    const int PORT = 4444;
    const in_addr_t ADDR = INADDR_ANY;

    std::atomic<uint64_t> metrics_exec_total{0};
    std::atomic<uint64_t> metrics_open_total{0};
    std::atomic<uint64_t> metrics_sudo_actions{0};
    std::atomic<uint64_t> metrics_root_actions{0};
    std::atomic<uint64_t> sensitive_files_opened{0};

    static AppContext& get();

private:
    AppContext() = default;
};

struct MetricsName {
    static constexpr std::string_view exec_process = "ebpf_exec_total";
    static constexpr std::string_view open_files = "ebpf_open_files_total";
    static constexpr std::string_view root_actions = "ebpf_root_actions_total";
    static constexpr std::string_view sudo_actions = "ebpf_security_sudo_alerts_total";
    static constexpr std::string_view sensitive_files = "ebpf_sensitive_files_open_total";
private:
    MetricsName() = default;
};