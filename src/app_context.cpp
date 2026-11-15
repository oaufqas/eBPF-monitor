#include "app_context.h"
#include <fstream>
#include <sstream>
#include <cctype>
#include <algorithm>
#include <iostream>
#include <unistd.h>
#include <limits.h>
#include <filesystem>

static std::string parse_args(int argc, char** argv) {
    std::string config_path;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--config") {
            if (i + 1 >= argc) {
                std::cerr << "--config requires a path\n";
                std::exit(1);
            }
            config_path = argv[i+1];
            i++;
        } else {
            std::cerr << "Unknown argument '" << arg << "'\n";
            std::exit(1);
        }
    }
    return config_path;
}


static std::string exe_dir() {
    char buf[PATH_MAX];
    ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
    if (n < 0) {
        return ".";
    }
    buf[n] = '\0';

    std::string path(buf);
    auto pos = path.find_last_of('/');
    if (pos == std::string::npos) return ".";
    return path.substr(0, pos);
}


static std::string trim(const std::string& s) {
    auto is_space = [](unsigned char c) { return std::isspace(c); };

    auto begin = s.begin();
    while (begin != s.end() && is_space(*begin)) ++begin;

    auto end = s.end();
    while (end != begin && is_space(*(end - 1))) --end;

    return std::string(begin, end);
}


static bool load_conf_file (AppContext& app_ctx, const std::string& path) {
    std::ifstream in (path);

    if (std::filesystem::is_directory(path) || !std::filesystem::exists(path)) {
        return false;
    } else {
        if (!in.is_open()) return false;
    }

    app_ctx.config_path = path;

    std::string line;
    int line_no = 0;

    while (std::getline(in, line)) {
        line_no++;

        auto hash = line.find('#');
        if (hash != std::string::npos) {
            line.erase(hash);
        }

        line = trim(line);
        if (line.empty()) continue;

        auto eq = line.find('=');
        if (eq == std::string::npos) continue;

        std::string key = trim(line.substr(0, eq));
        std::string value = trim(line.substr(eq + 1));

        if (key == "listen_port") {
            app_ctx.PORT = static_cast<uint16_t>(std::stoul(value));
        } else if (key == "extended_logs") {
            app_ctx.extended_logs = (value == "true" || value == "1");
        // } else if (key == "hooks_strategy") {
        //     app_ctx.hooks_strategy = value;
        // }
        } else {
            std::cerr << "Unknown key '" << key << "' - skipped\n";
        }
    }
    return true;
}





AppContext& AppContext::instance() {
    static AppContext inst;
    return inst;
}


void AppContext::load_config(int argc, char** argv) {
    AppContext& inst = instance();
    std::string path = parse_args(argc, argv);

    if (path.empty()) {
        path = exe_dir() + "/config.conf";
    }

    if (!load_conf_file(inst, path)) {
        std::cerr << "Config file not found at " << path << ", using default settings\n";
    } else {
        std::cerr << "Loaded config from " << path << std::endl;
    }
}