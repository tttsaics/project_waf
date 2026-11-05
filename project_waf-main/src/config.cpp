#include "config.hpp"
#include "json.hpp"
#include <fstream>
#include <iostream>

using json = nlohmann::json;

namespace waf {

WafConfig load_config(const std::string& config_file_path) {
    WafConfig config;
    std::ifstream file(config_file_path);
    if (!file.is_open()) {
        std::cout << "[CONFIG] 未找到設定檔 " << config_file_path << "，將使用預設安全配置。\n";
        return config;
    }

    try {
        json j;
        file >> j;

        if (j.contains("server")) {
            auto& s = j["server"];
            if (s.contains("port") && s["port"].is_number()) config.port = s["port"].get<int>();
            if (s.contains("host") && s["host"].is_string()) config.host = s["host"].get<std::string>();
            if (s.contains("mode") && s["mode"].is_string()) config.mode = s["mode"].get<std::string>();
        }

        if (j.contains("backend")) {
            auto& b = j["backend"];
            if (b.contains("host") && b["host"].is_string()) config.backend_host = b["host"].get<std::string>();
            if (b.contains("port") && b["port"].is_number()) config.backend_port = b["port"].get<int>();
        }

        if (j.contains("security")) {
            auto& sec = j["security"];
            if (sec.contains("anomaly_threshold") && sec["anomaly_threshold"].is_number()) {
                config.anomaly_threshold = sec["anomaly_threshold"].get<int>();
            }
            if (sec.contains("custom_rules_file") && sec["custom_rules_file"].is_string()) {
                config.custom_rules_file = sec["custom_rules_file"].get<std::string>();
            }
        }

        if (j.contains("rate_limit")) {
            auto& r = j["rate_limit"];
            if (r.contains("enabled") && r["enabled"].is_boolean()) {
                config.rate_limit_enabled = r["enabled"].get<bool>();
            }
            if (r.contains("max_requests") && r["max_requests"].is_number()) {
                config.rate_limit_requests = r["max_requests"].get<int>();
            }
            if (r.contains("window_seconds") && r["window_seconds"].is_number()) {
                config.rate_limit_window_sec = r["window_seconds"].get<int>();
            }
        }

        std::cout << "[CONFIG] 成功載入設定檔: " << config_file_path << " (模式: " << config.mode << ")\n";
    } catch (const std::exception& e) {
        std::cerr << "[CONFIG] 解析設定檔失敗 (" << e.what() << ")，改用預設安全設定。\n";
    }

    return config;
}

bool save_default_config(const std::string& config_file_path) {
    json j = {
        {"server", {
            {"host", "0.0.0.0"},
            {"port", 8080},
            {"mode", "standalone"} // "standalone" 或 "proxy"
        }},
        {"backend", {
            {"host", "127.0.0.1"},
            {"port", 3000}
        }},
        {"security", {
            {"anomaly_threshold", 5},
            {"custom_rules_file", "config/waf_rules.json"}
        }},
        {"rate_limit", {
            {"enabled", true},
            {"max_requests", 60},
            {"window_seconds", 10}
        }}
    };

    std::ofstream file(config_file_path);
    if (!file.is_open()) return false;
    file << j.dump(4);
    return true;
}

} // namespace waf
