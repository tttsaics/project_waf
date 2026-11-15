#include <iostream>
#include <iomanip>
#include <chrono>
#include <sstream>
#include <atomic>
#include <random>
#include <filesystem>
#include "httplib.h"
#include "rule_engine.hpp"
#include "url_utils.hpp"
#include "rate_limiter.hpp"
#include "proxy_handler.hpp"
#include "config.hpp"
#include "json.hpp"

// 時間格式化工具
std::string current_time() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

// 產生安全且唯一的 Request-ID (含時間戳與原子計數器)
std::string generate_request_id() {
    static std::atomic<uint64_t> counter{1000};
    auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    std::stringstream ss;
    ss << "req-" << now_ms << "-" << counter.fetch_add(1);
    return ss.str();
}

int main(int argc, char* argv[]) {
    // 1. 載入配置設定
    std::string config_path = "config/waf_config.json";
    if (!std::filesystem::exists("config")) {
        std::filesystem::create_directory("config");
    }
    if (!std::filesystem::exists(config_path)) {
        waf::save_default_config(config_path);
    }
    waf::WafConfig config = waf::load_config(config_path);

    // 支援命令列參數覆蓋
    if (argc > 1) {
        config.port = std::stoi(argv[1]);
    }
    if (argc > 2) {
        config.mode = argv[2]; // "standalone" 或 "proxy"
    }

    httplib::Server svr;
    waf::RuleEngine engine(config.anomaly_threshold);
    waf::RateLimiter rate_limiter(config.rate_limit_enabled, config.rate_limit_requests, config.rate_limit_window_sec);
    waf::ProxyHandler proxy(config.backend_host, config.backend_port);

    // 若有自訂規則檔則嘗試載入
    if (!config.custom_rules_file.empty() && std::filesystem::exists(config.custom_rules_file)) {
        engine.load_rules_from_file(config.custom_rules_file);
    }

    std::cout << "======================================================\n";
    std::cout << "     [進階企業級 WAF 防火牆核心 (Enhanced WAF Core)]   \n";
    std::cout << "  - 運作模式: " << (config.mode == "proxy" ? "反向代理 (Reverse Proxy)" : "單機獨立模式 (Standalone)") << "\n";
    std::cout << "  - 監聽介面: " << config.host << ":" << config.port << "\n";
    if (config.mode == "proxy") {
        std::cout << "  - 後端轉發: http://" << config.backend_host << ":" << config.backend_port << "\n";
    }
    std::cout << "  - 異常評分閥值 (Anomaly Threshold): " << config.anomaly_threshold << "\n";
    std::cout << "  - 頻率限制 (Rate Limiting): " << (config.rate_limit_enabled ? "已啟用 (" + std::to_string(config.rate_limit_requests) + " reqs / " + std::to_string(config.rate_limit_window_sec) + "s)" : "已停用") << "\n";
    std::cout << "  - 雙重 URL 編碼與特殊字元規範化: 已啟用\n";
    std::cout << "  - 敏感特徵隱藏 (零資訊洩漏 403 回應): 已啟用\n";
    std::cout << "======================================================\n\n";

    // 安全阻擋回應：對客戶端僅回傳 Request-ID，隱藏正則表達式與攻擊特徵，防止探測
    auto block_response = [&](const httplib::Request& req, httplib::Response& res, const waf::InspectionResult& check, const std::string& req_id) {
        std::string client_ip = req.remote_addr.empty() ? "127.0.0.1" : req.remote_addr;

        // 伺服器內部終端機記錄詳細審計日誌
        std::cout << "\033[1;31m[" << current_time() << "] [BLOCKED] "
                  << "ReqID: " << req_id << " | "
                  << "Client: " << client_ip << " | "
                  << "Method: " << req.method << " | "
                  << "Path: " << req.path << " | "
                  << "Attack: " << check.primary_attack_type << " | "
                  << "Score: " << check.total_score << "/" << engine.get_anomaly_threshold() << " | ";
        
        if (!check.matches.empty()) {
            std::cout << "Trigger: " << check.matches[0].rule_name << " (" << check.matches[0].source_location << ") | "
                      << "Payload: \"" << check.matches[0].matched_payload << "\"";
        }
        std::cout << "\033[0m\n";

        // 對外客戶端回應 (不洩露任何規則細節與 Payload)
        res.status = 403;
        res.set_header("X-Request-ID", req_id);
        res.set_content(
            "{\n"
            "  \"status\": 403,\n"
            "  \"error\": \"Access Denied by WAF\",\n"
            "  \"message\": \"您的請求違反安全策略已被攔截\",\n"
            "  \"request_id\": \"" + req_id + "\"\n"
            "}\n",
            "application/json"
        );
    };

    // Pre-Routing 統一過濾處理器
    svr.set_pre_routing_handler([&](const httplib::Request& req, httplib::Response& res) {
        std::string req_id = generate_request_id();
        res.set_header("X-Request-ID", req_id);

        std::string client_ip = req.remote_addr.empty() ? "127.0.0.1" : req.remote_addr;

        // 1. IP 頻率限制 (Rate Limiting)
        if (!rate_limiter.is_allowed(client_ip)) {
            std::cout << "\033[1;33m[" << current_time() << "] [RATE_LIMIT] "
                      << "ReqID: " << req_id << " | "
                      << "Client: " << client_ip << " | "
                      << "Path: " << req.path << " - 429 Too Many Requests\033[0m\n";

            res.status = 429;
            res.set_header("Retry-After", std::to_string(config.rate_limit_window_sec));
            res.set_content(
                "{\n"
                "  \"status\": 429,\n"
                "  \"error\": \"Too Many Requests\",\n"
                "  \"message\": \"請求過於頻繁，已被防火牆限流攔截\",\n"
                "  \"request_id\": \"" + req_id + "\"\n"
                "}\n",
                "application/json"
            );
            return httplib::Server::HandlerResponse::Handled;
        }

        // 2. 線上熱重載端點 (管理用途: POST /waf/admin/reload)
        if (req.method == "POST" && req.path == "/waf/admin/reload") {
            config = waf::load_config(config_path);
            engine.set_anomaly_threshold(config.anomaly_threshold);
            engine.init_default_rules();
            if (!config.custom_rules_file.empty() && std::filesystem::exists(config.custom_rules_file)) {
                engine.load_rules_from_file(config.custom_rules_file);
            }
            rate_limiter.update_config(config.rate_limit_enabled, config.rate_limit_requests, config.rate_limit_window_sec);
            proxy.set_backend(config.backend_host, config.backend_port);

            std::cout << "\033[1;34m[" << current_time() << "] [ADMIN] 成功熱重載 WAF 設定與規則庫\033[0m\n";

            res.status = 200;
            res.set_content(
                "{\n"
                "  \"status\": 200,\n"
                "  \"message\": \"WAF 配置與規則庫已成功熱重載\",\n"
                "  \"anomaly_threshold\": " + std::to_string(config.anomaly_threshold) + ",\n"
                "  \"mode\": \"" + config.mode + "\"\n"
                "}\n",
                "application/json"
            );
            return httplib::Server::HandlerResponse::Handled;
        }

        // 3. 核心安全檢驗 (檢查 Path, Query, Headers)
        auto check = engine.inspect_request(req);
        if (check.is_blocked) {
            block_response(req, res, check, req_id);
            return httplib::Server::HandlerResponse::Handled;
        }

        // 檢查通過，交由後續路由分發
        return httplib::Server::HandlerResponse::Unhandled;
    });

    // 統一路由分發器 (支援 Body 檢測、Proxy 轉發與 Standalone 模擬端點)
    auto handle_passed_request = [&](const httplib::Request& req, httplib::Response& res) {
        std::string req_id = res.has_header("X-Request-ID") ? res.get_header_value("X-Request-ID") : generate_request_id();

        // 4. 針對含 Body 的請求 (POST/PUT/PATCH 等) 進行 Body 安全檢驗
        if (!req.body.empty()) {
            waf::InspectionResult body_check;
            engine.inspect_string(req.body, "Body", body_check);
            if (body_check.total_score >= engine.get_anomaly_threshold()) {
                body_check.is_blocked = true;
                block_response(req, res, body_check, req_id);
                return;
            }
        }

        std::cout << "\033[1;32m[" << current_time() << "] [PASSED]  "
                  << "ReqID: " << req_id << " | "
                  << "Method: " << req.method << " | "
                  << "Path: " << req.path << " (Body: " << req.body.size() << " bytes)\033[0m\n";

        if (config.mode == "proxy") {
            proxy.forward_request(req, res, req_id);
        } else {
            // Standalone 原型模式
            res.status = 200;
            res.set_content(
                "{\n"
                "  \"status\": 200,\n"
                "  \"message\": \"恭喜！請求通過 WAF 防火牆檢驗 (Pass-Through)\",\n"
                "  \"method\": \"" + req.method + "\",\n"
                "  \"path\": \"" + req.path + "\",\n"
                "  \"request_id\": \"" + req_id + "\"\n"
                "}\n",
                "application/json"
            );
        }
    };

    // 完整註冊所有標準 HTTP 方法 (GET, POST, PUT, DELETE, PATCH, OPTIONS)
    svr.Get(".*", handle_passed_request);
    svr.Post(".*", handle_passed_request);
    svr.Put(".*", handle_passed_request);
    svr.Delete(".*", handle_passed_request);
    svr.Patch(".*", handle_passed_request);
    svr.Options(".*", handle_passed_request);

    // 啟動伺服器
    if (!svr.listen(config.host.c_str(), config.port)) {
        std::cerr << "[ERROR] 無法綁定 " << config.host << ":" << config.port << "，請確認埠口是否被其他程式占用。\n";
        return 1;
    }

    return 0;
}
