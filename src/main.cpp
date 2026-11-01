#include <iostream>
#include <iomanip>
#include <chrono>
#include <sstream>
#include "httplib.h"
#include "rule_engine.hpp"
#include "url_utils.hpp"

// 取得當前時間字串
std::string current_time() {
    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

int main(int argc, char* argv[]) {
    // 預設監聽埠口
    int port = 8080;
    if (argc > 1) {
        port = std::stoi(argv[1]);
    }

    httplib::Server svr;
    waf::RuleEngine engine;

    std::cout << "======================================================\n";
    std::cout << "       [WAF 防火牆核心原型 (C++ Prototype)]           \n";
    std::cout << "       - 運作模式: Layer 7 應用層安全檢查             \n";
    std::cout << "       - 防護範圍: SQLi / XSS / Path Traversal / Cmd  \n";
    std::cout << "======================================================\n";
    std::cout << "[INFO] WAF 服務正在啟動，監聽埠口: " << port << " ...\n";
    std::cout << "[INFO] 您可以使用瀏覽器或 curl 測試: http://localhost:" << port << "\n\n";

    auto block_response = [&](const httplib::Request& req, httplib::Response& res, const waf::InspectionResult& check) {
        std::cout << "\033[1;31m[" << current_time() << "] [BLOCKED] "
                  << "Method: " << req.method << " | "
                  << "Path: " << req.path << " | "
                  << "Attack: " << check.attack_type << " (" << check.matched_rule << ") | "
                  << "Location: " << check.source_location << " | "
                  << "Payload: \"" << check.matched_payload << "\"\033[0m\n";

        res.status = 403;
        res.set_content(
            "{\n"
            "  \"status\": 403,\n"
            "  \"error\": \"Access Denied by WAF\",\n"
            "  \"attack_type\": \"" + check.attack_type + "\",\n"
            "  \"matched_rule\": \"" + check.matched_rule + "\",\n"
            "  \"location\": \"" + check.source_location + "\"\n"
            "}\n",
            "application/json"
        );
    };

    // 使用 set_pre_routing_handler 攔截所有進來的 HTTP Request (檢測 URI、Path、Headers)
    svr.set_pre_routing_handler([&](const httplib::Request& req, httplib::Response& res) {
        auto check = engine.inspect_request(req);

        if (check.is_blocked) {
            block_response(req, res, check);
            return httplib::Server::HandlerResponse::Handled;
        }

        return httplib::Server::HandlerResponse::Unhandled;
    });

    // 預設模擬端點 (用於第一周測試，日後可替換為反向代理轉發給後端伺服器)
    svr.Get(".*", [](const httplib::Request& req, httplib::Response& res) {
        std::cout << "\033[1;32m[" << current_time() << "] [PASSED]  "
                  << "Method: " << req.method << " | "
                  << "Path: " << req.path << "\033[0m\n";

        res.set_content(
            "{\n"
            "  \"status\": 200,\n"
            "  \"message\": \"恭喜！請求通過 WAF 防火牆檢驗 (Pass-Through)\",\n"
            "  \"path\": \"" + req.path + "\"\n"
            "}\n",
            "application/json"
        );
    });

    svr.Post(".*", [&](const httplib::Request& req, httplib::Response& res) {
        // 針對 POST Body 進行深度安全檢測
        auto check = engine.inspect_request(req);
        if (check.is_blocked) {
            block_response(req, res, check);
            return;
        }

        std::cout << "\033[1;32m[" << current_time() << "] [PASSED]  "
                  << "Method: " << req.method << " | "
                  << "Path: " << req.path << " (Body Size: " << req.body.size() << ")\033[0m\n";

        res.set_content(
            "{\n"
            "  \"status\": 200,\n"
            "  \"message\": \"POST 請求通過 WAF 防火牆檢驗 (Pass-Through)\",\n"
            "  \"body_received_length\": " + std::to_string(req.body.size()) + "\n"
            "}\n",
            "application/json"
        );
    });

    // 啟動伺服器 (若繫結失敗則印出錯誤訊息)
    if (!svr.listen("0.0.0.0", port)) {
        std::cerr << "[ERROR] 無法綁定埠口 " << port << "，請確認埠口是否被其他程式占用。\n";
        return 1;
    }

    return 0;
}
