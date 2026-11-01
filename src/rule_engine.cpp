#include "rule_engine.hpp"
#include "url_utils.hpp"
#include <iostream>

namespace waf {

RuleEngine::RuleEngine() {
    init_rules();
}

void RuleEngine::init_rules() {
    // 1. SQL Injection 規則
    // 比對常見 SQL 關鍵字組合、聯合查詢、布林盲注、註解符號
    rules_.push_back({
        "SQLi",
        "SQLi-Union-Select",
        std::regex(R"(\bunion\b\s+(\ball\b\s+)?\bselect\b)", std::regex_constants::icase)
    });

    rules_.push_back({
        "SQLi",
        "SQLi-Tautology-Or",
        std::regex(R"(\b(or|and)\b\s+('|\")?([a-zA-Z0-9_]+)('|\")?\s*=\s*\2\3)", std::regex_constants::icase)
    });

    rules_.push_back({
        "SQLi",
        "SQLi-Stacked-Commands",
        std::regex(R"(;\s*(drop|insert|update|delete|create|alter|truncate)\b)", std::regex_constants::icase)
    });

    rules_.push_back({
        "SQLi",
        "SQLi-Inline-Comment",
        std::regex(R"((--|/\*|#))", std::regex_constants::icase)
    });

    // 2. Cross-Site Scripting (XSS) 規則
    // 比對 script 標籤、偽協議、事件處理屬性、可疑函式呼叫
    rules_.push_back({
        "XSS",
        "XSS-Script-Tag",
        std::regex(R"(<\s*script\b[^>]*>)", std::regex_constants::icase)
    });

    rules_.push_back({
        "XSS",
        "XSS-Javascript-URI",
        std::regex(R"(javascript\s*:\s*[\w\W]+)", std::regex_constants::icase)
    });

    rules_.push_back({
        "XSS",
        "XSS-Event-Handler",
        std::regex(R"(\bon(error|load|click|mouseover|focus|submit)\s*=)", std::regex_constants::icase)
    });

    rules_.push_back({
        "XSS",
        "XSS-Common-Payloads",
        std::regex(R"(\b(alert|prompt|confirm|eval)\s*\([^)]*\))", std::regex_constants::icase)
    });

    // 3. Path Traversal (路徑穿越) 規則
    // 比對目錄遍歷符號與敏感系統檔案
    rules_.push_back({
        "PathTraversal",
        "Traversal-Dots",
        std::regex(R"((\.\./|\.\.\\))", std::regex_constants::icase)
    });

    rules_.push_back({
        "PathTraversal",
        "Traversal-System-Files",
        std::regex(R"((\/etc\/(passwd|shadow)|windows\/(win\.ini|system32)))", std::regex_constants::icase)
    });

    // 4. Command Injection (系統指令注入) 規則
    // 比對管道符號、分號串接系統指令
    rules_.push_back({
        "CmdInjection",
        "Cmd-Chaining",
        std::regex(R"((;|\||`|\$\()\s*(cat|ls|dir|whoami|id|bash|sh|cmd|powershell)\b)", std::regex_constants::icase)
    });
}

InspectionResult RuleEngine::inspect_string(const std::string& input, const std::string& location) {
    if (input.empty()) {
        return InspectionResult{};
    }

    // 先進行 URL 解碼，避免以 %27、%3C 等編碼手法繞過
    std::string decoded = url_decode(input);

    for (const auto& rule : rules_) {
        std::smatch match;
        if (std::regex_search(decoded, match, rule.pattern)) {
            InspectionResult res;
            res.is_blocked = true;
            res.attack_type = rule.attack_type;
            res.matched_rule = rule.rule_name;
            res.matched_payload = match.str();
            res.source_location = location;
            return res;
        }
    }

    return InspectionResult{};
}

InspectionResult RuleEngine::inspect_request(const httplib::Request& req) {
    // 1. 檢查完整請求目標 (包含 Path 與 Query String，例如 /login?user=admin' OR '1'='1)
    auto res = inspect_string(req.target, "TargetURI");
    if (res.is_blocked) return res;

    // 2. 檢查單獨 Path
    res = inspect_string(req.path, "Path");
    if (res.is_blocked) return res;

    // 2. 檢查 Query 參數
    for (const auto& [key, val] : req.params) {
        res = inspect_string(key, "QueryKey");
        if (res.is_blocked) return res;

        res = inspect_string(val, "QueryParam[" + key + "]");
        if (res.is_blocked) return res;
    }

    // 3. 檢查關鍵 Header (User-Agent, Cookie, Referer)
    static const std::vector<std::string> critical_headers = {
        "User-Agent", "Referer", "Cookie"
    };
    for (const auto& header_name : critical_headers) {
        if (req.has_header(header_name.c_str())) {
            auto val = req.get_header_value(header_name.c_str());
            res = inspect_string(val, "Header[" + header_name + "]");
            if (res.is_blocked) return res;
        }
    }

    // 4. 檢查 Request Body (POST 表單或 JSON)
    if (!req.body.empty()) {
        res = inspect_string(req.body, "Body");
        if (res.is_blocked) return res;
    }

    return InspectionResult{};
}

} // namespace waf
