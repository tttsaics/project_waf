#include "rule_engine.hpp"
#include "url_utils.hpp"
#include "json.hpp"
#include <fstream>
#include <iostream>

using json = nlohmann::json;

namespace waf {

RuleEngine::RuleEngine(int anomaly_threshold)
    : anomaly_threshold_(anomaly_threshold) {
    init_default_rules();
}

void RuleEngine::set_anomaly_threshold(int threshold) {
    anomaly_threshold_ = threshold;
}

int RuleEngine::get_anomaly_threshold() const {
    return anomaly_threshold_;
}

void RuleEngine::init_default_rules() {
    rules_.clear();

    // ==========================================
    // 1. SQL Injection (SQLi) 規則組
    // ==========================================
    // 1.1 聯合查詢 (UNION SELECT)
    rules_.push_back({
        "942100",
        "SQLi",
        "SQLi-Union-Select",
        std::regex(R"(\bunion\b\s+(\ball\b\s+)?\bselect\b)", std::regex_constants::icase),
        5
    });

    // 1.2 恆真式條件與布林注入 (OR 1=1, 'a'='a', OR true 等)
    rules_.push_back({
        "942110",
        "SQLi",
        "SQLi-Tautology",
        std::regex(R"(\b(or|and)\b\s+(['"]?\w+['"]?\s*=\s*['"]?\w+['"]?|1\s*=\s*1|true\b))", std::regex_constants::icase),
        5
    });

    // 1.3 盲注與關鍵函數 (SLEEP, BENCHMARK, EXTRACTVALUE, UPDATEXML, WAITFOR DELAY)
    rules_.push_back({
        "942120",
        "SQLi",
        "SQLi-Functions",
        std::regex(R"(\b(sleep|benchmark|waitfor\s+delay|extractvalue|updatexml)\s*\()", std::regex_constants::icase),
        5
    });

    // 1.4 堆疊指令注入 (分號接資料庫管理操作)
    rules_.push_back({
        "942130",
        "SQLi",
        "SQLi-Stacked-Commands",
        std::regex(R"(;\s*(drop|insert|update|delete|create|alter|truncate)\b)", std::regex_constants::icase),
        5
    });

    // 1.5 SQL 註解 (修正誤判：要求接空白、結尾或 SQL 引號，避免誤殺 C#, #ffffff 等正常輸入)
    rules_.push_back({
        "942140",
        "SQLi",
        "SQLi-Comment-Pattern",
        std::regex(R"((--[\s\+]|--$|/\*.*?\*/|['"`\)]\s*#|;\s*#))", std::regex_constants::icase),
        3
    });

    // ==========================================
    // 2. Cross-Site Scripting (XSS) 規則組
    // ==========================================
    // 2.1 危險 HTML 標籤 (包含 script, iframe, object, embed, svg, style 等)
    rules_.push_back({
        "941100",
        "XSS",
        "XSS-Dangerous-Tags",
        std::regex(R"(<\s*(script|iframe|object|embed|svg|style|meta|link|base)\b[^>]*>?)", std::regex_constants::icase),
        5
    });

    // 2.2 DOM 事件處理屬性 (onerror=, onload=, onclick=, ontoggle= 等任意 on* 屬性)
    rules_.push_back({
        "941110",
        "XSS",
        "XSS-Event-Handler",
        std::regex(R"(\bon[a-z]{3,20}\s*=)", std::regex_constants::icase),
        5
    });

    // 2.3 偽協議 (javascript:, data:, vbscript:)
    rules_.push_back({
        "941120",
        "XSS",
        "XSS-Pseudo-Protocol",
        std::regex(R"((javascript|vbscript|data)\s*:[^\s]+)", std::regex_constants::icase),
        5
    });

    // 2.4 常見危險 JS 執行函式與敏感物件存取
    rules_.push_back({
        "941130",
        "XSS",
        "XSS-Dangerous-Functions",
        std::regex(R"(\b(alert|prompt|confirm|eval|document\.cookie|window\.location)\s*\()", std::regex_constants::icase),
        5
    });

    // ==========================================
    // 3. Path Traversal (路徑穿越) 規則組
    // ==========================================
    // 3.1 目錄遍歷點號 (支援 ../, ..\, ..;, 點號逃逸)
    rules_.push_back({
        "930100",
        "PathTraversal",
        "Traversal-Dots",
        std::regex(R"((\.{2,}[/\\]|\.{2,};|/\.\./))", std::regex_constants::icase),
        5
    });

    // 3.2 敏感系統核心檔案存取
    rules_.push_back({
        "930110",
        "PathTraversal",
        "Traversal-System-Files",
        std::regex(R"((/etc/(passwd|shadow|hosts|group)|(windows|winnt)/system32|boot\.ini|win\.ini))", std::regex_constants::icase),
        5
    });

    // ==========================================
    // 4. Command Injection (指令注入) 規則組
    // ==========================================
    // 4.1 管道與指令串接運算子 (&&, ||, ;, |, `, $() 接系統指令或連線工具)
    rules_.push_back({
        "932100",
        "CmdInjection",
        "Cmd-Chaining-Operators",
        std::regex(R"((&&|\|\||;|\||`|\$\()\s*(cat|ls|dir|whoami|id|bash|sh|cmd|powershell|curl|wget|nc|python|perl|certutil|findstr|net\s+user)\b)", std::regex_constants::icase),
        5
    });

    // 4.2 換行符號串接指令 (\r, \n 接指令)
    rules_.push_back({
        "932110",
        "CmdInjection",
        "Cmd-Newline-Chaining",
        std::regex(R"([\r\n]\s*(cat|ls|dir|whoami|id|bash|sh|cmd|powershell)\b)", std::regex_constants::icase),
        5
    });
}

bool RuleEngine::load_rules_from_file(const std::string& filepath) {
    std::ifstream file(filepath);
    if (!file.is_open()) {
        return false;
    }

    try {
        json j;
        file >> j;

        if (!j.is_array()) return false;

        std::vector<Rule> loaded_rules;
        for (const auto& item : j) {
            std::string id = item.value("id", "");
            std::string attack_type = item.value("attack_type", "");
            std::string rule_name = item.value("rule_name", "");
            std::string pattern_str = item.value("pattern", "");
            int score = item.value("score", 5);

            if (!pattern_str.empty()) {
                loaded_rules.push_back({
                    id,
                    attack_type,
                    rule_name,
                    std::regex(pattern_str, std::regex_constants::icase),
                    score
                });
            }
        }

        if (!loaded_rules.empty()) {
            rules_ = std::move(loaded_rules);
            std::cout << "[RULE_ENGINE] 成功自 " << filepath << " 載入 " << rules_.size() << " 條規則。\n";
            return true;
        }
    } catch (const std::exception& e) {
        std::cerr << "[RULE_ENGINE] 載入規則檔失敗: " << e.what() << "\n";
    }

    return false;
}

void RuleEngine::inspect_string(const std::string& input, const std::string& location, InspectionResult& result) {
    if (input.empty()) return;

    // 先經過完整正規化防禦 (多重解碼、HTML Entity 還原、空字元去除、路徑斜線標準化)
    std::string normalized = normalize_payload(input);

    for (const auto& rule : rules_) {
        std::smatch match;
        if (std::regex_search(normalized, match, rule.pattern)) {
            MatchedDetail detail;
            detail.rule_id = rule.id;
            detail.attack_type = rule.attack_type;
            detail.rule_name = rule.rule_name;
            detail.matched_payload = match.str();
            detail.source_location = location;
            detail.score = rule.score;

            result.matches.push_back(detail);
            result.total_score += rule.score;

            if (result.primary_attack_type.empty()) {
                result.primary_attack_type = rule.attack_type;
            }
        }
    }
}

InspectionResult RuleEngine::inspect_request(const httplib::Request& req) {
    InspectionResult result;

    // 1. 檢查路徑 Path (避免與 Query 參數重複累計)
    inspect_string(req.path, "Path", result);

    // 2. 檢查所有 Query 參數
    for (const auto& [key, val] : req.params) {
        inspect_string(key, "QueryKey[" + key + "]", result);
        inspect_string(val, "QueryParam[" + key + "]", result);
    }

    // 3. 檢查重要 Header (User-Agent, Referer, Cookie, Authorization)
    static const std::vector<std::string> critical_headers = {
        "User-Agent", "Referer", "Cookie", "Authorization"
    };
    for (const auto& h : critical_headers) {
        if (req.has_header(h.c_str())) {
            auto val = req.get_header_value(h.c_str());
            inspect_string(val, "Header[" + h + "]", result);
        }
    }

    // 4. 檢查 Body 內容 (若在 pre_routing 時已有 Body)
    if (!req.body.empty()) {
        inspect_string(req.body, "Body", result);
    }

    // 綜合異常評分決策 (超過門檻則阻擋)
    result.is_blocked = (result.total_score >= anomaly_threshold_);

    return result;
}

} // namespace waf
