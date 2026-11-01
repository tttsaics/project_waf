#pragma once

#include <string>
#include <vector>
#include <regex>
#include "httplib.h"

namespace waf {

// 檢測結果結構體
struct InspectionResult {
    bool is_blocked = false;
    std::string attack_type;      // 攻擊類型: SQLi, XSS, PathTraversal, CmdInjection 等
    std::string matched_rule;     // 觸發的規則名稱
    std::string matched_payload;  // 匹配到的惡意特徵片段
    std::string source_location;  // 來源位置: Path, QueryParam, Header, Body
};

// 單一安全防護規則
struct Rule {
    std::string attack_type;
    std::string rule_name;
    std::regex pattern;
};

// 規則檢查引擎類別
class RuleEngine {
public:
    RuleEngine();

    // 檢查字串是否包含惡意特徵
    InspectionResult inspect_string(const std::string& input, const std::string& location);

    // 完整檢查 HTTP Request (含 Path, Query, Headers, Body)
    InspectionResult inspect_request(const httplib::Request& req);

private:
    void init_rules();
    std::vector<Rule> rules_;
};

} // namespace waf
