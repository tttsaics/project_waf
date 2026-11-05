#pragma once

#include <string>
#include <vector>
#include <regex>
#include <memory>
#include "httplib.h"

namespace waf {

// 單條觸發細節 (用於伺服器端內部日誌分析)
struct MatchedDetail {
    std::string rule_id;
    std::string attack_type;
    std::string rule_name;
    std::string matched_payload;
    std::string source_location;
    int score = 0;
};

// 檢測結果結構體
struct InspectionResult {
    bool is_blocked = false;
    int total_score = 0;
    std::string primary_attack_type;
    std::vector<MatchedDetail> matches;
};

// 安全防護規則
struct Rule {
    std::string id;
    std::string attack_type;      // SQLi, XSS, PathTraversal, CmdInjection
    std::string rule_name;
    std::regex pattern;
    int score = 5;                // 規則威脅權重 (1~5)
};

class RuleEngine {
public:
    explicit RuleEngine(int anomaly_threshold = 5);

    // 設定異常評分門檻
    void set_anomaly_threshold(int threshold);
    int get_anomaly_threshold() const;

    // 載入自訂外部規則檔 (JSON 格式)
    bool load_rules_from_file(const std::string& filepath);

    // 初始化內建核心高準確度規則
    void init_default_rules();

    // 檢查字串是否包含惡意特徵 (累計分數與細節)
    void inspect_string(const std::string& input, const std::string& location, InspectionResult& result);

    // 完整檢查 HTTP Request (Path, Query, Headers, Body)
    InspectionResult inspect_request(const httplib::Request& req);

private:
    int anomaly_threshold_;
    std::vector<Rule> rules_;
};

} // namespace waf
