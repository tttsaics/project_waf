#pragma once

#include <string>

namespace waf {

struct WafConfig {
    int port = 8080;
    std::string host = "0.0.0.0";
    
    // 運作模式: "standalone" (展示/測試用) 或 "proxy" (轉發至真實後端)
    std::string mode = "standalone";
    
    // 後端伺服器 (Proxy 模式使用)
    std::string backend_host = "127.0.0.1";
    int backend_port = 3000;
    
    // 異常評分體系門檻 (Anomaly Scoring Threshold)
    int anomaly_threshold = 5;
    
    // Rate Limiting (頻率限制) 設定
    bool rate_limit_enabled = true;
    int rate_limit_requests = 60;      // 窗口內最多請求數
    int rate_limit_window_sec = 10;    // 時間窗口 (秒)
    
    // 外部規則檔路徑 (選填)
    std::string custom_rules_file = "config/waf_rules.json";
};

// 載入設定檔 (若檔案不存在或格式有誤則套用安全預設值)
WafConfig load_config(const std::string& config_file_path);

// 產生預設設定檔
bool save_default_config(const std::string& config_file_path);

} // namespace waf
