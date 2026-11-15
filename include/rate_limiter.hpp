#pragma once

#include <string>
#include <deque>
#include <chrono>
#include <mutex>
#include <unordered_map>

namespace waf {

class RateLimiter {
public:
    RateLimiter(bool enabled = true, int max_requests = 60, int window_seconds = 10);

    // 檢查該 IP 是否允許請求；若超過限制回傳 false
    bool is_allowed(const std::string& client_ip);

    // 更新配置
    void update_config(bool enabled, int max_requests, int window_seconds);

    // 清理過期的 IP 紀錄
    void cleanup_expired();

private:
    bool enabled_;
    int max_requests_;
    std::chrono::seconds window_;

    std::mutex mutex_;
    std::unordered_map<std::string, std::deque<std::chrono::steady_clock::time_point>> ip_records_;
    std::chrono::steady_clock::time_point last_cleanup_;
};

} // namespace waf
