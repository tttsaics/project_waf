#include "rate_limiter.hpp"

namespace waf {

RateLimiter::RateLimiter(bool enabled, int max_requests, int window_seconds)
    : enabled_(enabled),
      max_requests_(max_requests),
      window_(std::chrono::seconds(window_seconds)),
      last_cleanup_(std::chrono::steady_clock::now()) {}

void RateLimiter::update_config(bool enabled, int max_requests, int window_seconds) {
    std::lock_guard<std::mutex> lock(mutex_);
    enabled_ = enabled;
    max_requests_ = max_requests;
    window_ = std::chrono::seconds(window_seconds);
    ip_records_.clear();
}

bool RateLimiter::is_allowed(const std::string& client_ip) {
    if (!enabled_) return true;

    auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(mutex_);

    // 每 60 秒自動觸發一次全域過期清理
    if (now - last_cleanup_ > std::chrono::seconds(60)) {
        for (auto it = ip_records_.begin(); it != ip_records_.end(); ) {
            while (!it->second.empty() && now - it->second.front() > window_) {
                it->second.pop_front();
            }
            if (it->second.empty()) {
                it = ip_records_.erase(it);
            } else {
                ++it;
            }
        }
        last_cleanup_ = now;
    }

    auto& timestamps = ip_records_[client_ip];

    // 清理該 IP 在窗口以外的舊請求
    while (!timestamps.empty() && now - timestamps.front() > window_) {
        timestamps.pop_front();
    }

    if (static_cast<int>(timestamps.size()) >= max_requests_) {
        return false;
    }

    timestamps.push_back(now);
    return true;
}

void RateLimiter::cleanup_expired() {
    auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(mutex_);
    for (auto it = ip_records_.begin(); it != ip_records_.end(); ) {
        while (!it->second.empty() && now - it->second.front() > window_) {
            it->second.pop_front();
        }
        if (it->second.empty()) {
            it = ip_records_.erase(it);
        } else {
            ++it;
        }
    }
    last_cleanup_ = now;
}

} // namespace waf
