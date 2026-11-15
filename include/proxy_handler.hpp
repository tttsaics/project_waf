#pragma once

#include <string>
#include "httplib.h"

namespace waf {

class ProxyHandler {
public:
    ProxyHandler(const std::string& backend_host = "127.0.0.1", int backend_port = 3000);

    // 設定後端目標
    void set_backend(const std::string& host, int port);

    // 將已通過 WAF 安全檢驗的請求轉發給後端伺服器，並將回應透傳回客戶端
    bool forward_request(const httplib::Request& req, httplib::Response& res, const std::string& request_id);

private:
    std::string backend_host_;
    int backend_port_;
};

} // namespace waf
