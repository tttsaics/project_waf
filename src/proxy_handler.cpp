#include "proxy_handler.hpp"
#include <iostream>

namespace waf {

ProxyHandler::ProxyHandler(const std::string& backend_host, int backend_port)
    : backend_host_(backend_host), backend_port_(backend_port) {}

void ProxyHandler::set_backend(const std::string& host, int port) {
    backend_host_ = host;
    backend_port_ = port;
}

bool ProxyHandler::forward_request(const httplib::Request& req, httplib::Response& res, const std::string& request_id) {
    httplib::Client cli(backend_host_, backend_port_);
    cli.set_connection_timeout(5, 0);
    cli.set_read_timeout(15, 0);

    httplib::Headers headers;
    for (const auto& [key, val] : req.headers) {
        if (key != "Host" && key != "Content-Length") {
            headers.emplace(key, val);
        }
    }

    // 注入反向代理標頭
    std::string client_ip = req.remote_addr;
    if (client_ip.empty()) client_ip = "127.0.0.1";
    headers.emplace("X-Forwarded-For", client_ip);
    headers.emplace("X-Forwarded-Proto", "http");
    headers.emplace("X-Real-IP", client_ip);
    headers.emplace("X-Request-ID", request_id);

    std::string content_type = "application/octet-stream";
    if (req.has_header("Content-Type")) {
        content_type = req.get_header_value("Content-Type");
    }

    httplib::Result result;
    const std::string& path = req.target;

    if (req.method == "GET") {
        result = cli.Get(path.c_str(), headers);
    } else if (req.method == "POST") {
        result = cli.Post(path.c_str(), headers, req.body, content_type.c_str());
    } else if (req.method == "PUT") {
        result = cli.Put(path.c_str(), headers, req.body, content_type.c_str());
    } else if (req.method == "DELETE") {
        result = cli.Delete(path.c_str(), headers, req.body, content_type.c_str());
    } else if (req.method == "PATCH") {
        result = cli.Patch(path.c_str(), headers, req.body, content_type.c_str());
    } else if (req.method == "OPTIONS") {
        result = cli.Options(path.c_str(), headers);
    } else if (req.method == "HEAD") {
        result = cli.Head(path.c_str(), headers);
    } else {
        res.status = 405;
        res.set_content("{\"status\": 405, \"error\": \"Method Not Allowed\"}", "application/json");
        return true;
    }

    if (!result) {
        std::cerr << "[PROXY ERROR] 無法轉發請求至後端伺服器 " << backend_host_ << ":" << backend_port_ 
                  << " (錯誤碼: " << static_cast<int>(result.error()) << ")\n";
        res.status = 502;
        res.set_content(
            "{\n"
            "  \"status\": 502,\n"
            "  \"error\": \"Bad Gateway\",\n"
            "  \"message\": \"後端伺服器無回應或連線中斷\",\n"
            "  \"request_id\": \"" + request_id + "\"\n"
            "}\n",
            "application/json"
        );
        return false;
    }

    // 透傳後端回應狀態碼與內容
    res.status = result->status;
    for (const auto& [key, val] : result->headers) {
        if (key != "Content-Length" && key != "Transfer-Encoding") {
            res.set_header(key.c_str(), val);
        }
    }
    res.set_header("X-Request-ID", request_id);
    res.body = result->body;

    return true;
}

} // namespace waf
