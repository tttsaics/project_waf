#include "url_utils.hpp"
#include <algorithm>
#include <cctype>
#include <sstream>
#include <unordered_map>

namespace waf {

std::string url_decode_once(const std::string& input) {
    std::string result;
    result.reserve(input.size());

    for (size_t i = 0; i < input.size(); ++i) {
        if (input[i] == '%' && i + 2 < input.size()) {
            char high = input[i + 1];
            char low = input[i + 2];
            if (std::isxdigit(static_cast<unsigned char>(high)) && 
                std::isxdigit(static_cast<unsigned char>(low))) {
                auto hex_to_int = [](char c) -> int {
                    if (c >= '0' && c <= '9') return c - '0';
                    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                    return 0;
                };
                char decoded_char = static_cast<char>((hex_to_int(high) << 4) | hex_to_int(low));
                result.push_back(decoded_char);
                i += 2;
                continue;
            }
        }

        if (input[i] == '+') {
            result.push_back(' ');
        } else {
            result.push_back(input[i]);
        }
    }
    return result;
}

std::string url_decode(const std::string& input, int max_depth) {
    std::string current = input;
    for (int depth = 0; depth < max_depth; ++depth) {
        std::string next = url_decode_once(current);
        if (next == current) {
            break;
        }
        current = std::move(next);
    }
    return current;
}

std::string html_entity_decode(const std::string& input) {
    std::string result;
    result.reserve(input.size());

    static const std::unordered_map<std::string, char> named_entities = {
        {"lt", '<'},
        {"gt", '>'},
        {"quot", '"'},
        {"apos", '\''},
        {"amp", '&'}
    };

    for (size_t i = 0; i < input.size(); ++i) {
        if (input[i] == '&') {
            size_t semi = input.find(';', i + 1);
            if (semi != std::string::npos && (semi - i) <= 10) {
                std::string entity = input.substr(i + 1, semi - i - 1);
                if (!entity.empty()) {
                    if (entity[0] == '#') {
                        // 數值 Entity: &#60; 或 &#x3c;
                        try {
                            int code = 0;
                            if (entity.size() > 2 && (entity[1] == 'x' || entity[1] == 'X')) {
                                code = std::stoi(entity.substr(2), nullptr, 16);
                            } else if (entity.size() > 1) {
                                code = std::stoi(entity.substr(1), nullptr, 10);
                            }
                            if (code > 0 && code < 256) {
                                result.push_back(static_cast<char>(code));
                                i = semi;
                                continue;
                            }
                        } catch (...) {}
                    } else {
                        // 具名 Entity
                        auto it = named_entities.find(entity);
                        if (it != named_entities.end()) {
                            result.push_back(it->second);
                            i = semi;
                            continue;
                        }
                    }
                }
            }
        }
        result.push_back(input[i]);
    }

    return result;
}

std::string remove_null_bytes(const std::string& input) {
    std::string result;
    result.reserve(input.size());
    for (char c : input) {
        if (c != '\0') {
            result.push_back(c);
        }
    }
    return result;
}

std::string normalize_path_separators(const std::string& input) {
    std::string result;
    result.reserve(input.size());
    char last = 0;
    for (char c : input) {
        char ch = (c == '\\') ? '/' : c;
        if (ch == '/' && last == '/') {
            // 折疊重複斜線
            continue;
        }
        result.push_back(ch);
        last = ch;
    }
    return result;
}

std::string normalize_payload(const std::string& input) {
    if (input.empty()) return "";
    
    // 1. 去除空字元
    std::string step1 = remove_null_bytes(input);
    // 2. 多重 URL 遞迴解碼 (防雙重/多重編碼)
    std::string step2 = url_decode(step1, 5);
    // 3. HTML Entity 解碼
    std::string step3 = html_entity_decode(step2);
    // 4. 路徑斜線標準化
    std::string step4 = normalize_path_separators(step3);
    
    return step4;
}

std::string to_lower(const std::string& input) {
    std::string lower = input;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return lower;
}

} // namespace waf
