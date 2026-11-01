#include "url_utils.hpp"
#include <algorithm>
#include <cctype>
#include <sstream>

namespace waf {

std::string url_decode(const std::string& input) {
    std::string result;
    result.reserve(input.size());

    for (size_t i = 0; i < input.size(); ++i) {
        if (input[i] == '%' && i + 2 < input.size()) {
            char high = input[i + 1];
            char low = input[i + 2];
            if (std::isxdigit(high) && std::isxdigit(low)) {
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

std::string to_lower(const std::string& input) {
    std::string lower = input;
    std::transform(lower.begin(), lower.end(), lower.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return lower;
}

} // namespace waf
