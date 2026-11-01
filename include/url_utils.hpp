#pragma once

#include <string>

namespace waf {

// 解碼 URL 編碼字串 (例如將 "%27" 轉換為 "'"，將 "+" 轉換為 " ")
std::string url_decode(const std::string& input);

// 將字串轉為全小寫，方便大小寫不敏感比對
std::string to_lower(const std::string& input);

} // namespace waf
