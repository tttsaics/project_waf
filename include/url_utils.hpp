#pragma once

#include <string>

namespace waf {

// 單次 URL 解碼
std::string url_decode_once(const std::string& input);

// 多重 / 遞迴 URL 解碼，直到字串不再變化或達上限，徹底防止雙重編碼 (Double Encoding) 繞過
std::string url_decode(const std::string& input, int max_depth = 5);

// HTML Entity 解碼 (例如 &quot;, &#39;, &#x3c;, &lt;, &gt;, &amp;)
std::string html_entity_decode(const std::string& input);

// 移除 Null Bytes (\0)
std::string remove_null_bytes(const std::string& input);

// 規範化路徑分隔符與重疊斜線 (例如 // -> /, \ -> /)
std::string normalize_path_separators(const std::string& input);

// 完整正規化處理 (包含遞迴解碼、去除空字元、HTML Entity 解碼、路徑標準化)
std::string normalize_payload(const std::string& input);

// 將字串轉為全小寫
std::string to_lower(const std::string& input);

} // namespace waf
