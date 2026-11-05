# Web Application Firewall (WAF) 企業級應用層防火牆核心

這是一個以 C++20 開發的高效能 Layer 7 (應用層) 網站應用程式防火牆 (WAF)，具備**多輪解碼正規化**、**異常評分決策 (Anomaly Scoring)**、**高頻限流 (Rate Limiting)**、**真實反向代理轉發 (Reverse Proxy)**、**外部規則動態熱重載** 與 **零資訊洩漏防禦** 機制。

---

## 專案架構說明

```text
C:\WAF\
├── .vscode/
│   ├── c_cpp_properties.json  # VS Code C++ IntelliSense 與標頭檔路徑設定
│   ├── tasks.json             # 一鍵編譯指令 (Ctrl + Shift + B)
│   └── launch.json            # 一鍵除錯與執行 (F5)
├── config/
│   ├── waf_config.json        # WAF 系統設定檔 (埠口、代理模式、限流、門檻)
│   └── waf_rules.json         # 外部動態自訂安全規則集 (JSON 格式)
├── include/
│   ├── config.hpp             # 系統設定結構與載入器定義
│   ├── httplib.h              # 輕量 HTTP 伺服器與客戶端庫
│   ├── json.hpp               # Modern C++ JSON 解析庫 (nlohmann/json)
│   ├── proxy_handler.hpp      # 反向代理轉發核心定義
│   ├── rate_limiter.hpp       # IP 滑動窗口頻率限制器 (Rate Limiter)
│   ├── rule_engine.hpp        # 異常評分與安全防護規則引擎定義
│   └── url_utils.hpp          # 多輪遞迴解碼與字串正規化工具
├── src/
│   ├── config.cpp             # 設定檔讀取與預設產生實作
│   ├── main.cpp               # WAF 主進入點 (統一排程、審計日誌與路由)
│   ├── proxy_handler.cpp      # 反向代理轉發與標頭注入實作
│   ├── rate_limiter.cpp       # 執行緒安全頻率限制實作
│   ├── rule_engine.cpp        # 規則引擎與異常評分實作
│   └── url_utils.cpp          # 多重 URL 解碼、HTML Entity 解碼與路徑標準化
├── tests/
│   ├── test_waf.py            # 全功能自動化驗證腳本 (涵蓋正常、防誤判、各類攻擊與限流)
│   └── test_proxy.py          # 反向代理轉發與後端聯防驗證腳本
├── CMakeLists.txt             # CMake 建置設定
├── waf.exe                    # 編譯產生的二進位執行檔
└── README.md                  # 專案指引文件
```

---

## 核心功能與已修正之缺失

| 項目 | 舊版缺陷 | 新版實作升級 |
| :--- | :--- | :--- |
| **雙重編碼繞過** | 僅做單次 URL 解碼，易受 `%252e%252e%252f` 逃逸 | **多輪遞迴 URL 解碼**、HTML Entity 還原、Null Bytes 剝離與路徑標準化 |
| **誤判 (False Positive)** | 規則過苛（如單獨 `#` 或 `--` 導致 C# 或色碼被誤殺） | **語法上下文嚴格判定**，並導入 **異常評分體系 (Anomaly Scoring)** |
| **資訊洩漏** | 403 回應外洩觸發之規則名稱與攻擊特徵字串 | **嚴格隱藏內部防禦細節**，對外僅回傳唯一 `Request-ID`，內部終端記錄完整審計日誌 |
| **反向代理能力** | 僅為假伺服器 (Mock)，無法轉發至真實後端 | 支援 **`proxy` 模式**，自動透傳 Request / Response 並注入 `X-Forwarded-For`、`X-Request-ID` |
| **頻率限制** | 無法防範高頻爬蟲、暴力破解與 Layer 7 DoS | 內建執行緒安全 **IP 滑動窗口限流器 (Rate Limiter)**，超標自動回應 HTTP 429 |
| **規則維運** | 規則全寫死在 C++ 程式碼中，更新需重新編譯 | 抽離為 `config/waf_rules.json`，支援 **`POST /waf/admin/reload` 線上零中斷熱重載** |
| **HTTP 方法覆蓋** | 僅支援 GET / POST | 完整支援 **GET, POST, PUT, DELETE, PATCH, OPTIONS** |

---

## 防護攻擊涵蓋範圍

1. **SQL 注入防禦 (SQLi)**：
   * 萬能密碼與恆真式注入 (`' OR '1'='1`, `' OR true`)
   * 聯合查詢注入 (`UNION SELECT`)
   * 堆疊指令注入 (`; DROP TABLE`, `; INSERT INTO`)
   * 時間盲注與報錯關鍵函式 (`sleep()`, `benchmark()`, `updatexml()`, `extractvalue()`)
   * SQL 註解注入 (`-- `, `/*...*/`, `['"]#`)
2. **跨站腳本防禦 (XSS)**：
   * 危險 HTML 標籤 (`<script>`, `<iframe>`, `<svg onload>`, `<embed>`, `<object>`)
   * 全面 DOM 事件處理器 (`onerror=`, `onload=`, `onclick=`, `ontoggle=`, `on*`)
   * 偽協議注入 (`javascript:`, `data:`, `vbscript:`)
   * 危險執行函式 (`alert()`, `eval()`, `document.cookie`)
3. **路徑穿越防禦 (Path Traversal)**：
   * 目錄遍歷點號 (`../../`, `..\..\`, `..;`, 多層編碼繞過)
   * 敏感系統核心檔案存取 (`/etc/passwd`, `/etc/shadow`, `windows/system32`, `win.ini`)
4. **系統指令注入防禦 (Command Injection)**：
   * 指令串接運算子 (`&&`, `||`, `;`, `|`, `` ` ``, `$()`)
   * 換行符號指令注入 (`\r`, `\n` 接指令)
   * 常見系統執行與連外指令 (`whoami`, `cat`, `curl`, `wget`, `powershell`, `bash`, `python`)

---

## 設定檔說明 (`config/waf_config.json`)

```json
{
    "server": {
        "host": "0.0.0.0",
        "port": 8080,
        "mode": "standalone"   // 可設為 "standalone" (獨立測試) 或 "proxy" (反向代理)
    },
    "backend": {
        "host": "127.0.0.1",
        "port": 3000          // proxy 模式下後端 Web Server 埠口
    },
    "security": {
        "anomaly_threshold": 5,
        "custom_rules_file": "config/waf_rules.json"
    },
    "rate_limit": {
        "enabled": true,
        "max_requests": 30,   // 時間窗口內最大允許請求數
        "window_seconds": 10  // 滑動窗口秒數 (超過即回傳 429)
    }
}
```

---

## 在 VS Code 中開發與執行

### 1. 一鍵編譯 (Build)
* 在 VS Code 內按下快捷鍵：**`Ctrl + Shift + B`**

### 2. 一鍵啟動與除錯 (Run & Debug)
* 按下鍵盤 **`F5`** 即可以除錯器啟動 WAF 服務。

### 3. 手動命令列編譯
```powershell
g++ -std=c++20 -D_WIN32_WINNT=0x0A00 -static -O2 -Iinclude src/main.cpp src/rule_engine.cpp src/url_utils.cpp src/config.cpp src/rate_limiter.cpp src/proxy_handler.cpp -lws2_32 -o waf.exe
```

### 4. 啟動 WAF 服務
```powershell
# 以預設設定檔啟動
.\waf.exe

# 或指定埠口與運作模式
.\waf.exe 8080 standalone
.\waf.exe 8080 proxy
```

---

## 執行自動化測試

啟動 WAF 服務後，於另一終端機執行：

### 1. 執行基礎與全攻擊防護測試 (22/22 項全過驗證)
```powershell
py -u tests\test_waf.py
```
* 涵蓋：正常 RESTful (GET, POST, PUT, DELETE)、誤判驗證 (C#, #ffffff, step--1)、SQLi、XSS、Path Traversal (含雙重編碼)、指令注入、403 無敏感洩漏驗證、429 頻率限制驗證。

### 2. 執行反向代理轉發與後端聯防驗證
```powershell
py -u tests\test_proxy.py
```
* 驗證真實後端 (Dummy Server) 與 WAF 聯防：放行合法資料透傳、注入 `X-Forwarded-For`、阻擋攻擊請求。
