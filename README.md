# Web Application Firewall (WAF) 防火牆核心專案

這是一個以 C++ 開發的輕量級 Layer 7 (應用層) 網站應用程式防火牆 (WAF) 原型，具備基礎規則防護引擎與日後整合 AI 深度檢測之擴充架構。

---

## 專案結構說明

```text
C:\WAF\
├── .vscode/
│   ├── c_cpp_properties.json  # VS Code C++ IntelliSense 與標頭檔路徑設定
│   ├── tasks.json             # 一鍵編譯指令 (Ctrl + Shift + B)
│   └── launch.json            # 一鍵除錯與執行 (F5)
├── include/
│   ├── httplib.h              # 輕量 HTTP 伺服器與客戶端庫
│   ├── rule_engine.hpp        # 安全過濾規則引擎定義
│   └── url_utils.hpp          # URL 解碼與正規化工具
├── src/
│   ├── main.cpp               # WAF 主伺服器進入點
│   ├── rule_engine.cpp        # 規則引擎實作 (SQLi, XSS, Traversal, Cmd)
│   └── url_utils.cpp          # URL 工具函式實作
├── tests/
│   └── test_waf.py            # 自動化測試腳本 (涵蓋正常與惡意攻擊測試)
├── CMakeLists.txt             # CMake 建置設定
├── waf.exe                    # 編譯產生的二進位執行檔
└── README.md                  # 專案指引文件
```

---

## 在 VS Code 中開發與執行

### 1. 一鍵編譯 (Build)
* 在 VS Code 內按下快捷鍵：**`Ctrl + Shift + B`**
* 即會調用 `g++` 自動編譯出全新的 `waf.exe`。

### 2. 一鍵啟動與除錯 (Run & Debug)
* 按下鍵盤 **`F5`**
* VS Code 會自動編譯最新程式碼並啟動 GDB 除錯器，WAF 伺服器將在 `http://localhost:8080` 開始監聽。

### 3. 手動命令列編譯 (若需在終端機編譯)
```powershell
g++ -std=c++20 -D_WIN32_WINNT=0x0A00 -static -Iinclude src/main.cpp src/rule_engine.cpp src/url_utils.cpp -lws2_32 -o waf.exe
```

---

## 執行自動化測試

啟動 WAF 伺服器後，在終端機執行：
```powershell
python tests\test_waf.py
```

### 目前已實作並通過之防禦測試案例：
1. **正常請求放行** (HTTP 200 OK)
   * 正常首頁請求 (`GET /`)
   * 正常帶參數查詢 (`GET /products?category=books&page=2`)
   * 正常使用者表單登入 (`POST /api/login`)
2. **SQL 注入攻擊 (SQLi) 攔截** (HTTP 403 Forbidden)
   * 萬能密碼 (`' OR '1'='1`)
   * 聯合查詢 (`UNION SELECT`)
   * 堆疊指令注入 (`DROP TABLE users; --`)
3. **跨站腳本攻擊 (XSS) 攔截** (HTTP 403 Forbidden)
   * 標籤注入 (`<script>alert(1)</script>`)
   * 事件屬性注入 (`onerror="alert(1)"`)
4. **路徑穿越 (Path Traversal) 攔截** (HTTP 403 Forbidden)
   * 目錄遍歷 (`../../etc/passwd`)
5. **系統指令注入 (Command Injection) 攔截** (HTTP 403 Forbidden)
   * 管道與分號串接 (`/ping?host=127.0.0.1; whoami`)

---

## 下一步：AI 整合路線展望 (Week 2+)

1. **L1 (C++ 規則引擎)**：先由當前這套 C++ 核心做毫秒級快速比對，擋下明顯已知的特徵。
2. **L2 (AI 語意分析)**：
   * 當請求未觸發 L1 規則，但參數長度異常、包含大量特殊符號或涉及關鍵語法時，將 payload 打包傳給 AI 模組進行推論（透過 gRPC / REST API 呼叫 Python 模型或以 ONNX Runtime 在 C++ 本地執行）。
   * 根據 AI 回傳的威脅評分 (Risk Score 0~100) 決定放行、阻擋或紀錄日誌。


## 可防護項目
1. SQL注入
2. XSS跨站腳本
3. 路徑穿越
4. 指令注入

## 無法防護
1. 其他語法&變形
2. 文字誤判
3. 暴力&DDOS