# 企業級 WAF (Web Application Firewall) 完整使用與維運手冊

本手冊統整本專案的架構、建置、部署、HTTP Request 測試方式與常用維運指令。

---

## 一、 專案核心特色

1. **C++20 高效能核心**：多執行緒非同步 HTTP 處理（基於 `cpp-httplib`）。
2. **多輪遞迴解碼**：防範雙重 URL 編碼（如 `%252e%252e%252f`）、HTML Entity 與 Null Byte 繞過。
3. **異常評分體系 (Anomaly Scoring)**：避免傳統 WAF 誤殺合法的 `C#`、色碼 `#ffffff` 或連字號 `step--1`。
4. **零敏感資訊洩漏 (Zero Information Disclosure)**：被阻擋的客戶端只會拿到包含追蹤用 `request_id` 的乾淨 JSON，絕不外洩內部規則特徵。
5. **IP 滑動窗口限流 (Rate Limiting)**：防止高頻爆破與 DoS 攻擊（超標回傳 `429 Too Many Requests`）。
6. **動態熱重載 (Dynamic Hot-Reload)**：透過 API 免重啟即可更新設定與規則。
7. **容器化打包 (Docker)**：採用 Alpine 多階段建置，產出 20MB 極輕量映像檔。

---

## 二、 檔案目錄結構

```text
C:\WAF\
├── config/
│   ├── waf_config.json        # 系統核心設定（連接埠、模式、後端位址、限流）
│   └── waf_rules.json         # 自訂安全規則庫（支援熱重載）
├── include/                   # C++ 標頭檔 (.hpp / .h)
├── src/                       # C++ 實作原始碼 (.cpp)
├── tests/
│   ├── test_waf.py            # 22 項安全防護 + 限流自動化測試套件
│   └── test_proxy.py          # 後端反向代理聯防測試腳本
├── .dockerignore              # Docker 忽略清單
├── Dockerfile                 # Alpine 多階段 Docker 建置腳本
├── CMakeLists.txt             # 跨平台 CMake 設定
├── README.md                  # 專案技術文件
└── waf.exe                    # Windows 本地預先編譯好的二進位檔
```

---

## 三、 Docker 容器化操作（標準推薦流程）

### 1. 建置 Docker 映像檔
在專案根目錄 (`C:\WAF`) 執行：
```powershell
docker build -t waf-app:latest .
```

### 2. 啟動 WAF 容器
```powershell
docker run -d -p 8080:8080 --name waf-server waf-app:latest
```
- `-d`：背景執行（Detached 模式）。
- `-p 8080:8080`：將實體機的 8080 埠映射至容器內。
- `--name waf-server`：指定容器名稱為 `waf-server`。

### 3. 查看容器日誌 (Logs)
- **單次檢視日誌（印完立即返回，不會卡住）**：
  ```powershell
  docker logs waf-server
  ```
- **查看最後 20 行日誌**：
  ```powershell
  docker logs --tail 20 waf-server
  ```
- **即時持續追蹤日誌（Follow 模式，按 `Ctrl + C` 退出）**：
  ```powershell
  docker logs -f waf-server
  ```

### 4. 停止與清理容器
```powershell
# 停止容器
docker stop waf-server

# 刪除容器
docker rm waf-server
```

---

## 四、 HTTP Request 測試範例指令

您可以使用命令提示字元 (CMD)、PowerShell 或 Postman 發送 HTTP 請求進行測試：

### 1. 正常請求測試（放行 200 OK）
```powershell
curl -i http://localhost:8080/
```
*預期回應：`HTTP/1.1 200 OK`*

### 2. SQL 注入攻擊攔截（SQLi - 阻擋 403 Forbidden）
```powershell
# 注意：URL 空格請以 %20 表示
curl -i "http://localhost:8080/login?user=admin'%20OR%20'1'='1"

# 或使用 POST 表單發送
curl -i -X POST http://localhost:8080/login -d "user=admin' OR '1'='1"
```
*預期回應：`HTTP/1.1 403 Forbidden`*

### 3. 跨站腳本攻擊攔截（XSS - 阻擋 403 Forbidden）
```powershell
curl -i "http://localhost:8080/search?q=<script>alert('xss')</script>"
```
*預期回應：`HTTP/1.1 403 Forbidden`*

### 4. 目錄遍歷與雙重編碼逃逸攔截（Path Traversal - 阻擋 403 Forbidden）
```powershell
curl -i "http://localhost:8080/download?file=%252e%252e%252fetc/passwd"
```
*預期回應：`HTTP/1.1 403 Forbidden`（雙重編碼被成功解析並還原阻擋）*

### 5. 系統指令注入攔截（Command Injection - 阻擋 403 Forbidden）
```powershell
curl -i "http://localhost:8080/ping?host=127.0.0.1;%20whoami"
```
*預期回應：`HTTP/1.1 403 Forbidden`*

### 6. 線上動態熱重載（免重啟容器）
```powershell
curl -i -X POST http://localhost:8080/waf/admin/reload
```
*預期回應：`HTTP/1.1 200 OK`，設定與規則立即更新生傚。*

---

## 五、 本地直接執行與自動化全套測試（免 Docker）

若不想啟動 Docker，直接在 Windows 本地開發除錯：

### 1. 啟動本機 WAF
```powershell
.\waf.exe
```

### 2. 執行自動化測試腳本
保持 `waf.exe` 執行，開新終端機執行：
```powershell
# 執行 22 項安全防護 + 頻率限制 (Rate Limit 429) 檢驗
py -u tests/test_waf.py

# 執行反向代理與真實後端聯防測試
py -u tests/test_proxy.py
```

### 3. 本地手動編譯指令（若修改了 C++ 原始碼）
```powershell
g++ -std=c++20 -D_WIN32_WINNT=0x0A00 -static -Iinclude src/main.cpp src/rule_engine.cpp src/url_utils.cpp src/config.cpp src/rate_limiter.cpp src/proxy_handler.cpp -lws2_32 -o waf.exe
```
