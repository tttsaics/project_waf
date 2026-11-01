import urllib.request
import urllib.parse
import json
import time

BASE_URL = "http://localhost:8080"

test_cases = [
    # 正常請求 (預期 200 OK)
    {
        "name": "正常首頁請求",
        "method": "GET",
        "path": "/",
        "expected_status": 200
    },
    {
        "name": "正常商品查詢",
        "method": "GET",
        "path": "/products?category=books&page=2",
        "expected_status": 200
    },
    {
        "name": "正常使用者登入 POST",
        "method": "POST",
        "path": "/api/login",
        "body": "username=alice&password=mypassword123",
        "expected_status": 200
    },

    # 攻擊請求：SQL 注入 (預期 403 Forbidden)
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
        "name": "SQLi POST 表單注入 (堆疊指令 DROP TABLE)",
        "method": "POST",
        "path": "/api/feedback",
        "body": "content=hello; DROP TABLE users; --",
        "expected_status": 403
    },

    # 攻擊請求：XSS 跨站腳本攻擊 (預期 403 Forbidden)
    {
        "name": "XSS 標籤注入 (<script>alert(1)</script>)",
        "method": "GET",
        "path": "/search?q=%3Cscript%3Ealert(1)%3C/script%3E",
        "expected_status": 403
    },
    {
        "name": "XSS 事件處理偽協議 (onerror=alert)",
        "method": "GET",
        "path": "/avatar?img=x%22%20onerror=%22alert(1)",
        "expected_status": 403
    },

    # 攻擊請求：路徑穿越 (預期 403 Forbidden)
    {
        "name": "Path Traversal (../../etc/passwd)",
        "method": "GET",
        "path": "/download?file=../../etc/passwd",
        "expected_status": 403
    },

    # 攻擊請求：指令注入 (預期 403 Forbidden)
    {
        "name": "Command Injection (; whoami)",
        "method": "GET",
        "path": "/ping?host=127.0.0.1;%20whoami",
        "expected_status": 403
    }
]

def run_tests():
    print("=" * 60)
    print("        WAF 自動化測試腳本 (Verification Suite)")
    print("=" * 60)
    
    passed_count = 0
    total_count = len(test_cases)

    for i, tc in enumerate(test_cases, 1):
        url = BASE_URL + tc["path"]
        data = tc.get("body", None)
        if data:
            data = data.encode("utf-8")

        req = urllib.request.Request(url, data=data, method=tc["method"])
        req.add_header("User-Agent", "WAF-Test-Runner/1.0")
        if data:
            req.add_header("Content-Type", "application/x-www-form-urlencoded")

        try:
            with urllib.request.urlopen(req, timeout=3) as resp:
                status_code = resp.getcode()
                body = resp.read().decode("utf-8", errors="ignore")
        except urllib.error.HTTPError as e:
            status_code = e.code
            body = e.read().decode("utf-8", errors="ignore")
        except Exception as e:
            print(f"[{i}/{total_count}] [ERROR] 測試失敗: {tc['name']} - 無法連接 WAF: {e}")
            continue

        if status_code == tc["expected_status"]:
            print(f"[{i:02d}/{total_count:02d}] [PASS] 通過 | 狀態碼: {status_code} | {tc['name']}")
            passed_count += 1
        else:
            print(f"[{i:02d}/{total_count:02d}] [FAIL] 未通過 | 期望 {tc['expected_status']} 但得到 {status_code} | {tc['name']}")
            print(f"       回應內容: {body.strip()}")

    print("=" * 60)
    print(f"測試完成: 共 {total_count} 項，通過 {passed_count} 項，失敗 {total_count - passed_count} 項。")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()
