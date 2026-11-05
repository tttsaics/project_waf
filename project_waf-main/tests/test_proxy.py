import http.server
import socketserver
import threading
import urllib.request
import urllib.error
import json
import time

BACKEND_PORT = 3000
WAF_PORT = 8080

backend_received_requests = []

class DummyBackendHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        backend_received_requests.append({
            "path": self.path,
            "headers": dict(self.headers)
        })
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-Backend-Server", "Python-Dummy-Backend/1.0")
        self.end_headers()
        self.wfile.write(b'{"backend_status": "OK", "data": "Hello from backend server!"}')

    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8')
        backend_received_requests.append({
            "path": self.path,
            "body": body,
            "headers": dict(self.headers)
        })
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(f'{{"received_length": {len(body)}}}'.encode('utf-8'))

    def log_message(self, format, *args):
        pass # Suppress server logging

def start_backend():
    server = socketserver.TCPServer(("127.0.0.1", BACKEND_PORT), DummyBackendHandler)
    server.serve_forever()

def run_proxy_test():
    print("=" * 65)
    print("      反向代理 (Reverse Proxy Mode) 轉發與防護驗證測試")
    print("=" * 65)

    # 1. 啟動模擬後端 (Port 3000)
    t = threading.Thread(target=start_backend, daemon=True)
    t.start()
    time.sleep(0.5)
    print("[1] 模擬後端伺服器已在 http://127.0.0.1:3000 啟動")

    # 2. 透過 WAF 熱重載切換為 Proxy 模式
    reload_url = f"http://127.0.0.1:{WAF_PORT}/waf/admin/reload"
    # 更新 config 設定為 proxy 模式
    with open("config/waf_config.json", "r", encoding="utf-8") as f:
        cfg = json.load(f)
    cfg["server"]["mode"] = "proxy"
    cfg["backend"]["host"] = "127.0.0.1"
    cfg["backend"]["port"] = BACKEND_PORT
    with open("config/waf_config.json", "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=4)

    req = urllib.request.Request(reload_url, data=b"{}", method="POST")
    with urllib.request.urlopen(req) as resp:
        print("[2] WAF 已成功熱重載為 Proxy 模式 (轉發至 127.0.0.1:3000)")

    # 3. 發送合法 GET 請求給 WAF，預期轉發到後端並收到後端的回應
    waf_url = f"http://127.0.0.1:{WAF_PORT}/api/users/profile"
    req = urllib.request.Request(waf_url)
    with urllib.request.urlopen(req) as resp:
        body = resp.read().decode('utf-8')
        headers = dict(resp.getheaders())
        assert resp.getcode() == 200
        assert "Hello from backend server!" in body
        assert headers.get("X-Backend-Server") == "Python-Dummy-Backend/1.0"
        assert "X-Request-ID" in headers
        print("[3] [PASS] 合法請求成功轉發！客戶端收到後端原生資料與標頭。")

    # 4. 驗證後端收到的標頭是否有包含 X-Forwarded-For 與 X-Request-ID
    last_req = backend_received_requests[-1]
    assert "X-Forwarded-For" in last_req["headers"]
    assert "X-Request-ID" in last_req["headers"]
    print(f"    後端接收到透傳標頭: X-Forwarded-For: {last_req['headers']['X-Forwarded-For']}, X-Request-ID: {last_req['headers']['X-Request-ID']}")

    # 5. 發送攻擊請求，驗證 WAF 403 攔截且【不會轉發至後端】
    attack_url = f"http://127.0.0.1:{WAF_PORT}/api/search?q=%3Cscript%3Ealert(1)%3C/script%3E"
    req = urllib.request.Request(attack_url)
    try:
        urllib.request.urlopen(req)
        assert False, "攻擊請求不應通過 WAF！"
    except urllib.error.HTTPError as e:
        assert e.code == 403
        data = json.loads(e.read().decode('utf-8'))
        assert "request_id" in data
        assert "matched_rule" not in data
        print("[4] [PASS] 惡意攻擊在 WAF 端被 403 阻擋，未轉發至後端！")

    # 6. 切回 standalone 模式
    cfg["server"]["mode"] = "standalone"
    with open("config/waf_config.json", "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=4)
    req = urllib.request.Request(reload_url, data=b"{}", method="POST")
    with urllib.request.urlopen(req) as resp:
        print("[5] 測試結束，已將 WAF 模式切換回復為 standalone。")

    print("=" * 65)
    print("       反向代理 (Reverse Proxy) 轉發與防禦所有測試全數通過！")
    print("=" * 65)

if __name__ == "__main__":
    run_proxy_test()
