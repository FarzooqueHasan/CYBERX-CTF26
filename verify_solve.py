import os
import sys
import time
import subprocess
import hashlib
import json
import codecs
import urllib.request
import urllib.parse
import http.cookiejar
import re

# Import config directly
from main import LEVEL_FLAGS
import database
import signal_decoder

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def rot13(text: str) -> str:
    return codecs.encode(text, 'rot_13')

def check_db_hint_usage(team_name: str, level: int, hint_index: int) -> bool:
    import sqlite3
    db_path = os.path.join(os.path.dirname(__file__), "ctf.db")
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("""
        SELECT h.* 
        FROM team_hints h
        JOIN teams t ON h.team_id = t.id
        WHERE t.team_name = ? AND h.level = ? AND h.hint_index = ?
    """, (team_name, level, hint_index))
    res = cursor.fetchone()
    conn.close()
    return res is not None

class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def http_error_302(self, req, fp, code, msg, hdrs):
        return fp
    http_error_301 = http_error_303 = http_error_307 = http_error_302

class CookieHTTPClient:
    def __init__(self):
        self.cookies = {}
        
    def request(self, method, url, data=None, headers=None):
        if headers is None:
            headers = {}
        
        # Inject standard User-Agent and Cookies
        headers['User-Agent'] = 'Mozilla/5.0 (CyberX Verification)'
        if self.cookies:
            cookie_str = "; ".join([f"{k}={v}" for k, v in self.cookies.items()])
            headers['Cookie'] = cookie_str
            
        req_data = None
        if data:
            req_data = urllib.parse.urlencode(data).encode('utf-8')
            if 'Content-Type' not in headers:
                headers['Content-Type'] = 'application/x-www-form-urlencoded'
                
        req = urllib.request.Request(url, data=req_data, headers=headers, method=method)
        opener = urllib.request.build_opener(NoRedirectHandler)
        
        try:
            with opener.open(req) as resp:
                status = resp.status
                body = resp.read()
                resp_headers = resp.headers
        except urllib.error.HTTPError as e:
            status = e.code
            body = e.read()
            resp_headers = e.headers
        except Exception as e:
            print(f"Connection error: {e}")
            raise e
            
        # Extract cookies manually from response headers
        set_cookie_headers = resp_headers.get_all("Set-Cookie")
        if set_cookie_headers:
            for h in set_cookie_headers:
                cookie_part = h.split(";")[0]
                if "=" in cookie_part:
                    name, val = cookie_part.split("=", 1)
                    self.cookies[name.strip()] = val.strip()
                    
        # Handle redirects manually so cookies are correctly injected into the next request
        if status in (301, 302, 303, 307):
            location = resp_headers.get("Location")
            if location:
                next_url = urllib.parse.urljoin(url, location)
                next_method = "GET" if status == 303 else method
                next_data = None if status == 303 else data
                return self.request(next_method, next_url, data=next_data, headers=None)
                
        return status, body, resp_headers

def run_test_solve():
    print("[*] Starting end-to-end solve verification...")
    
    # 1. Clear database and start fresh
    if os.path.exists(database.DB_PATH):
        os.remove(database.DB_PATH)
    database.init_db()
    
    # 2. Start uvicorn server in a subprocess on port 8001
    server_process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "main:app", "--port", "8001", "--host", "127.0.0.1"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    
    # Wait for server to bind and start (with retries)
    client = CookieHTTPClient()
    base_url = "http://127.0.0.1:8001"
    
    connected = False
    headers = {}
    status_code = 0
    
    print("[*] Waiting for uvicorn server to start...")
    for attempt in range(12):
        if server_process.poll() is not None:
            stdout, stderr = server_process.communicate()
            print("--- SERVER STDOUT (Exited early) ---")
            print(stdout.decode(errors='replace'))
            print("--- SERVER STDERR (Exited early) ---")
            print(stderr.decode(errors='replace'))
            raise RuntimeError("Server exited before starting up")
        
        try:
            status_code, body, headers = client.request("GET", f"{base_url}/")
            if status_code == 200:
                connected = True
                break
        except Exception:
            pass
        time.sleep(1.0)
        
    if not connected:
        if server_process.poll() is None:
            server_process.terminate()
        stdout, stderr = server_process.communicate()
        print("--- SERVER STDOUT (Timeout) ---")
        print(stdout.decode(errors='replace'))
        print("--- SERVER STDERR (Timeout) ---")
        print(stderr.decode(errors='replace'))
        raise RuntimeError("Could not connect to uvicorn server after 12 seconds")
        
    assert status_code == 200, "Server failed to start"
    try:
        # Verify custom header exists
        x_ops_note = headers.get("X-Ops-Note")
        print(f"[+] Root page checked. X-Ops-Note Header: {x_ops_note}")
        assert x_ops_note == "check /ops/", "X-Ops-Note header missing or incorrect"
        
        # ----------------------------------------------------
        # ADVERSARIAL TESTS (Unregistered Client)
        # ----------------------------------------------------
        print("\n=== ADVERSARIAL TEST 1: Unregistered Client Access ===")
        # Requesting /dashboard without session cookie
        status_code, body, headers_dashboard = client.request("GET", f"{base_url}/dashboard")
        # Client follows redirect and lands on /register (returning 200 and registration body)
        assert status_code == 200 and "Portal Authentication" in body.decode(), "Unregistered /dashboard should redirect to /register"
        print("[+] Verified: Unregistered /dashboard redirected to /register.")

        # Requesting /api/telemetry?crew_id=1 without any credentials
        status_code, body, headers_tel = client.request("GET", f"{base_url}/api/telemetry?crew_id=1")
        # Client follows redirect and lands on /register (returning 200 and registration body)
        assert status_code == 200 and "Portal Authentication" in body.decode(), "Cold access to telemetry API should redirect to /register"
        print("[+] Verified: Cold access to telemetry API blocked (redirected).")
        
        # ----------------------------------------------------
        # STEP 1: Registration & Re-entry Checks
        # ----------------------------------------------------
        print("\n=== STEP 1: Team Registration & Re-entry ===")
        team_name = "alphaoperator@dpsrkp.net"
        
        # Verify invalid email format is rejected
        status_code, body, _ = client.request(
            "POST", 
            f"{base_url}/register", 
            data={"team_name": "invalid_email@gmail.com"}
        )
        assert "Only official @dpsrkp.net" in body.decode(), "Gmail address should be rejected"
        print("[+] Verified: Invalid email domains are blocked.")

        # Register valid email
        status_code, body, headers = client.request(
            "POST", 
            f"{base_url}/register", 
            data={"team_name": team_name}
        )
        assert status_code == 200, f"Registration failed with code {status_code}: {body.decode()}"
        print(f"[+] Team '{team_name}' registered successfully.")
        
        # Test Re-entry with the same email
        status_code, body, headers = client.request(
            "POST", 
            f"{base_url}/register", 
            data={"team_name": team_name}
        )
        assert status_code == 200 and "CyberX Induction Dashboard" in body.decode(), "Re-entry should log back in"
        print("[+] Verified: Re-entry using same email ID restored session.")
        
        # Calculate team-specific log filename
        team_hash = hashlib.md5(team_name.lower().encode()).hexdigest()
        log_filename = f"log_{team_hash}.log"
        print(f"[+] Assigned Log Filename: {log_filename}")
        
        # ----------------------------------------------------
        # ADVERSARIAL TESTS (Registered but Level 3 Locked)
        # ----------------------------------------------------
        print("\n=== ADVERSARIAL TEST 2: Locked Level Bypass Checks ===")
        # Try to access Level 3 dashboard before solving Level 1 & 2 (should return 404 since it's deleted)
        status_code, body, _ = client.request("GET", f"{base_url}/level/3/dashboard")
        assert status_code == 404, "Level 3 dashboard route should return 404"
        print("[+] Verified: Level 3 dashboard route returns 404.")

        # Try to access /level with a forged telemetry_session cookie
        client.cookies["telemetry_session"] = "forged_token_123"
        status_code, body, _ = client.request("GET", f"{base_url}/level")
        assert status_code == 200 and "Node 01: Recon & Log Analysis" in body.decode(), "Should still serve current active level (Level 1)"
        print("[+] Verified: Forged cookie does not bypass level lock on /level.")

        # Try to access non-existent Level 9
        status_code, body, _ = client.request("GET", f"{base_url}/level/9")
        assert status_code == 404, f"Level 9 should return 404, got {status_code}"
        print("[+] Verified: Level 9 bounds check returns 404.")

        # Try to call telemetry API with forged telemetry_session
        client.cookies["telemetry_session"] = "forged_token_123"
        status_code, body, _ = client.request("GET", f"{base_url}/api/telemetry?crew_id=1")
        # Should return 403 Forbidden because Level 3 is locked for this team
        assert status_code == 403, f"Locked telemetry API should return 403, got {status_code}"
        print("[+] Verified: Telemetry API blocks access when Level 3 is locked (403 Forbidden).")
        
        # Clean up forged cookie
        del client.cookies["telemetry_session"]
        
        # ----------------------------------------------------
        # STEP 2: Level 1 - Signal Acquisition
        # ----------------------------------------------------
        print("\n=== STEP 2: Level 1 (Signal Acquisition) ===")

        # Check raw Level 1 page for leak regression checks
        status_code, body, _ = client.request("GET", f"{base_url}/level")
        html_content = body.decode()
        assert "AES.new" not in html_content, "Level 1 page leaks Level 2 solve keywords!"
        assert "crew_id=1" not in html_content, "Level 1 page leaks Level 3 solve keywords!"
        assert "032a817c7d34" not in html_content, "Level 1 page leaks Level 4 solve keywords!"
        print("[+] Verified: Level 1 raw HTML does not leak solved state keywords.")

        # Test Hint Gating and usage tracking
        status_code, body, _ = client.request("GET", f"{base_url}/level/hint/1")
        assert status_code == 200, "Failed to retrieve hint 1"
        hint_json = json.loads(body.decode())
        assert "X-Ops-Note" in hint_json["hint"], "Hint content mismatch"
        print("[+] Hint 1 successfully fetched dynamically.")
        
        # Verify DB records usage
        assert check_db_hint_usage(team_name, 1, 1), "Hint usage not recorded in SQLite"
        print("[+] Verified: Hint usage logged in database.")
        
        # Check robots.txt
        status_code, body, headers = client.request("GET", f"{base_url}/robots.txt")
        assert status_code == 200
        assert "Disallow: /ops/logs/" in body.decode(), "robots.txt missing path"
        print("[+] robots.txt contains /ops/logs/ path restriction.")
        
        # Fetch log file
        status_code, body, headers = client.request("GET", f"{base_url}/ops/logs/{log_filename}")
        assert status_code == 200, f"Failed to retrieve operator log, status {status_code}"
        print("[+] Operator log retrieved successfully.")
        
        # Extract Base64 chunk
        log_text = body.decode()
        b64_chunk = None
        for line in log_text.split("\n"):
            if "Captured raw payload chunk:" in line:
                b64_chunk = line.split("Captured raw payload chunk:")[1].strip()
                break
                
        assert b64_chunk is not None, "Failed to locate Base64 payload in logs"
        print(f"[+] Extracted encoded signal chunk: {b64_chunk}")
        
        # Decode: Base64 -> Hex -> ROT13
        import base64
        hex_str = base64.b64decode(b64_chunk).decode('utf-8')
        print(f"[+] Decoded Base64 to Hex: {hex_str}")
        
        rot13_str = bytes.fromhex(hex_str).decode('utf-8')
        print(f"[+] Decoded Hex to ROT13 string: {rot13_str}")
        
        flag1 = rot13(rot13_str)
        print(f"[+] Decoded ROT13 to Flag 1: {flag1}")
        assert flag1 == LEVEL_FLAGS[1], "Flag 1 mismatch!"
        
        # Submit Flag 1
        status_code, body, headers = client.request(
            "POST", 
            f"{base_url}/level/submit", 
            data={"flag": flag1}
        )
        assert status_code == 200
        res_json = json.loads(body.decode())
        assert res_json["status"] == "correct", f"Flag 1 incorrect: {res_json}"
        print("[+] Flag 1 validated by server: Level 2 unlocked!")
        
        # ----------------------------------------------------
        # STEP 3: Level 2 - Broken Cipher
        # ----------------------------------------------------
        print("\n=== STEP 3: Level 2 (Broken Cipher) ===")
        
        # Check raw Level 2 page for leaks
        status_code, body, _ = client.request("GET", f"{base_url}/level")
        html_content = body.decode()
        assert "AES.new" not in html_content, "Level 2 page leaks decryption script!"
        assert "crew_id=1" not in html_content, "Level 2 page leaks Level 3 solve credentials!"
        assert "032a817c7d34" not in html_content, "Level 2 page leaks Level 4 solve credentials!"
        print("[+] Verified: Level 2 raw HTML does not leak solved state keywords.")
        
        # Download intercept.bin
        status_code, body, headers = client.request("GET", f"{base_url}/level/download")
        assert status_code == 200, "Failed to download Level 2 ciphertext"
        ciphertext = body
        print(f"[+] Downloaded intercept.bin ({len(ciphertext)} bytes)")
        
        # Decrypt AES-256-CBC
        key = hashlib.sha256(flag1.encode('utf-8')).digest()
        iv = b"cyberx_iv_level2"
        
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(ciphertext)
        plaintext_bytes = unpad(decrypted_padded, 16)
        plaintext = json.loads(plaintext_bytes.decode('utf-8'))
        
        print(f"[+] Decrypted JSON: {plaintext}")
        flag2 = plaintext["flag"]
        next_user = plaintext["next_user"]
        
        assert flag2 == LEVEL_FLAGS[2], "Flag 2 mismatch!"
        assert next_user == "gs_analyst04", "Next user mismatch!"
        
        # Submit Flag 2
        status_code, body, headers = client.request(
            "POST", 
            f"{base_url}/level/submit", 
            data={"flag": flag2}
        )
        assert status_code == 200
        res_json = json.loads(body.decode())
        assert res_json["status"] == "correct"
        print("[+] Flag 2 validated by server: Level 3 unlocked!")
        
        # ----------------------------------------------------
        # STEP 4: Level 3 - Access Control Breach
        # ----------------------------------------------------
        print("\n=== STEP 4: Level 3 (Access Control Breach) ===")
        
        # Check raw Level 3 login page for leaks
        status_code, body, _ = client.request("GET", f"{base_url}/level")
        html_content = body.decode()
        assert "crew_id=1" not in html_content, "Level 3 login page leaks IDOR target!"
        assert "032a817c7d34" not in html_content, "Level 3 login page leaks Level 4 stego key!"
        print("[+] Verified: Level 3 raw HTML does not leak solved state keywords.")
        
        # Portal login
        pwd = hashlib.sha1(flag2.encode('utf-8')).hexdigest()[:12]
        print(f"[+] Calculated portal password for '{next_user}': {pwd}")
        
        status_code, body, headers = client.request(
            "POST", 
            f"{base_url}/level/3/login", 
            data={"username": next_user, "password": pwd}
        )
        assert status_code == 200 and "System User Profile Feed" in body.decode(), f"Portal login failed with code {status_code}"
        print("[+] Telemetry portal authenticated successfully.")
        
        # Verify analyst own ID (4)
        status_code, body, headers = client.request("GET", f"{base_url}/api/telemetry?crew_id=4")
        assert status_code == 200
        res_json = json.loads(body.decode())
        print(f"[+] Analyst's own telemetry role: {res_json['role']}")
        
        # ----------------------------------------------------
        # ADVERSARIAL TESTS (Level 3 Unlocked, Forged Cookie)
        # ----------------------------------------------------
        print("\n=== ADVERSARIAL TEST 3: Telemetry Session Token Forgery Check ===")
        # Save valid token
        valid_telemetry_token = client.cookies.get("telemetry_session")
        
        # Stomp it with a forged session token
        client.cookies["telemetry_session"] = "forged_telemetry_token_value_999"
        status_code, body, _ = client.request("GET", f"{base_url}/api/telemetry?crew_id=1")
        # Should return 401 Unauthorized since token is invalid in DB
        assert status_code == 401, f"Forged telemetry session should return 401, got {status_code}"
        print("[+] Verified: Telemetry API blocks access for forged session cookies (401 Unauthorized).")
        
        # Restore valid token
        client.cookies["telemetry_session"] = valid_telemetry_token
        
        # Perform IDOR to query crew_id=1 (Admin)
        status_code, body, headers = client.request("GET", f"{base_url}/api/telemetry?crew_id=1")
        assert status_code == 200, "IDOR request failed"
        admin_data = json.loads(body.decode())
        print(f"[+] Administrative Telemetry Role: {admin_data['role']}")
        print(f"[+] Administrative Notes: {admin_data['telemetry']['notes']}")
        
        # Extract Flag 3
        notes_text = admin_data['telemetry']['notes']
        flag3_match = re.search(r"CYBERX\{[a-zA-Z0-9_]+\}", notes_text)
        assert flag3_match is not None, "Failed to parse Flag 3 from notes"
        flag3 = flag3_match.group(0)
        print(f"[+] Parsed Flag 3: {flag3}")
        assert flag3 == LEVEL_FLAGS[3], "Flag 3 mismatch!"
        
        # Submit Flag 3
        status_code, body, headers = client.request(
            "POST", 
            f"{base_url}/level/submit", 
            data={"flag": flag3}
        )
        assert status_code == 200
        res_json = json.loads(body.decode())
        assert res_json["status"] == "correct"
        print("[+] Flag 3 validated by server: Level 4 unlocked!")
        
        # ----------------------------------------------------
        # STEP 5: Level 4 - Recovered Device
        # ----------------------------------------------------
        print("\n=== STEP 5: Level 4 (Recovered Device) ===")
        
        # Check raw Level 4 page for leaks
        status_code, body, _ = client.request("GET", f"{base_url}/level")
        html_content = body.decode()
        assert "032a817c7d34" not in html_content, "Level 4 page leaks derived stego passphrase!"
        print("[+] Verified: Level 4 raw HTML does not leak solved state keywords.")
        
        # Verify script download works
        status_code, body_script, _ = client.request("GET", f"{base_url}/level/download/script")
        assert status_code == 200 and b"def extract_message" in body_script, "Failed to download stego decoder script"
        print("[+] Stego decoder script downloaded successfully.")

        # Download recovered.bmp
        status_code, body, headers = client.request("GET", f"{base_url}/level/download")
        assert status_code == 200
        
        recovered_bmp_path = "recovered_test.bmp"
        with open(recovered_bmp_path, "wb") as f:
            f.write(body)
            
        print(f"[+] Downloaded recovered.bmp ({len(body)} bytes)")
        
        # Derive stego passphrase: first 12 hex chars of MD5(flag3)
        stego_passphrase = hashlib.md5(flag3.encode('utf-8')).hexdigest()[:12]
        print(f"[+] Derived stego passphrase: {stego_passphrase}")
        
        # Extract message using stego tool
        flag4_bytes = signal_decoder.extract_message(recovered_bmp_path, stego_passphrase)
        flag4 = flag4_bytes.decode('utf-8', errors='ignore')
        print(f"[+] Extracted Flag 4: {flag4}")
        assert flag4 == LEVEL_FLAGS[4], "Flag 4 mismatch!"
        
        # Clean up test file
        if os.path.exists(recovered_bmp_path):
            os.remove(recovered_bmp_path)
            
        # Submit Flag 4
        status_code, body, headers = client.request(
            "POST", 
            f"{base_url}/level/submit", 
            data={"flag": flag4}
        )
        assert status_code == 200
        res_json = json.loads(body.decode())
        assert res_json["status"] == "correct"
        print("[+] Flag 4 validated by server: Induction Complete!")
        
        # ----------------------------------------------------
        # STEP 6: DB Integrity Checks
        # ----------------------------------------------------
        print("\n=== STEP 6: DB Integrity Verification ===")
        conn = database.get_db()
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM teams WHERE team_name = ?", (team_name,))
        team_row = cursor.fetchone()
        assert team_row is not None
        
        cursor.execute("SELECT level, solved_at FROM progress WHERE team_id = ? ORDER BY level ASC", (team_row["id"],))
        progress_rows = cursor.fetchall()
        
        assert len(progress_rows) == 4, "Progress count incorrect"
        for r in progress_rows:
            print(f"[+] Node 0{r['level']} Solve state: SOLVED AT {r['solved_at']}")
            assert r["solved_at"] is not None, f"Node 0{r['level']} was not marked solved in DB!"
            
        conn.close()
        print("\n[+] SUCCESS: All 4 levels solved programmatically and verified against SQLite DB!")
        
    finally:
        # Ensure server process is terminated
        server_process.terminate()
        server_process.wait()
        print("[*] Subprocess server terminated.")

if __name__ == "__main__":
    run_test_solve()
