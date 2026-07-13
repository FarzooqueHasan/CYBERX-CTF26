# CyberX Induction CTF - Administrator Solver Guide

This guide provides the complete step-by-step walkthrough to solve all four challenge nodes of the CyberX Induction CTF. It follows the exact perspective and actions required of a participant.

---

## Challenge Setup & Parameters

Below is a reference table of the flags and derived values for the CTF:

| Node | Challenge Name | Flag Value | Key Derivation Formula | Derived Key/Secret |
|---|---|---|---|---|
| **0** | Registration | N/A | Must validate `*@dpsrkp.net` | Email serves as unique ID |
| **1** | Recon & Log Analysis | `CYBERX{r3c0n_b3f0r3_4ss4ult}` | Base64 -> Hex -> ROT13 | Hex: `504c4f52454b...` |
| **2** | Decryption & Key Derivation | `CYBERX{k3y_fr0m_ch405}` | AES-256-CBC Key = `SHA-256(Flag 1)` | Key: `5ca4a15a8161...` |
| **3** | Identity & Access Control | `CYBERX{tru5t_but_v3r1fy}` | Portal password = `SHA-1(Flag 2)[:12]` | Password: `22bc59e0dc92` |
| **4** | Image Steganography Analysis | `CYBERX{1nduct10n_c0mpl3t3_w3lc0m3}` | Stego pass = `MD5(Flag 3)[:12]` | Stego pass: `032a817c7d34` |

---

## Gated Hint System & DB Audit (For Admins)
To maintain challenge rigor, hints are **not** sent in the raw HTML body. Instead, when a user clicks a hint trigger, the frontend requests `GET /level/hint/{index}` dynamically.
The server records hint clicks in the SQLite `team_hints` table:
```sql
CREATE TABLE IF NOT EXISTS team_hints (
    team_id INTEGER NOT NULL,
    level INTEGER NOT NULL,
    hint_index INTEGER NOT NULL,
    used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (team_id, level, hint_index),
    FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE
);
```

### Auditing Hint Usage
To check which teams unlocked which hints (for point deductions), run:
```sql
SELECT t.team_name, h.level, h.hint_index, h.used_at 
FROM team_hints h
JOIN teams t ON h.team_id = t.id
ORDER BY h.used_at ASC;
```

---

## Step-by-Step Solver Walkthrough

### Step 1: Portal Authentication
1. Navigate to the landing page at `http://127.0.0.1:8000/`.
2. Click **Initialize Operator Session** (or navigate to `/register`).
3. Enter an official school email ending in `@dpsrkp.net` (e.g. `student@dpsrkp.net`).
4. Click **Enter Portal**. The system will save your session cookie and redirect you to the dashboard.
   > [!NOTE]
   > To re-enter or resume your progress on another machine, simply register with the exact same email address. The server will restore your existing session and unlocked state.

---

### Step 2: Node 01 - Recon & Log Analysis
1. From the dashboard, click **Access Active Challenge** (pointing to `http://127.0.0.1:8000/level`).
2. Open your browser's Developer Tools (`F12` or inspect element) and go to the **Network** tab.
3. Reload the page and select the main document request. Inspect the **Response Headers**.
4. Find the custom header:
   ```http
   X-Ops-Note: check /ops/
   ```
5. Navigate to `http://127.0.0.1:8000/robots.txt`. It contains:
   ```text
   User-agent: *
   Disallow: /ops/logs/
   ```
6. Calculate the MD5 checksum of your registered email ID (lowercase, trimmed).
   - For example, for `student@dpsrkp.net`:
     ```python
     import hashlib
     hashlib.md5(b"student@dpsrkp.net").hexdigest() # e.g. 5d57b293c66f7f63110292ffcd4e6b18
     ```
7. Navigate to the log location: `http://127.0.0.1:8000/ops/logs/log_<md5_hash>.log`.
8. Locate the log line containing the anomalous debug payload:
   ```text
   2026-07-12 10:11:42 - DEBUG - Captured raw payload chunk: NTA0YzRmNTI0NTRiN2I2NTMzNzAzMDYxNWY2ZjMzNzMzMDY1MzM1ZjM0NjY2NjM0Njg3OTY3N2Q=
   ```
9. Decode the payload through the three layers:
   - **Base64 Decode**: `NTA0YzRmNTI0NTRiN2I2NTMzNzAzMDYxNWY2ZjMzNzMzMDY1MzM1ZjM0NjY2NjM0Njg3OTY3N2Q=` decodes to the hex string `504c4f52454b7b65337030615f6f33733065335f346666346879677d`.
   - **Hex Decode**: Decode the hex string to get the ROT-13 text: `PLOREK{e3p0a_o3s0e3_4ff4hyg}`.
   - **ROT13 Decode**: Rotate characters by 13 places to reveal the flag:
     `CYBERX{r3c0n_b3f0r3_4ss4ult}`.
10. Submit `CYBERX{r3c0n_b3f0r3_4ss4ult}` in the input field on `/level`. The page will dynamically update and proceed to Node 02.

---

### Step 3: Node 02 - Decryption & Key Derivation
1. On the dynamic `/level` page, click **Download intercept.bin** to retrieve the encrypted binary payload (64 bytes).
2. The encryption parameters are:
   - **Algorithm**: AES-256-CBC
   - **IV (hex)**: `6379626572785f69765f6c6576656c32` (text representation: `cyberx_iv_level2`)
   - **Key**: `SHA-256(CYBERX{r3c0n_b3f0r3_4ss4ult})`
3. Execute a python script locally to decrypt the payload (using `pycryptodome` library).
   ```python
   from Crypto.Cipher import AES
   from Crypto.Util.Padding import unpad
   import hashlib
   import json

   key = hashlib.sha256(b"CYBERX{r3c0n_b3f0r3_4ss4ult}").digest()
   iv = b"cyberx_iv_level2"

   with open("intercept.bin", "rb") as f:
       ciphertext = f.read()

   cipher = AES.new(key, AES.MODE_CBC, iv)
   plaintext = unpad(cipher.decrypt(ciphertext), 16)

   print(json.loads(plaintext.decode('utf-8')))
   ```
4. The output displays:
   ```json
   {"flag": "CYBERX{k3y_fr0m_ch405}", "next_user": "gs_analyst04"}
   ```
5. Submit `CYBERX{k3y_fr0m_ch405}` on `/level`. The page will load the Telemetry Portal login page.

---

### Step 4: Node 03 - Identity & Access Control
1. Retrieve the credentials from the decrypted JSON of Node 02:
   - **Username**: `gs_analyst04`
   - **Passphrase**: First 12 hex characters of `SHA-1(CYBERX{k3y_fr0m_ch405})`.
     - Run: `hashlib.sha1(b"CYBERX{k3y_fr0m_ch405}").hexdigest()` -> `22bc59e0dc92131...`
     - Password = `22bc59e0dc92`
2. Enter these credentials on the Telemetry Portal authentication card and click **Submit**.
3. Upon logging in, the dynamic `/level` page will render the *System User Profile Feed*.
4. Open your browser's Developer Tools and navigate to the **Network** tab.
5. Notice an API request was dispatched to fetch your user details:
   ```http
   GET /api/telemetry?crew_id=4
   ```
6. Exploit the Insecure Direct Object Reference (IDOR) flaw by modifying the query parameter in your browser console or a new tab to request ID `1` (the system administrator):
   - console command:
     ```javascript
     fetch('/api/telemetry?crew_id=1').then(r => r.json()).then(console.log)
     ```
7. The API returns:
   ```json
   {
     "crew_id": 1,
     "username": "admin",
     "role": "Director of Operations",
     "telemetry": {
       "notes": "System override complete. Terminal key: CYBERX{tru5t_but_v3r1fy}. Security protocols are currently active."
     }
   }
   ```
8. Submit `CYBERX{tru5t_but_v3r1fy}` in the flag submission form. The page updates to Node 04.

---

### Step 5: Node 04 - Image Steganography Analysis
1. Download both the memory image `recovered.bmp` and the python decoder script `signal_decoder.py` using the links on `/level`.
2. Compute the stego passphrase: the first 12 hex characters of `MD5(CYBERX{tru5t_but_v3r1fy})`.
   - Run: `hashlib.md5(b"CYBERX{tru5t_but_v3r1fy}").hexdigest()` -> `032a817c7d3448a3...`
   - Stego Passphrase = `032a817c7d34`
3. Run the decoder script in your terminal:
   ```bash
   python signal_decoder.py extract recovered.bmp 032a817c7d34
   ```
4. The script extracts and prints the final flag:
   ```text
   CYBERX{1nduct10n_c0mpl3t3_w3lc0m3}
   ```
5. Submit `CYBERX{1nduct10n_c0mpl3t3_w3lc0m3}` to complete the Induction CTF. The application redirects you back to the dashboard, displaying the **Induction Completed** check status!
