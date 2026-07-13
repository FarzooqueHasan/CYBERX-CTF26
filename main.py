import os
import hmac
import shutil
import hashlib
from datetime import datetime
import sqlite3
from typing import Optional

from fastapi import FastAPI, Request, Depends, HTTPException, status, Form, Cookie, Response
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse, PlainTextResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from PIL import Image

import database
import signal_decoder

# Server configuration
SERVER_SECRET = "cyberx-ctf-super-secret-key-2026"
LEVEL_FLAGS = {
    1: "CYBERX{r3c0n_b3f0r3_4ss4ult}",
    2: "CYBERX{k3y_fr0m_ch405}",
    3: "CYBERX{tru5t_but_v3r1fy}",
    4: "CYBERX{1nduct10n_c0mpl3t3_w3lc0m3}"
}

def flag_hash(flag: str) -> str:
    return hmac.new(SERVER_SECRET.encode(), flag.strip().encode(), hashlib.sha256).hexdigest()

LEVEL_FLAG_HASHES = {level: flag_hash(flag) for level, flag in LEVEL_FLAGS.items()}

app = FastAPI(title="CyberX Club Induction CTF")

# Directories setup
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")

if os.environ.get("VERCEL"):
    NON_PUBLIC_DIR = "/tmp/non_public"
else:
    NON_PUBLIC_DIR = os.path.join(BASE_DIR, "non_public")

os.makedirs(NON_PUBLIC_DIR, exist_ok=True)

# Mount static files
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

templates = Jinja2Templates(directory=TEMPLATES_DIR)

# Setup challenges assets on startup
def generate_challenge_assets():
    # 1. Copy generated ground station image and create recovered.bmp (LSB stego)
    artifact_img = r"C:\Users\dpset\.gemini\antigravity\brain\2fe3c668-dfaa-4d37-a438-8d18ca2769fb\raw_ground_station_1783833219830.png"
    dest_png = os.path.join(NON_PUBLIC_DIR, "raw_ground_station.png")
    carrier_bmp = os.path.join(NON_PUBLIC_DIR, "carrier.bmp")
    recovered_bmp = os.path.join(NON_PUBLIC_DIR, "recovered.bmp")
    
    # Copy from artifact if it exists, otherwise create a fallback image
    if os.path.exists(artifact_img):
        shutil.copy(artifact_img, dest_png)
    else:
        # Fallback raw PNG if artifact not found
        img = Image.new("RGB", (512, 512), color=(10, 12, 16))
        img.save(dest_png)
        
    # Convert PNG to BMP (uncompressed 24-bit RGB)
    img = Image.open(dest_png)
    img.save(carrier_bmp, "BMP")
    
    # Stego passphrase = first 12 hex chars of MD5 of Flag 3
    passphrase = hashlib.md5(LEVEL_FLAGS[3].encode('utf-8')).hexdigest()[:12] # 032a817c7d34
    
    # Hide Flag 4 in carrier.bmp
    flag_bytes = LEVEL_FLAGS[4].encode('utf-8')
    signal_decoder.hide_message(carrier_bmp, recovered_bmp, flag_bytes, passphrase)
    
    # Clean up intermediate carrier BMP
    if os.path.exists(carrier_bmp):
        os.remove(carrier_bmp)
        
    # 2. Create intercept.bin (AES encrypted file) for Level 2
    # Key = SHA-256 of Flag 1
    key = hashlib.sha256(LEVEL_FLAGS[1].encode('utf-8')).digest()
    iv = b"cyberx_iv_level2"
    plaintext = b'{"flag": "CYBERX{k3y_fr0m_ch405}", "next_user": "gs_analyst04"}'
    
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, 16))
    
    intercept_bin = os.path.join(NON_PUBLIC_DIR, "intercept.bin")
    with open(intercept_bin, "wb") as f:
        f.write(ciphertext)

@app.on_event("startup")
def startup_event():
    database.init_db()
    generate_challenge_assets()

# Database and Session Helpers
def get_team_from_db(token: str):
    conn = database.get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM teams WHERE session_token = ?", (token,))
    team = cursor.fetchone()
    conn.close()
    return team

def get_current_level(team_id: int) -> int:
    conn = database.get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT MAX(level) as max_level FROM progress WHERE team_id = ? AND solved_at IS NOT NULL", (team_id,))
    res = cursor.fetchone()
    conn.close()
    if res and res["max_level"] is not None:
        return min(4, res["max_level"] + 1)
    return 1

def is_level_unlocked(team_id: int, level: int) -> bool:
    if level == 1:
        return True
    conn = database.get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT solved_at FROM progress WHERE team_id = ? AND level = ?", (team_id, level - 1))
    res = cursor.fetchone()
    conn.close()
    return res is not None and res["solved_at"] is not None

def get_progress_record(team_id: int, level: int):
    conn = database.get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM progress WHERE team_id = ? AND level = ?", (team_id, level))
    res = cursor.fetchone()
    conn.close()
    return res

def ensure_progress_record(team_id: int, level: int):
    conn = database.get_db()
    cursor = conn.cursor()
    cursor.execute("INSERT OR IGNORE INTO progress (team_id, level) VALUES (?, ?)", (team_id, level))
    conn.commit()
    conn.close()

def record_hint_used(team_id: int, level: int, hint_index: int):
    conn = database.get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT OR IGNORE INTO team_hints (team_id, level, hint_index) VALUES (?, ?, ?)",
            (team_id, level, hint_index)
        )
        conn.commit()
    except Exception:
        pass
    finally:
        conn.close()

async def get_active_team(session_token: Optional[str] = Cookie(None)):
    if not session_token:
        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            detail="Not registered",
            headers={"Location": "/register"}
        )
    team = get_team_from_db(session_token)
    if not team:
        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            detail="Invalid session",
            headers={"Location": "/register"}
        )
    return team

@app.get("/", response_class=HTMLResponse)
def index(request: Request, session_token: Optional[str] = Cookie(None)):
    team = None
    if session_token:
        team = get_team_from_db(session_token)
    res = templates.TemplateResponse("index.html", {"request": request, "team": team})
    res.headers["X-Ops-Note"] = "check /ops/"
    return res

@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request, session_token: Optional[str] = Cookie(None)):
    if session_token:
        team = get_team_from_db(session_token)
        if team:
            return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse("register.html", {"request": request})

@app.post("/register")
def register_team(team_name: str = Form(...)):
    email = team_name.strip().lower()
    import re
    if not re.match(r"^[a-zA-Z0-9._%+-]+@dpsrkp\.net$", email):
        return RedirectResponse(
            url="/register?error=Only+official+@dpsrkp.net+email+IDs+are+allowed",
            status_code=status.HTTP_303_SEE_OTHER
        )
        
    conn = database.get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM teams WHERE team_name = ?", (email,))
    team = cursor.fetchone()
    
    if team:
        token = team["session_token"]
    else:
        token = hashlib.sha256(os.urandom(32)).hexdigest()
        try:
            cursor.execute("INSERT INTO teams (team_name, session_token) VALUES (?, ?)", (email, token))
            team_id = cursor.lastrowid
            cursor.execute("INSERT INTO progress (team_id, level) VALUES (?, 1)", (team_id,))
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            return RedirectResponse(
                url="/register?error=Registration+failed.+Please+try+again.",
                status_code=status.HTTP_303_SEE_OTHER
            )
    conn.close()
    
    res = RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    res.set_cookie(key="session_token", value=token, httponly=True, samesite="lax", max_age=86400)
    return res

@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, team=Depends(get_active_team)):
    current_level = get_current_level(team["id"])
    
    # Load level unlock states
    levels_status = []
    for l in range(1, 5):
        unlocked = is_level_unlocked(team["id"], l)
        solved = False
        prog = get_progress_record(team["id"], l)
        if prog and prog["solved_at"] is not None:
            solved = True
        
        status_str = "solved" if solved else ("active" if l == current_level else ("unlocked" if unlocked else "locked"))
        levels_status.append({
            "number": l,
            "status": status_str,
            "solved_at": prog["solved_at"] if prog else None
        })
        
    # Get leaderboard
    conn = database.get_db()
    cursor = conn.cursor()
    # To compute leaderboard score:
    # Count of levels solved + timestamp of last level solve (asc)
    cursor.execute("""
        SELECT t.team_name, 
               COUNT(p.solved_at) as solved_count,
               MAX(p.solved_at) as last_solve_time
        FROM teams t
        LEFT JOIN progress p ON t.id = p.team_id AND p.solved_at IS NOT NULL
        GROUP BY t.id
        ORDER BY solved_count DESC, last_solve_time ASC, t.created_at ASC
    """)
    leaderboard_data = cursor.fetchall()
    conn.close()
    
    # Operator file clue calculation
    team_hash = hashlib.md5(team["team_name"].strip().lower().encode()).hexdigest()
    log_filename = f"log_{team_hash}.log"
    
    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "team": team,
        "levels": levels_status,
        "leaderboard": leaderboard_data,
        "log_filename": log_filename,
        "current_level": current_level
    })

@app.get("/level", response_class=HTMLResponse)
def level_page(request: Request, telemetry_session: Optional[str] = Cookie(None), team=Depends(get_active_team)):
    level = get_current_level(team["id"])
    
    # If the user has solved all levels, redirect to dashboard
    if level > 4:
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
        
    ensure_progress_record(team["id"], level)
    prog = get_progress_record(team["id"], level)
    solved = prog["solved_at"] is not None if prog else False
    
    context = {
        "request": request,
        "team": team,
        "level": level,
        "solved": solved,
        "attempts": prog["attempts"] if prog else 0,
        "iv_hex": "6379626572785f69765f6c6576656c32",
        "md5_hint": "first 12 hex characters of MD5(flag3)"
    }
    
    if level == 1:
        return templates.TemplateResponse("level1.html", context)
    elif level == 2:
        return templates.TemplateResponse("level2.html", context)
    elif level == 3:
        # Check telemetry session
        sess = get_telemetry_session(telemetry_session)
        if sess and sess["team_id"] == team["id"]:
            context["own_crew_id"] = sess["crew_id"]
            return templates.TemplateResponse("level3_dashboard.html", context)
        else:
            return templates.TemplateResponse("level3.html", context)
    elif level == 4:
        return templates.TemplateResponse("level4.html", context)
        
    raise HTTPException(status_code=404, detail="Level not found")
    
@app.post("/level/submit")
def submit_flag(flag: str = Form(...), team=Depends(get_active_team)):
    level = get_current_level(team["id"])
    if level > 4:
        return JSONResponse(status_code=403, content={"status": "incorrect", "message": "All levels solved"})
        
    ensure_progress_record(team["id"], level)
    prog = get_progress_record(team["id"], level)
    
    # Cooldown & Rate limiting check
    attempts = prog["attempts"]
    last_attempt = prog["last_attempt_at"]
    
    if attempts >= 10:
        if last_attempt:
            dt_last = datetime.fromisoformat(last_attempt)
            delta = (datetime.utcnow() - dt_last).total_seconds()
            if delta < 120:
                # 2-minute cooldown active
                return JSONResponse(status_code=429, content={"status": "cooldown", "message": "Too many attempts. Cooldown active."})
            else:
                # Reset attempts or allow
                conn = database.get_db()
                cursor = conn.cursor()
                cursor.execute("UPDATE progress SET attempts = 0 WHERE team_id = ? AND level = ?", (team["id"], level))
                conn.commit()
                conn.close()
                attempts = 0
        else:
            attempts = 0
            
    # Increment attempts
    conn = database.get_db()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE progress 
        SET attempts = attempts + 1, last_attempt_at = ? 
        WHERE team_id = ? AND level = ?
    """, (datetime.utcnow().isoformat(), team["id"], level))
    conn.commit()
    conn.close()
    
    # Hash check
    submitted_hash = flag_hash(flag)
    if hmac.compare_digest(submitted_hash, LEVEL_FLAG_HASHES[level]):
        # Correct! Mark solved and unlock next level
        conn = database.get_db()
        cursor = conn.cursor()
        now_str = datetime.utcnow().isoformat()
        cursor.execute("UPDATE progress SET solved_at = ? WHERE team_id = ? AND level = ?", (now_str, team["id"], level))
        if level < 4:
            cursor.execute("INSERT OR REPLACE INTO progress (team_id, level, unlocked_at) VALUES (?, ?, ?)", (team["id"], level + 1, now_str))
        conn.commit()
        conn.close()
        return JSONResponse(content={"status": "correct"})
        
    return JSONResponse(content={"status": "incorrect"})

# Secure challenge files download routes
@app.get("/level/download")
def download_level_file(team=Depends(get_active_team)):
    level = get_current_level(team["id"])
    if level == 2:
        file_path = os.path.join(NON_PUBLIC_DIR, "intercept.bin")
        return FileResponse(path=file_path, filename="intercept.bin", media_type="application/octet-stream")
    elif level == 4:
        file_path = os.path.join(NON_PUBLIC_DIR, "recovered.bmp")
        return FileResponse(path=file_path, filename="recovered.bmp", media_type="image/bmp")
        
    raise HTTPException(status_code=403, detail="Forbidden")

@app.get("/level/download/script")
def download_level_script(team=Depends(get_active_team)):
    level = get_current_level(team["id"])
    if level == 4:
        file_path = os.path.join(BASE_DIR, "signal_decoder.py")
        return FileResponse(path=file_path, filename="signal_decoder.py", media_type="text/x-python")
        
    raise HTTPException(status_code=403, detail="Forbidden")

HINTS = {
    (1, 1): "Open your browser's developer tools (F12), select the Network tab, and reload the root page (/). Examine the HTTP response headers of the root document request for a custom header named X-Ops-Note.",
    (1, 2): "Accessing /ops/ directly returns a 403 Forbidden. However, search engines locate index paths using /robots.txt. Access /robots.txt in your browser to discover the disallowed directory path where your log file is served.",
    (1, 3): "Locate the anomalous Base64 string in the log. Decode the Base64 block using Python or CyberChef to get hex bytes. Decode that Hex string to text to get the ROT-13 representation, then decode ROT-13 to recover the flag.",
    
    (2, 1): "The key is the raw 32-byte SHA-256 digest of the level 1 flag. In Python: hashlib.sha256(b'CYBERX{...}').digest().",
    (2, 2): "Use the pycryptodome library. Create a new cipher using AES.new(key, AES.MODE_CBC, iv), decrypt the binary payload, and unpad the result with unpad(..., 16) — the key and IV are defined in the payload details above.",
    
    (3, 1): "Open your developer tools (F12) and inspect the Network tab. Look for the API request to /api/telemetry?crew_id=4. The server fetches details based on this parameter. What happens if you request the profile for another user ID?",
    (3, 2): "Try changing the crew_id query parameter to other integer values in your request. For example, what identifier is typically assigned to the first account (the administrator) created in a database?",
    
    (4, 1): "Apply the MD5 formula described in the Decryption Metadata box to the Level 3 flag. You can compute this in Python using hashlib.md5(b'CYBERX{...}').hexdigest() and take the first 12 characters.",
    (4, 2): "Execute the extraction command in your terminal using the Python script you downloaded, passing the correct image file path and the 12-character passphrase you derived in Hint 1."
}

@app.get("/level/hint/{idx}")
def get_hint(idx: int, team=Depends(get_active_team)):
    level = get_current_level(team["id"])
    hint_text = HINTS.get((level, idx))
    if not hint_text:
        raise HTTPException(status_code=404, detail="Hint not found")
        
    record_hint_used(team["id"], level, idx)
    return {"hint": hint_text}

# Level 1 Recon Dynamic Log serving route
@app.get("/ops/")
def ops_dir():
    raise HTTPException(status_code=403, detail="Forbidden - Directory listing disabled.")

@app.get("/robots.txt", response_class=PlainTextResponse)
def robots_txt():
    return "User-agent: *\nDisallow: /ops/logs/\n"

@app.get("/ops/logs/{filename}", response_class=PlainTextResponse)
def get_ops_log(filename: str, team=Depends(get_active_team)):
    # Calculate the exact expected filename for the team
    team_hash = hashlib.md5(team["team_name"].strip().lower().encode()).hexdigest()
    expected_filename = f"log_{team_hash}.log"
    
    # Prevent traversal and check team assignment matches
    if filename != expected_filename:
        raise HTTPException(status_code=403, detail="Forbidden: Log file is not assigned to your session.")
        
    # Return simulated log lines containing the flag
    # Base64 -> Hex -> ROT13 encoding of CYBERX{r3c0n_b3f0r3_4ss4ult}
    # Value: NTA0YzRmNTI0NTRiN2I2NTMzNzAzMDYxNWY2ZjMzNzMzMDY1MzM1ZjM0NjY2NjM0Njg3OTY3N2Q=
    log_content = (
        "2026-07-12 10:00:01 - INFO - Authentication portal service initialized.\n"
        "2026-07-12 10:05:32 - INFO - Connection handshake successful on channel 01.\n"
        "2026-07-12 10:10:15 - WARNING - Unexpected diagnostic data packet received.\n"
        "2026-07-12 10:11:42 - DEBUG - Captured raw payload chunk: NTA0YzRmNTI0NTRiN2I2NTMzNzAzMDYxNWY2ZjMzNzMzMDY1MzM1ZjM0NjY2NjM0Njg3OTY3N2Q=\n"
        "2026-07-12 10:12:00 - INFO - Diagnostic check complete; buffer flushed.\n"
        "2026-07-12 10:15:44 - INFO - Session idle; standing by.\n"
    )
    return log_content

def create_telemetry_session(team_id: int, crew_id: int) -> str:
    token = hashlib.sha256(os.urandom(32)).hexdigest()
    conn = database.get_db()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR REPLACE INTO telemetry_sessions (token, team_id, crew_id) VALUES (?, ?, ?)",
        (token, team_id, crew_id)
    )
    conn.commit()
    conn.close()
    return token

def get_telemetry_session(token: str):
    if not token:
        return None
    conn = database.get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM telemetry_sessions WHERE token = ?", (token,))
    res = cursor.fetchone()
    conn.close()
    return res

@app.post("/level/3/login")
def level3_login_post(
    username: str = Form(...), 
    password: str = Form(...),
    team=Depends(get_active_team)
):
    if not is_level_unlocked(team["id"], 3):
        raise HTTPException(status_code=403, detail="Forbidden")
        
    # Expected: username = gs_analyst04, password = first 12 hex chars of SHA1(flag2)
    # flag2 = CYBERX{k3y_fr0m_ch405} -> SHA1 first 12 chars = 22bc59e0dc92
    expected_username = "gs_analyst04"
    expected_pwd = hashlib.sha1(LEVEL_FLAGS[2].encode('utf-8')).hexdigest()[:12] # 22bc59e0dc92
    
    if username.strip() == expected_username and password.strip() == expected_pwd:
        # Success: Set secure telemetry session cookie mapped to database
        token = create_telemetry_session(team["id"], 4)
        res = RedirectResponse(url="/level", status_code=status.HTTP_303_SEE_OTHER)
        res.set_cookie(key="telemetry_session", value=token, httponly=True, samesite="lax")
        return res
        
    return RedirectResponse(url="/level?error=Invalid+credentials", status_code=status.HTTP_303_SEE_OTHER)

@app.get("/api/telemetry")
def get_telemetry(crew_id: int, telemetry_session: Optional[str] = Cookie(None), team=Depends(get_active_team)):
    if not is_level_unlocked(team["id"], 3):
        raise HTTPException(status_code=403, detail="Forbidden")
        
    sess = get_telemetry_session(telemetry_session)
    if not sess or sess["team_id"] != team["id"]:
        raise HTTPException(status_code=401, detail="Unauthorized - Invalid session")
        
    # IDOR Vulnerability: We do NOT check if crew_id == sess["crew_id"] (which is 4)
    # We fetch whatever crew_id is requested by the query param.
    conn = database.get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT crew_id, username, role, telemetry_data FROM crew_members WHERE crew_id = ?", (crew_id,))
    member = cursor.fetchone()
    conn.close()
    
    if not member:
        raise HTTPException(status_code=404, detail="Crew member not found")
        
    # Parse notes JSON
    import json
    try:
        telemetry_json = json.loads(member["telemetry_data"])
    except Exception:
        telemetry_json = {"notes": member["telemetry_data"]}
        
    return {
        "crew_id": member["crew_id"],
        "username": member["username"],
        "role": member["role"],
        "telemetry": telemetry_json
    }

@app.post("/logout")
def logout():
    res = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    res.delete_cookie("session_token")
    res.delete_cookie("telemetry_session")
    return res

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
