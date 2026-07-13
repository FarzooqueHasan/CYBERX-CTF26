# CyberX Club Induction CTF — Design Plan

## 1. Design Principles

- **4 levels**, difficulty ramping Medium → Medium-Hard.
- **Real technical challenges**, not riddles. Every level tests a genuine, namable skill (recon, applied crypto, web auth logic, forensics).
- **Functionally chained, not just narratively chained.** Each level's flag is required as an input (key derivation, password, credential seed) to reach the next level's content — so there's no "click next" moment that can be faked or shared without doing the work.
- **Server is the only source of truth.** No flag, hash, or unlock state ever lives in HTML, JS, cookies, or localStorage. All progress is checked against the database on every request.
- **No SQL injection.** Every query is parameterized. The intended vulnerability in Level 3 is a *logic flaw* (broken access control), not injection — a more realistic and more teachable bug class anyway.
- **No console override.** Because unlock state lives server-side, there's nothing for a participant to flip in devtools. Opening the console should be a dead end.

Optional theme: since AEROSS gives you an obvious hook, you could wrap this as a "compromised ground-station" narrative (Level 1: intercept a transmission, Level 4: recover data from a crashed device). Purely cosmetic — swap for anything you like without touching the mechanics below.

---

## 2. Architecture

Same stack as AarogyaLink/YatraMitr: **FastAPI + SQLite + vanilla HTML/JS.**

```
Participant registers (team name) → gets session_token (httpOnly cookie)
        │
        ▼
GET /level/{n}  ──► server checks progress table: is level n unlocked for this team?
        │                     │
        │ yes                │ no
        ▼                    ▼
  serve level content    403 / redirect to current level
        │
        ▼
POST /level/{n}/submit  ──► hash submitted flag, compare (constant-time) to stored hash
        │
        ├─ correct → mark level n solved, unlock level n+1, log solved_at
        └─ wrong   → increment attempt counter, generic "incorrect" response
```

### Database schema

```sql
CREATE TABLE teams (
    id INTEGER PRIMARY KEY,
    team_name TEXT UNIQUE NOT NULL,
    session_token TEXT UNIQUE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE progress (
    team_id INTEGER NOT NULL REFERENCES teams(id),
    level INTEGER NOT NULL,
    unlocked_at TIMESTAMP,
    solved_at TIMESTAMP,
    attempts INTEGER DEFAULT 0,
    PRIMARY KEY (team_id, level)
);
```

### Flag validation (illustrative)

```python
import hmac, hashlib
from fastapi import HTTPException, Depends

SERVER_SECRET = "changeme-long-random-string"  # from env var, never in git

def flag_hash(flag: str) -> str:
    return hmac.new(SERVER_SECRET.encode(), flag.strip().encode(), hashlib.sha256).hexdigest()

LEVEL_FLAG_HASHES = {
    1: flag_hash("CYBERX{r3c0n_b3f0r3_4ss4ult}"),
    2: flag_hash("CYBERX{k3y_fr0m_ch405}"),
    3: flag_hash("CYBERX{tru5t_but_v3r1fy}"),
    4: flag_hash("CYBERX{1nduct10n_c0mpl3t3_w3lc0m3}"),
}

@app.post("/level/{level}/submit")
def submit_flag(level: int, payload: FlagSubmit, team=Depends(get_team_from_session)):
    prog = get_progress(team.id, level)
    if level != get_current_level(team.id):
        raise HTTPException(403, "Level locked")
    if prog.attempts >= 10:
        raise HTTPException(429, "Too many attempts — cool down")
    increment_attempts(team.id, level)
    if hmac.compare_digest(flag_hash(payload.flag), LEVEL_FLAG_HASHES[level]):
        unlock_next_level(team.id, level)
        return {"status": "correct"}
    return {"status": "incorrect"}
```

Notice: the flag/hash never leaves the Python process. The response is always a bare `correct`/`incorrect` — nothing to inspect in Network tab that helps guess.

---

## 3. The Four Levels

### Level 1 — "Signal Acquisition" (Recon + Multi-Layer Encoding) · Medium

**Skill tested:** HTTP recon, layered decoding.

- Landing page includes a custom response header, e.g. `X-Ops-Note: check /ops/`.
- `/ops/` returns 403, but `robots.txt` discloses `Disallow: /ops/logs/`.
- `/ops/logs/<filename>.log` (directory listing off; filename given via a small clue at registration, so it's findable, not brute-forceable) contains junk log lines plus one anomalous string.
- That string is **Base64 → Hex → ROT13**, decoding to the flag.
- Flag: `CYBERX{r3c0n_b3f0r3_4ss4ult}`

**Est. time:** 20–30 min.
**Hint ladder (point-cost):** "Check response headers" → "robots.txt is a map, not a wall" → "Three layers, oldest cipher last."

---

### Level 2 — "Broken Cipher" (Applied Symmetric Crypto) · Medium

**Skill tested:** AES decryption, key derivation, basic scripting (Python/pycryptodome or CyberChef).

- Only reachable once Level 1 is marked solved server-side.
- Page offers `intercept.bin` (AES-256-CBC ciphertext) with the IV shown in hex.
- Documented rule: **key = SHA-256(level-1 flag string, UTF-8)**. This forces them to actually use flag 1 — not just remember it.
- Decrypted plaintext is JSON: `{"flag": "CYBERX{k3y_fr0m_ch405}", "next_user": "gs_analyst04"}`.
- On correct submission, server stores `next_user` against the team and uses it to provision their Level 3 login — so the credential is server-issued, not something they type in from memory.

**Est. time:** 30–45 min.
**Hints:** "AES needs mode + IV — both given." "Hash the flag exactly as submitted, no extra whitespace."

---

### Level 3 — "Access Control Breach" (Web Exploitation, non-SQLi) · Medium-Hard

**Skill tested:** Broken object-level authorization (OWASP API3) — a realistic bug class, no injection involved.

- Login page uses the Level-2-issued username; password = first 12 hex chars of `SHA1(flag2)` (documented on-page). All auth queries are parameterized — genuinely SQLi-proof.
- Post-login dashboard fetches `/api/telemetry?crew_id=<own_id>` for the logged-in analyst's own record.
- **The vulnerability:** the endpoint checks that the session is valid, but never checks that `crew_id` in the query belongs to that session. Changing `crew_id` (via browser devtools "Edit and Resend," curl, or Postman — no console trickery, just normal request inspection) to another value returns someone else's record.
- `crew_id=1` (admin) has flag3 embedded in a notes field: `CYBERX{tru5t_but_v3r1fy}`.

This teaches a real, common vulnerability class without touching your "no SQLi" constraint at all.

**Est. time:** 40–60 min.
**Hints:** "Every request says who's asking *and* what they're asking for. Is the server checking both?" "Try being someone else's crew_id."

---

### Level 4 — "Recovered Device" (Forensics / Steganography) · Medium-Hard

**Skill tested:** File forensics, steganography extraction.

- Downloadable `recovered.png`, LSB-steganography encoded (via `steghide` or a simple custom LSB embed script you write ahead of time).
- Passphrase to extract = **first 12 hex chars of MD5(flag3)** — documented, again forcing a real derivation step rather than memorization.
- `steghide extract -sf recovered.png` (or your custom extractor, if you hint at the scheme) yields `final.txt`:
  `CYBERX{1nduct10n_c0mpl3t3_w3lc0m3}`
- Submitting it marks induction complete and logs completion time for the leaderboard.

**Est. time:** 45–75 min.
**Hints:** "Images can carry more than pixels." "The steghide man page has everything you need."

---

## 4. Anti-Loophole Checklist (do this before going live)

- [ ] No flag or flag-hash appears anywhere in HTML, JS, CSS, or API responses — grep your entire frontend bundle for the string `CYBERX{` before shipping.
- [ ] Flag comparison uses `hmac.compare_digest` (constant-time), never `==`.
- [ ] All SQL uses parameterized queries (SQLAlchemy/SQLModel or `?` placeholders) — never string formatting.
- [ ] Progress/unlock state lives only in the `progress` table — nothing in localStorage, sessionStorage, or client JS variables controls access.
- [ ] Session tokens are httpOnly cookies (not readable/editable from console).
- [ ] Level N+1 static files are **not** sitting in a public folder waiting to be found early — serve them from a non-web-exposed directory via an authenticated route that checks the DB first.
- [ ] Directory listing disabled on the web server.
- [ ] Submission endpoint is rate-limited (e.g. 10 attempts/level, then a cooldown) to block brute force.
- [ ] Generic error messages only — never "wrong, but close" or anything that leaks partial correctness.
- [ ] **Red-team pass:** before the event, have one or two people *not* involved in building it try to break it — view-source diving, guessing file paths, replaying/tampering requests, poking the console. Fix whatever they find.

---

## 5. Scoring & Timing

- Suggested window: **2.5–3 hours**, on-site, one attempt window per team (individual or pairs — your call based on expected turnout).
- Base points per level, decreasing slightly with each hint used (e.g. Level 1: 100 pts, −15 per hint).
- Time-to-complete as a tiebreaker, not the primary score — rewards correctness and understanding over speed alone, which suits an induction filter better than a pure speed-CTF.
- A simple live leaderboard page (read-only, no participant-facing progress details beyond their own) adds good energy without leaking anything.

---

## 6. Build Timeline (suggested)

| Day | Task |
|---|---|
| 1 | Scaffold FastAPI app, DB schema, registration + session auth |
| 2 | Build Level 1 (recon files, encoding chain) + submission endpoint |
| 3 | Build Level 2 (AES encrypt the intercept file, key-derivation docs) |
| 4 | Build Level 3 (mini portal, deliberately-missing authorization check) |
| 5 | Build Level 4 (stego encode, extraction docs) |
| 6 | End-to-end test as a "team" yourself, solving all 4 levels clean |
| 7 | Red-team pass by an outsider + patch findings + deploy |

---

## 7. Optional Stretch Ideas

- **Per-team unique flags:** seed each team's flags from `team_id` so solutions can't be shared across teams verbatim. Adds real complexity — only worth it if you're worried about answer-sharing between induction batches.
- **Admin dashboard:** simple internal page showing each team's current level, attempts, and timestamps — useful for live-monitoring the event and catching stuck teams for hints.

---

This should give you a rigorous, self-contained induction CTF that tests recon, crypto, web security, and forensics — with no accidental frontend leaks and nothing exploitable outside the intended puzzle. Happy to help scaffold the actual FastAPI app next, the same way we've staged your other builds.
