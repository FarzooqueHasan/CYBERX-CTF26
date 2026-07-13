import sqlite3
import os

if os.environ.get("VERCEL"):
    DB_PATH = "/tmp/ctf.db"
elif os.path.exists("/data"):
    DB_PATH = "/data/ctf.db"
else:
    DB_PATH = os.path.join(os.path.dirname(__file__), "ctf.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    
    # Create teams table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS teams (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        team_name TEXT UNIQUE NOT NULL,
        session_token TEXT UNIQUE NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)
    
    # Create progress table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS progress (
        team_id INTEGER NOT NULL,
        level INTEGER NOT NULL,
        unlocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        solved_at TIMESTAMP,
        attempts INTEGER DEFAULT 0,
        last_attempt_at TIMESTAMP,
        PRIMARY KEY (team_id, level),
        FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE
    );
    """)
    
    # Create crew_members table for Level 3 IDOR
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS crew_members (
        crew_id INTEGER PRIMARY KEY,
        username TEXT UNIQUE NOT NULL,
        role TEXT NOT NULL,
        telemetry_data TEXT NOT NULL
    );
    """)
    
    # Create telemetry_sessions table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS telemetry_sessions (
        token TEXT PRIMARY KEY,
        team_id INTEGER NOT NULL,
        crew_id INTEGER NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE
    );
    """)

    # Create team_hints table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS team_hints (
        team_id INTEGER NOT NULL,
        level INTEGER NOT NULL,
        hint_index INTEGER NOT NULL,
        used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (team_id, level, hint_index),
        FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE CASCADE
    );
    """)
    
    # Seed crew_members table
    crew_data = [
        (1, "admin", "Director of Operations", 
         '{"status": "Nominal", "temp": "21.5C", "signal_strength": "100%", "notes": "System override complete. Terminal key: CYBERX{tru5t_but_v3r1fy}. Security protocols are currently active."}'),
        (2, "gs_analyst02", "Ground Station Lead", 
         '{"status": "Away", "temp": "22.1C", "signal_strength": "85%", "notes": "Attending safety briefing. Contact analyst04 for live data."}'),
        (3, "gs_analyst03", "Systems Technician", 
         '{"status": "Standby", "temp": "23.8C", "signal_strength": "0%", "notes": "Recalibrating downlink receivers on antenna B."}'),
        (4, "gs_analyst04", "Ground Station Analyst", 
         '{"status": "Active", "temp": "24.2C", "signal_strength": "92%", "notes": "Monitoring antenna array azimuth. Level 1 & 2 signals verified. Standard logs rotated."}')
    ]
    
    for member in crew_data:
        cursor.execute("""
        INSERT OR REPLACE INTO crew_members (crew_id, username, role, telemetry_data)
        VALUES (?, ?, ?, ?);
        """, member)
        
    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db()
    print("Database initialized successfully.")
