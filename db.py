"""SmartGuard — Secure SQLite Database (PBKDF2 passwords, full login history + location)"""
import sqlite3, hashlib, secrets, time
from pathlib import Path
from datetime import datetime

DB = Path(__file__).parent.parent / 'data' / 'smartguard.db'

def conn():
    c = sqlite3.connect(str(DB))
    c.row_factory = sqlite3.Row
    return c

def init():
    db = conn()
    db.executescript('''
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            pw_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            display_name TEXT,
            last_login TEXT
        );
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY,
            user_id TEXT,
            masked_ip TEXT,
            country TEXT,
            region TEXT,
            city TEXT,
            latitude REAL,
            longitude REAL,
            location_source TEXT DEFAULT 'manual',
            device TEXT,
            browser TEXT,
            os TEXT,
            risk INTEGER,
            decision TEXT,
            signal TEXT,
            ml_prob REAL DEFAULT 0,
            factors TEXT,
            rtt_ms REAL DEFAULT 0,
            is_attack_ip INTEGER DEFAULT 0,
            failed_attempts INTEGER DEFAULT 0,
            outcome TEXT DEFAULT 'pending',
            ts TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS otps (
            sid TEXT PRIMARY KEY,
            email TEXT,
            otp_hash TEXT,
            expires REAL,
            attempts INTEGER DEFAULT 0
        );

        /* Migrate: add new columns if not present (for upgrades) */
        PRAGMA table_info(events);
    ''')
    # Safe migrations: add missing columns
    cols = [r[1] for r in db.execute('PRAGMA table_info(events)').fetchall()]
    migrations = [
        ('region',           'TEXT DEFAULT ""'),
        ('city',             'TEXT DEFAULT ""'),
        ('latitude',         'REAL DEFAULT 0'),
        ('longitude',        'REAL DEFAULT 0'),
        ('location_source',  'TEXT DEFAULT "manual"'),
        ('os',               'TEXT DEFAULT ""'),
        ('ml_prob',          'REAL DEFAULT 0'),
        ('factors',          'TEXT DEFAULT "[]"'),
        ('rtt_ms',           'REAL DEFAULT 0'),
        ('is_attack_ip',     'INTEGER DEFAULT 0'),
        ('failed_attempts',  'INTEGER DEFAULT 0'),
        ('outcome',          'TEXT DEFAULT "pending"'),
    ]
    for col, typ in migrations:
        if col not in cols:
            try:
                db.execute(f'ALTER TABLE events ADD COLUMN {col} {typ}')
            except Exception:
                pass
    db.commit()
    db.close()

def _hash(pw, salt=None):
    if not salt: salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', pw.encode(), salt.encode(), 200_000)
    return h.hex(), salt

def create_admin(username, password, display_name):
    h, s = _hash(password)
    try:
        db = conn()
        db.execute('INSERT INTO admins (username,pw_hash,salt,display_name) VALUES (?,?,?,?)',
                   (username.lower(), h, s, display_name))
        db.commit(); db.close()
        return True
    except: return False

def verify_admin(username, password):
    db = conn()
    row = db.execute('SELECT * FROM admins WHERE username=?', (username.lower(),)).fetchone()
    db.close()
    if not row: return None
    h, _ = _hash(password, row['salt'])
    if not secrets.compare_digest(h, row['pw_hash']): return None
    db = conn()
    db.execute('UPDATE admins SET last_login=? WHERE username=?', (datetime.now().isoformat(), username))
    db.commit(); db.close()
    return {'username': row['username'], 'display_name': row['display_name']}

def change_password(username, old_pw, new_pw):
    if not verify_admin(username, old_pw): return False
    h, s = _hash(new_pw)
    db = conn()
    db.execute('UPDATE admins SET pw_hash=?,salt=? WHERE username=?', (h, s, username))
    db.commit(); db.close()
    return True

def admin_exists():
    db = conn()
    n = db.execute('SELECT COUNT(*) FROM admins').fetchone()[0]
    db.close()
    return n > 0

def log(user_id, ip, country, device, browser, risk, decision, signal,
        region='', city='', lat=0.0, lon=0.0, loc_src='manual',
        os_name='', ml_prob=0.0, factors_json='[]',
        rtt_ms=0, is_attack_ip=0, failed_attempts=0, outcome='pending'):
    import json as _json
    try:
        db = conn()
        db.execute(
            '''INSERT INTO events
               (user_id,masked_ip,country,region,city,latitude,longitude,location_source,
                device,browser,os,risk,decision,signal,ml_prob,factors,
                rtt_ms,is_attack_ip,failed_attempts,outcome)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
            (str(user_id)[:40], ip, country, region, city,
             float(lat), float(lon), loc_src,
             device, browser, os_name,
             risk, decision, signal,
             float(ml_prob), factors_json,
             float(rtt_ms), int(is_attack_ip), int(failed_attempts), outcome)
        )
        db.commit(); db.close()
    except Exception as e:
        print(f'DB log error: {e}')

def update_outcome(event_id, outcome):
    """Update outcome of an event (e.g., after OTP verified or block confirmed)"""
    try:
        db = conn()
        db.execute('UPDATE events SET outcome=? WHERE id=?', (outcome, event_id))
        db.commit(); db.close()
    except: pass

def get_stats():
    db = conn()
    r = lambda q: db.execute(q).fetchone()[0]
    s = {
        'total': r("SELECT COUNT(*) FROM events"),
        'block': r("SELECT COUNT(*) FROM events WHERE decision='BLOCK'"),
        'otp':   r("SELECT COUNT(*) FROM events WHERE decision='OTP'"),
        'allow': r("SELECT COUNT(*) FROM events WHERE decision='ALLOW'"),
        'avg':   round(r("SELECT COALESCE(AVG(risk),0) FROM events"), 1),
        'otp_verified': r("SELECT COUNT(*) FROM events WHERE outcome='otp_verified'"),
        'otp_failed':   r("SELECT COUNT(*) FROM events WHERE outcome='otp_failed'"),
    }
    db.close()
    return s

def get_events(n=100):
    """Get latest n events (full history)"""
    db = conn()
    rows = db.execute(
        'SELECT * FROM events ORDER BY ts DESC LIMIT ?', (n,)
    ).fetchall()
    db.close()
    return [dict(r) for r in rows]

def get_all_events():
    """Get ALL events for full history tab"""
    db = conn()
    rows = db.execute('SELECT * FROM events ORDER BY ts DESC').fetchall()
    db.close()
    return [dict(r) for r in rows]

def get_analysis():
    """Return aggregated analysis data for conclusion tab"""
    db = conn()
    total = db.execute('SELECT COUNT(*) FROM events').fetchone()[0]
    if total == 0:
        db.close()
        return {}

    allow = db.execute("SELECT COUNT(*) FROM events WHERE decision='ALLOW'").fetchone()[0]
    otp   = db.execute("SELECT COUNT(*) FROM events WHERE decision='OTP'").fetchone()[0]
    block = db.execute("SELECT COUNT(*) FROM events WHERE decision='BLOCK'").fetchone()[0]
    otp_ok= db.execute("SELECT COUNT(*) FROM events WHERE outcome='otp_verified'").fetchone()[0]

    top_countries = db.execute(
        "SELECT country, COUNT(*) as c FROM events GROUP BY country ORDER BY c DESC LIMIT 10"
    ).fetchall()

    risk_dist = {
        'low':    db.execute("SELECT COUNT(*) FROM events WHERE risk < 35").fetchone()[0],
        'medium': db.execute("SELECT COUNT(*) FROM events WHERE risk >= 35 AND risk < 70").fetchone()[0],
        'high':   db.execute("SELECT COUNT(*) FROM events WHERE risk >= 70").fetchone()[0],
    }

    top_signals = db.execute(
        "SELECT signal, COUNT(*) as c FROM events WHERE signal IS NOT NULL AND signal != '' "
        "GROUP BY signal ORDER BY c DESC LIMIT 8"
    ).fetchall()

    hourly = db.execute(
        "SELECT CAST(strftime('%H', ts) AS INTEGER) as hr, COUNT(*) as c "
        "FROM events GROUP BY hr ORDER BY hr"
    ).fetchall()

    avg_risk = db.execute("SELECT COALESCE(AVG(risk),0) FROM events").fetchone()[0]
    peak_hour = db.execute(
        "SELECT CAST(strftime('%H', ts) AS INTEGER) as hr, COUNT(*) as c "
        "FROM events WHERE decision='BLOCK' GROUP BY hr ORDER BY c DESC LIMIT 1"
    ).fetchone()

    db.close()
    return {
        'total': total, 'allow': allow, 'otp': otp, 'block': block,
        'otp_verified': otp_ok,
        'allow_pct': round(allow/total*100, 1),
        'otp_pct':   round(otp/total*100, 1),
        'block_pct': round(block/total*100, 1),
        'avg_risk':  round(avg_risk, 1),
        'risk_dist': risk_dist,
        'top_countries': [{'country': r[0], 'count': r[1]} for r in top_countries],
        'top_signals':   [{'signal': r[0], 'count': r[1]} for r in top_signals],
        'hourly': [{'hour': r[0], 'count': r[1]} for r in hourly],
        'peak_block_hour': peak_hour[0] if peak_hour else None,
    }

def store_otp(sid, email, otp_hash, expires):
    db = conn()
    db.execute('INSERT OR REPLACE INTO otps VALUES (?,?,?,?,0)', (sid, email, otp_hash, expires))
    db.commit(); db.close()

def get_otp(sid):
    db = conn()
    r = db.execute('SELECT * FROM otps WHERE sid=?', (sid,)).fetchone()
    db.close()
    return dict(r) if r else None

def bump_otp(sid):
    db = conn()
    db.execute('UPDATE otps SET attempts=attempts+1 WHERE sid=?', (sid,))
    db.commit(); db.close()

def del_otp(sid):
    db = conn()
    db.execute('DELETE FROM otps WHERE sid=?', (sid,))
    db.commit(); db.close()
