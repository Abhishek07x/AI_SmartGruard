"""
SmartGuard — Secure Flask API (Enhanced v4.0)
✅ Real-time location via browser GPS + IP geolocation
✅ Full login history (all events stored with location)
✅ Analysis/conclusion endpoint
✅ OTP outcome tracking
✅ Enhanced event logging
"""
import os, sys, json, hashlib, uuid, time, secrets, pickle
from pathlib import Path
from datetime import datetime
from functools import wraps

from flask import Flask, request, jsonify, g
from flask_cors import CORS
import pandas as pd
import hmac as _hmac, base64
from dotenv import load_dotenv

BASE = Path(__file__).parent.parent
load_dotenv(BASE / '.env')
sys.path.insert(0, str(Path(__file__).parent))

import db as DB
from mailer import gen_otp, hash_otp, verify as verify_otp, send as send_otp

app = Flask(__name__)
CORS(app, supports_credentials=True)

# Config — ALL from .env
JWT_SECRET   = os.getenv('JWT_SECRET', secrets.token_hex(32))
JWT_EXPIRY   = 8 * 3600
OTP_EXPIRY   = 300
OTP_ATTEMPTS = 3

# Load ML model
MDIR = BASE / 'models'
try:
    model      = pickle.load(open(MDIR/'model.pkl','rb'))
    le_country = pickle.load(open(MDIR/'le_country.pkl','rb'))
    le_device  = pickle.load(open(MDIR/'le_device.pkl','rb'))
    le_browser = pickle.load(open(MDIR/'le_browser.pkl','rb'))
    le_os      = pickle.load(open(MDIR/'le_os.pkl','rb'))
    schema     = json.load(open(MDIR/'schema.json'))
    importances= json.load(open(MDIR/'importances.json'))
    FEATURES   = schema['features']
    KNOWN_C    = schema['known_countries']
    KNOWN_D    = schema['known_devices']
    KNOWN_B    = schema['known_browsers']
    KNOWN_O    = schema['known_os']
    print(f"✅ ML Model loaded (AUC={schema['auc_roc']}, trained={schema['trained_on']:,} events)")
except Exception as e:
    model = None; FEATURES = []; schema = {}; importances = {}
    KNOWN_C = KNOWN_D = KNOWN_B = KNOWN_O = []
    print(f"⚠  ML model not found — run: python3 models/train.py")

HIGH_RISK_COUNTRIES = {
    'Russia','China','Nigeria','Iran','Belarus','North Korea',
    'Venezuela','Syria','Somalia','Libya','Afghanistan','Myanmar'
}

# Rate limiter
_rl: dict = {}
def rate_limit(n, w):
    def dec(f):
        @wraps(f)
        def wrap(*a, **kw):
            ip = request.remote_addr or 'x'
            key = f"{f.__name__}:{ip}"
            now = time.time()
            calls = [t for t in _rl.get(key,[]) if now-t < w]
            if len(calls) >= n:
                return jsonify({'error':'Too many requests','code':429}), 429
            calls.append(now); _rl[key] = calls
            return f(*a, **kw)
        return wrap
    return dec

# JWT
def b64(data): return base64.urlsafe_b64encode(data).rstrip(b'=').decode()
def make_jwt(sub, role='user'):
    h = b64(json.dumps({'alg':'HS256','typ':'JWT'}).encode())
    p = b64(json.dumps({'sub':sub,'role':role,'iat':int(time.time()),
                         'exp':int(time.time())+JWT_EXPIRY,'jti':secrets.token_hex(8)}).encode())
    s = b64(_hmac.new(JWT_SECRET.encode(), f'{h}.{p}'.encode(), 'sha256').digest())
    return f'{h}.{p}.{s}'

def verify_jwt(token):
    try:
        h, p, s = token.split('.')
        ok = b64(_hmac.new(JWT_SECRET.encode(), f'{h}.{p}'.encode(), 'sha256').digest())
        if not secrets.compare_digest(s, ok): return None
        data = json.loads(base64.urlsafe_b64decode(p + '=='*3))
        return data if data.get('exp',0) > time.time() else None
    except: return None

def admin_only(f):
    @wraps(f)
    def wrap(*a, **kw):
        t = request.headers.get('Authorization','').replace('Bearer ','')
        c = verify_jwt(t)
        if not c or c.get('role') != 'admin':
            return jsonify({'error':'Admin access required'}), 401
        g.username = c['sub']
        return f(*a, **kw)
    return wrap

# Privacy
_SALT = 'SmartGuard_GDPR_2024'
def mask_ip(ip):
    p = str(ip or '').split('.')
    return f"{p[0]}.{p[1]}.xxx.xxx" if len(p)==4 else 'x.x.xxx.xxx'
def anon(uid):
    ns = uuid.UUID('ab12cd34-ef56-7890-ab12-cd34ef567890')
    return str(uuid.uuid5(ns, f"{_SALT}_{uid}"))
def enc(le, val, known):
    try: return int(le.transform([val])[0]) if val in known else len(known)
    except: return len(known)

# Event cache
_cache: list = []
def cache(ev):
    _cache.append(ev)
    if len(_cache) > 500: _cache.pop(0)

# ── IP Geolocation (free, no API key) ─────────────────────────────────────────
def geolocate_ip(ip):
    """Get location from IP using ip-api.com (free, no key needed)"""
    try:
        import urllib.request
        # Skip private IPs
        if not ip or ip.startswith(('127.','10.','192.168.','172.','::1','localhost')):
            return None
        url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,lat,lon,isp,org,query"
        req = urllib.request.Request(url, headers={'User-Agent': 'SmartGuard/4.0'})
        with urllib.request.urlopen(req, timeout=3) as r:
            data = json.loads(r.read().decode())
            if data.get('status') == 'success':
                return {
                    'country':  data.get('country', ''),
                    'region':   data.get('regionName', ''),
                    'city':     data.get('city', ''),
                    'lat':      float(data.get('lat', 0)),
                    'lon':      float(data.get('lon', 0)),
                    'isp':      data.get('isp', ''),
                    'source':   'ip_geo'
                }
    except Exception as e:
        print(f"IP geo error: {e}")
    return None

# Risk engine
def evaluate(payload):
    country  = payload.get('country','United States')
    prev_c   = payload.get('prev_country', country)
    device   = payload.get('device','Desktop')
    browser  = payload.get('browser','Chrome')
    os_name  = payload.get('os','Windows 10')
    rtt      = float(payload.get('rtt_ms', 200))
    is_atk   = int(payload.get('is_attack_ip', 0))
    failed   = int(payload.get('failed_attempts', 0))
    typing   = float(payload.get('typing_kps', 1.2))
    prev_mins= float(payload.get('prev_login_mins', 120))
    now      = datetime.now()

    # ML prediction
    ml_prob = 0.05
    if model and FEATURES:
        row = {'ce': enc(le_country, country, KNOWN_C),
               'de': enc(le_device,  device,  KNOWN_D),
               'be': enc(le_browser, browser, KNOWN_B),
               'oe': enc(le_os,      os_name, KNOWN_O),
               'rtt_ms': rtt, 'is_attack_ip': is_atk,
               'hour_of_day': now.hour}
        X = pd.DataFrame([{f: row.get(f,0) for f in FEATURES}])
        ml_prob = float(model.predict_proba(X)[0][1])

    # Risk score
    risk = int(ml_prob * 100)
    dist = 0 if country == prev_c else 5000
    speed = dist / max(prev_mins/60, 0.1)
    imp   = speed > 800

    if is_atk:                     risk = min(risk+30, 100)
    if imp:                        risk = min(risk+25, 100)
    if country in HIGH_RISK_COUNTRIES: risk = min(risk+20, 100)
    if failed > 3:                 risk = min(risk+15, 100)
    if typing > 4.0:               risk = min(risk+12, 100)
    if rtt > 8000:                 risk = min(risk+10, 100)
    if now.hour < 5:               risk = min(risk+8,  100)
    risk = max(0, min(risk, 100))

    if risk >= 70:   decision = 'BLOCK'
    elif risk >= 35: decision = 'OTP'
    else:            decision = 'ALLOW'

    # Factors
    factors = []
    if is_atk:   factors.append({'s':'Known Attack IP',       'sev':'critical','d':'IP flagged in threat database'})
    if imp:      factors.append({'s':'Impossible Travel',      'sev':'critical','d':f'{speed:.0f} km/h: {prev_c}→{country}'})
    if country in HIGH_RISK_COUNTRIES:
                 factors.append({'s':'High-Risk Country',      'sev':'high',   'd':f'Login from {country}'})
    if failed>3: factors.append({'s':'Multiple Failed Logins', 'sev':'high',   'd':f'{failed} failed attempts'})
    if typing>4: factors.append({'s':'Bot-like Typing Speed',  'sev':'medium', 'd':f'{typing} kps'})
    if rtt>8000: factors.append({'s':'High Network RTT',       'sev':'medium', 'd':f'{rtt:.0f}ms'})
    if now.hour<5:factors.append({'s':'Off-hours Access',      'sev':'low',    'd':f'{now.hour:02d}:00'})
    if ml_prob>.5:factors.append({'s':'ML Anomaly (Kaggle RBA)','sev':'high',  'd':f'{ml_prob*100:.0f}% attack probability'})
    if not factors: factors.append({'s':'Normal Behaviour',    'sev':'safe',   'd':'All signals within expected range'})

    col = {'ALLOW':'#22c55e','OTP':'#f59e0b','BLOCK':'#ef4444'}[decision]
    lbl = {'ALLOW':'✅ Allow Access','OTP':'🔐 Require OTP','BLOCK':'🚫 Block & Alert'}[decision]
    return {'risk': risk, 'decision': decision, 'label': lbl, 'color': col,
            'ml_prob': round(ml_prob,4), 'factors': factors, 'os': os_name,
            'rtt_ms': rtt, 'is_attack_ip': is_atk, 'failed_attempts': failed}

# ══ ROUTES ═══════════════════════════════════════════════════════════════════

@app.route('/api/health')
def health():
    return jsonify({'status':'ok','model':'Kaggle RBA GradientBoosting',
                    'auc': schema.get('auc_roc','N/A'), 'events': len(_cache)})

# ── Location endpoint (IP geolocation) ────────────────────────────────────────
@app.route('/api/location', methods=['GET', 'POST'])
def get_location():
    """Get location from server-side IP geolocation"""
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr or '')
    # Take first IP if multiple (proxy chain)
    if ',' in client_ip:
        client_ip = client_ip.split(',')[0].strip()

    geo = geolocate_ip(client_ip)
    if geo:
        return jsonify({
            'ok': True,
            'country': geo['country'],
            'region':  geo['region'],
            'city':    geo['city'],
            'lat':     geo['lat'],
            'lon':     geo['lon'],
            'isp':     geo['isp'],
            'source':  'ip_geolocation',
            'masked_ip': mask_ip(client_ip)
        })
    # Fallback for localhost / private IPs
    return jsonify({
        'ok': False,
        'country': 'Unknown',
        'region': '', 'city': '', 'lat': 0, 'lon': 0,
        'source': 'unavailable',
        'masked_ip': mask_ip(client_ip),
        'note': 'Local/private IP — use manual selection'
    })

# ── Admin auth ────────────────────────────────────────────────────────────────
@app.route('/api/auth/login', methods=['POST'])
@rate_limit(10, 60)
def admin_login():
    d = request.get_json(force=True) or {}
    u, p = d.get('username','').lower(), d.get('password','')
    if not u or not p: return jsonify({'ok':False,'error':'Required fields missing'}), 400
    admin = DB.verify_admin(u, p)
    if not admin:
        time.sleep(0.5)
        return jsonify({'ok':False,'error':'Invalid credentials'}), 401
    return jsonify({'ok':True,'token':make_jwt(u,'admin'),
                    'username':u,'display_name':admin['display_name'],'expires':JWT_EXPIRY})

@app.route('/api/auth/verify')
def auth_verify():
    t = request.headers.get('Authorization','').replace('Bearer ','')
    c = verify_jwt(t)
    if c: return jsonify({'valid':True,'username':c['sub'],'role':c.get('role')})
    return jsonify({'valid':False}), 401

@app.route('/api/auth/logout', methods=['POST'])
@admin_only
def logout():
    return jsonify({'ok':True})

# ── User login flow ───────────────────────────────────────────────────────────
@app.route('/api/user/check', methods=['POST'])
@rate_limit(30, 60)
def user_check():
    d = request.get_json(force=True) or {}
    email = d.get('email','').strip().lower()
    if not email: return jsonify({'error':'Email required'}), 400

    result = evaluate({
        'country'        : d.get('country','United States'),
        'prev_country'   : d.get('prev_country', d.get('country','United States')),
        'device'         : d.get('device','Desktop'),
        'browser'        : d.get('browser','Chrome'),
        'os'             : d.get('os','Windows 10'),
        'rtt_ms'         : d.get('rtt_ms',200),
        'is_attack_ip'   : d.get('is_attack_ip',0),
        'failed_attempts': d.get('failed_attempts',0),
        'typing_kps'     : d.get('typing_kps',1.2),
        'prev_login_mins': d.get('prev_login_mins',120),
    })

    uid     = anon(email)
    mip     = mask_ip(request.remote_addr)
    top     = result['factors'][0]['s'] if result['factors'] else 'N/A'
    country = d.get('country','United States')

    # Enhanced logging with location
    factors_json = json.dumps(result['factors'])
    outcome = 'allowed' if result['decision']=='ALLOW' else ('blocked' if result['decision']=='BLOCK' else 'otp_pending')

    DB.log(uid, mip, country, d.get('device','Desktop'), d.get('browser','Chrome'),
           result['risk'], result['decision'], top,
           region  = d.get('region',''),
           city    = d.get('city',''),
           lat     = d.get('lat', 0),
           lon     = d.get('lon', 0),
           loc_src = d.get('location_source','manual'),
           os_name = d.get('os',''),
           ml_prob = result['ml_prob'],
           factors_json = factors_json,
           rtt_ms  = d.get('rtt_ms',0),
           is_attack_ip = d.get('is_attack_ip',0),
           failed_attempts = d.get('failed_attempts',0),
           outcome = outcome)

    ev = {'user_id':uid,'masked_ip':mip,'country':country,'device':d.get('device','Desktop'),
          'browser':d.get('browser','Chrome'),'os':d.get('os',''),
          'risk_score':result['risk'],'decision':result['decision'],
          'label':result['label'],'color':result['color'],
          'factors':result['factors'],'timestamp':datetime.now().isoformat(),
          'city': d.get('city',''), 'region': d.get('region',''),
          'lat': d.get('lat',0), 'lon': d.get('lon',0)}
    cache(ev)

    resp = {'decision':result['decision'],'label':result['label'],'risk':result['risk'],
            'color':result['color'],'ml_prob':result['ml_prob'],'factors':result['factors'],
            'masked_email': email[0]+'***@'+email.split('@')[1] if '@' in email else '***',
            'masked_ip':mip,'timestamp':ev['timestamp']}

    if result['decision'] == 'ALLOW':
        resp['access_token'] = make_jwt(uid,'user')
        resp['message'] = 'Access granted'

    elif result['decision'] == 'OTP':
        otp = gen_otp()
        sid = secrets.token_urlsafe(32)
        DB.store_otp(sid, email, hash_otp(otp), time.time()+OTP_EXPIRY)

        signals = [f['s'] for f in result['factors'][:3]]
        name    = email.split('@')[0].title()
        r       = send_otp(email, name, otp, result['risk'], signals, mip, country)

        resp['session_id'] = sid
        resp['message']    = f"OTP sent to {resp['masked_email']}"
        if r.get('demo_otp'): resp['demo_otp'] = r['demo_otp']

    else:  # BLOCK
        resp['message'] = 'Access blocked — high risk signals detected'

    return jsonify(resp)

@app.route('/api/user/verify-otp', methods=['POST'])
@rate_limit(20, 60)
def user_verify_otp():
    d = request.get_json(force=True) or {}
    sid, otp = d.get('session_id',''), d.get('otp','').strip()
    if not sid or not otp: return jsonify({'ok':False,'error':'Required'}), 400

    sess = DB.get_otp(sid)
    if not sess: return jsonify({'ok':False,'error':'Session expired'}), 404
    if time.time() > sess['expires']:
        DB.del_otp(sid)
        return jsonify({'ok':False,'error':'OTP expired'}), 401
    if sess['attempts'] >= OTP_ATTEMPTS:
        DB.del_otp(sid)
        return jsonify({'ok':False,'error':'Too many attempts'}), 401

    if verify_otp(otp, sess['otp_hash']):
        DB.del_otp(sid)
        uid = anon(sess['email'])
        # Update outcome in DB
        try:
            db_conn = DB.conn()
            db_conn.execute(
                "UPDATE events SET outcome='otp_verified' WHERE user_id=? AND decision='OTP' ORDER BY ts DESC LIMIT 1",
                (uid,))
            db_conn.commit(); db_conn.close()
        except: pass
        return jsonify({'ok':True,'access_token':make_jwt(uid,'user'),'message':'OTP Verified! ✅'})

    DB.bump_otp(sid)
    left = OTP_ATTEMPTS - sess['attempts'] - 1
    # Update outcome
    try:
        uid = anon(sess['email'])
        db_conn = DB.conn()
        db_conn.execute(
            "UPDATE events SET outcome='otp_failed' WHERE user_id=? AND decision='OTP' ORDER BY ts DESC LIMIT 1",
            (uid,))
        db_conn.commit(); db_conn.close()
    except: pass
    return jsonify({'ok':False,'error':f'Wrong OTP. {max(0,left)} attempt(s) left'}), 401

@app.route('/api/user/resend-otp', methods=['POST'])
@rate_limit(5, 300)
def resend_otp():
    sid  = (request.get_json(force=True) or {}).get('session_id','')
    sess = DB.get_otp(sid)
    if not sess: return jsonify({'ok':False,'error':'Session not found'}), 404
    otp = gen_otp()
    DB.store_otp(sid, sess['email'], hash_otp(otp), time.time()+OTP_EXPIRY)
    r = send_otp(sess['email'], 'User', otp, 50, [], 'x.x.xxx.xxx', '')
    resp = {'ok':True,'message':'OTP resent'}
    if r.get('demo_otp'): resp['demo_otp'] = r['demo_otp']
    return jsonify(resp)

# ── Admin protected ───────────────────────────────────────────────────────────
@app.route('/api/admin/dashboard')
@admin_only
def dashboard():
    stats = DB.get_stats()
    evs   = list(reversed(_cache[-100:]))
    total = len(evs)
    blocks= sum(1 for e in evs if e.get('decision')=='BLOCK')
    rate  = blocks/max(total,1)
    from collections import Counter
    ctrs  = Counter(e.get('country','?') for e in evs)
    avg   = round(sum(e.get('risk_score',0) for e in evs)/max(total,1),1)
    return jsonify({**stats,'threat':'HIGH' if rate>.15 else 'MEDIUM' if rate>.05 else 'LOW',
                    'avg_risk':avg,'dataset':'Kaggle RBA Dataset',
                    'timeline':[{'t':e['timestamp'][11:16],'r':e.get('risk_score',0),
                                 'd':e.get('decision','?')} for e in list(reversed(_cache))[-30:]],
                    'recent':evs[:15],'countries':dict(ctrs.most_common(6))})

@app.route('/api/admin/history')
@admin_only
def full_history():
    """Full login history — all events from DB"""
    limit = int(request.args.get('limit', 500))
    offset = int(request.args.get('offset', 0))
    decision_filter = request.args.get('decision', '')  # ALLOW/OTP/BLOCK or ''
    try:
        db = DB.conn()
        if decision_filter:
            rows = db.execute(
                'SELECT * FROM events WHERE decision=? ORDER BY ts DESC LIMIT ? OFFSET ?',
                (decision_filter, limit, offset)
            ).fetchall()
            total = db.execute('SELECT COUNT(*) FROM events WHERE decision=?', (decision_filter,)).fetchone()[0]
        else:
            rows = db.execute('SELECT * FROM events ORDER BY ts DESC LIMIT ? OFFSET ?',
                              (limit, offset)).fetchall()
            total = db.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        db.close()
        events = []
        for r in rows:
            ev = dict(r)
            # Parse factors JSON
            try: ev['factors'] = json.loads(ev.get('factors') or '[]')
            except: ev['factors'] = []
            events.append(ev)
        return jsonify({'events': events, 'total': total, 'limit': limit, 'offset': offset})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/analysis')
@admin_only
def analysis():
    """Full analysis/conclusion data"""
    data = DB.get_analysis()
    # Add model info
    data['model_auc'] = schema.get('auc_roc', 'N/A')
    data['dataset'] = schema.get('dataset_source', 'Kaggle RBA')
    data['trained_on'] = schema.get('trained_on', 0)
    return jsonify(data)

@app.route('/api/admin/evaluate', methods=['POST'])
@admin_only
def admin_eval():
    p = request.get_json(force=True) or {}
    r = evaluate(p)
    ev = {**r,'user_id':anon(p.get('user_id','test')),'masked_ip':mask_ip(p.get('ip','0.0.0.0')),
          'timestamp':datetime.now().isoformat(),'country':p.get('country',''),'risk_score':r['risk'],
          'device':p.get('device',''),'browser':p.get('browser','')}
    cache(ev)
    DB.log(ev['user_id'],ev['masked_ip'],p.get('country',''),p.get('device',''),p.get('browser',''),
           r['risk'],r['decision'],r['factors'][0]['s'] if r['factors'] else 'N/A',
           os_name=p.get('os',''), ml_prob=r['ml_prob'], factors_json=json.dumps(r['factors']),
           rtt_ms=p.get('rtt_ms',0), is_attack_ip=p.get('is_attack_ip',0),
           failed_attempts=p.get('failed_attempts',0), outcome='eval')
    return jsonify(ev)

@app.route('/api/admin/simulate', methods=['POST'])
@admin_only
def simulate():
    import random
    n = min(int((request.get_json(force=True) or {}).get('n',25)), 100)
    countries = list(HIGH_RISK_COUNTRIES) + ['United States','Germany','India','France','Japan','Canada']
    devices   = ['Desktop','Mobile','Tablet']
    browsers  = ['Chrome','Firefox','Safari','Edge']
    os_list   = ['Windows 10','Windows 11','macOS','Android','iOS','Linux']
    results   = []
    for i in range(n):
        anom = random.random() < 0.20
        c    = random.choice(list(HIGH_RISK_COUNTRIES) if anom else countries[6:])
        p    = {'country':c,'prev_country':(random.choice(countries) if anom else c),
                'device':random.choice(devices),'browser':random.choice(browsers),
                'os':random.choice(os_list),'rtt_ms':random.randint(9000,25000) if anom else random.randint(50,600),
                'is_attack_ip':int(anom and random.random()<0.6),
                'failed_attempts':random.randint(4,10) if anom else random.randint(0,1),
                'typing_kps':round(random.uniform(4,9) if anom else random.uniform(0.5,2),2),
                'prev_login_mins':random.randint(5,30) if anom else random.randint(60,1440)}
        r = evaluate(p)
        ev = {**r,'user_id':anon(f'sim_{i}'),'masked_ip':f'103.{random.randint(1,254)}.xxx.xxx',
              'timestamp':datetime.now().isoformat(),'country':c,'risk_score':r['risk'],
              'device':p['device'],'browser':p['browser']}
        cache(ev)
        DB.log(ev['user_id'],ev['masked_ip'],c,p['device'],p['browser'],r['risk'],
               r['decision'],r['factors'][0]['s'] if r['factors'] else 'N/A',
               os_name=p['os'], ml_prob=r['ml_prob'], factors_json=json.dumps(r['factors']),
               rtt_ms=p['rtt_ms'], is_attack_ip=p['is_attack_ip'],
               failed_attempts=p['failed_attempts'], outcome='simulated')
        results.append(ev)
    return jsonify({'simulated':n,'results':results})

@app.route('/api/admin/features')
@admin_only
def features():
    return jsonify({'importances':importances,'dataset':'Kaggle RBA Dataset','auc':schema.get('auc_roc')})

@app.route('/api/admin/change-password', methods=['POST'])
@admin_only
def change_pw():
    d = request.get_json(force=True) or {}
    old, new = d.get('old',''), d.get('new','')
    if len(new) < 8: return jsonify({'ok':False,'error':'Min 8 characters'}), 400
    if DB.change_password(g.username, old, new):
        return jsonify({'ok':True,'message':'Password changed'})
    return jsonify({'ok':False,'error':'Old password incorrect'}), 401

if __name__ == '__main__':
    print('\n🛡  SmartGuard v4.0 — Starting...')
    DB.init()
    if not DB.admin_exists():
        from dotenv import load_dotenv; load_dotenv(BASE/'.env')
        key = os.getenv('ADMIN_SETUP_KEY','SmartGuard_Setup_2024')
        DB.create_admin('admin', key, 'System Admin')
        print(f'   Default admin created (password = ADMIN_SETUP_KEY from .env)')
        print(f'   ⚠  Change password after first login!')
    print(f'   ML: {"Loaded" if model else "Not found — run models/train.py"}')
    print(f'   Email: {"LIVE Gmail" if not os.getenv("SMTP_DEMO_MODE","true")=="true" else "DEMO (console OTP)"}')
    print(f'   → http://localhost:{os.getenv("PORT",5050)}/api/health\n')
    app.run(host='0.0.0.0', port=int(os.getenv('PORT',5050)), debug=False)
