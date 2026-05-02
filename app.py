import os, sqlite3, secrets, hashlib, json, datetime, pathlib, base64, io, zipfile, xml.etree.ElementTree as _ET
try:
    import bcrypt as _bcrypt
    BCRYPT_OK = True
except ImportError:
    BCRYPT_OK = False
from datetime import timedelta
from functools import wraps
from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, jsonify, g, send_from_directory, make_response)
from werkzeug.utils import secure_filename
import requests as _req

# Optional deps — degrade gracefully if not installed yet
WEASYPRINT_OK = False  # Disabled — not compatible with Railway environment

try:
    import stripe as _stripe
    STRIPE_OK = True
except Exception:
    STRIPE_OK = False

try:
    from sendgrid import SendGridAPIClient
    from sendgrid.helpers.mail import Mail
    SENDGRID_OK = True
except Exception:
    SENDGRID_OK = False

app = Flask(__name__)

# ── EcDash network client (Phase 2 + 3) ───────────────────────────────────
try:
    from ecdash_client import init_app as _ecdash_init, call_app as _call_app
    _ecdash_init(app, 'FloodClaim Pro')
except ImportError:
    _ecdash_init = None
    def _call_app(*a, **kw): return None

APP_NAME    = 'FloodClaim Pro'
APP_VERSION = '1.0'
import time as _uptime_time
_APP_START_TIME = _uptime_time.time()

def _get_secret_key():
    env_key = os.environ.get('SECRET_KEY')
    if env_key:
        return env_key
    data_dir = os.environ.get('RAILWAY_DATA_DIR') or os.environ.get('DATA_DIR') or '/data'
    key_file = os.path.join(data_dir, 'secret_key')
    try:
        os.makedirs(data_dir, exist_ok=True)
        if os.path.exists(key_file):
            with open(key_file) as f:
                key = f.read().strip()
            if key:
                return key
        import secrets as _sec
        key = _sec.token_hex(32)
        with open(key_file, 'w') as f:
            f.write(key)
        return key
    except Exception:
        import secrets as _sec
        return _sec.token_hex(32)


# ── Secret key: stable across deploys ────────────────────────────────────────
# Railway: set SECRET_KEY as an env var (one-time). Falls back to a file-based
# key so at minimum it survives restarts on the same volume.
_SECRET_KEY = os.environ.get('SECRET_KEY', '')
if not _SECRET_KEY:
    _KEY_FILE = '/data/.secret_key'
    try:
        os.makedirs('/data', exist_ok=True)
        if os.path.exists(_KEY_FILE):
            with open(_KEY_FILE) as _f:
                _SECRET_KEY = _f.read().strip()
        if not _SECRET_KEY:
            _SECRET_KEY = secrets.token_hex(32)
            with open(_KEY_FILE, 'w') as _f:
                _f.write(_SECRET_KEY)
    except Exception:
        # Last resort: derive a stable key from a fixed string + Railway service ID
        # so at least it's consistent within the same Railway service even without a volume.
        import hashlib
        _svc = os.environ.get('RAILWAY_SERVICE_ID', 'floodclaim-pro-default')
        _SECRET_KEY = hashlib.sha256(f'floodclaim-secret-{_svc}'.encode()).hexdigest()

app.secret_key = _get_secret_key()

# ── Session config ────────────────────────────────────────────────────────────
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
app.config['SESSION_COOKIE_HTTPONLY']    = True
app.config['SESSION_COOKIE_SAMESITE']   = 'Lax'
# Keep Secure=False — Railway's edge terminates TLS; the cookie travels over
# plain HTTP between the edge and the app container, so Secure would silently
# drop it. Railway enforces HTTPS at the edge already.
app.config['SESSION_COOKIE_SECURE']     = False

# ── CSRF protection ───────────────────────────────────────────────────────────────
def _get_csrf_token():
    """Generate (or retrieve) a per-session CSRF token."""
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def _validate_csrf():
    """Return True if the CSRF token in the request matches the session token."""
    token = (request.form.get('csrf_token')
             or request.headers.get('X-CSRF-Token', ''))
    return bool(token and token == session.get('csrf_token', ''))

# Expose to all Jinja2 templates as {{ csrf_token() }}
app.jinja_env.globals['csrf_token'] = _get_csrf_token

# ── Bot / scanner sink ──────────────────────────────────────────────────────
# Returns 410 Gone for paths that scanners probe but will never exist here.
_BOT_PATHS = [
    '/wp-admin/', '/wp-login.php', '/wp-cron.php', '/wp-includes/',
    '/wp-content/', '/xmlrpc.php', '/wp-admin/install.php',
    '/wp-json/', '/.env', '/.git/', '/config.php', '/setup.php',
    '/install.php', '/phpmyadmin/', '/pma/', '/admin/config.php',
    '/sitemap.xml', '/sitemap_index.xml', '/robots.txt.bak',
    '/.htaccess', '/web.config', '/backup/', '/administrator/',
    '/joomla/', '/drupal/', '/typo3/',
]

@app.before_request
def _block_bot_paths():
    path = request.path
    if any(path == p or path.startswith(p) for p in _BOT_PATHS):
        return '', 410
# ────────────────────────────────────────────────────────────────────────────


@app.before_request
def _csrf_protect():
    """Enforce CSRF on all state-changing requests."""
    if request.method in ('POST', 'PUT', 'DELETE', 'PATCH'):
        if request.path.startswith('/api/'):
            return  # API routes use token auth, skip CSRF
        if request.path.startswith('/portal/'):
            return  # Public client portal — no session/CSRF
        import re
        if re.search(r'/claims/\d+/sign$', request.path):
            return  # Public signature endpoint — no session
        if not _validate_csrf():
            from flask import abort
            abort(403)

def csrf_required(f):
    """Decorator: reject POST requests with missing/invalid CSRF token.
    Skips validation for Willie API routes (Bearer token auth).
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if request.method == 'POST' and not _validate_csrf():
            # API callers use JSON + Bearer — don't break them
            if request.is_json or request.headers.get('Authorization', ''):
                return f(*args, **kwargs)
            return jsonify({'error': 'CSRF validation failed'}), 403
        return f(*args, **kwargs)
    return decorated

DATA_DIR    = os.environ.get('RAILWAY_VOLUME_MOUNT_PATH', '/data')
DB_PATH     = os.path.join(DATA_DIR, 'floodclaim.db')
UPLOAD_DIR  = os.path.join(DATA_DIR, 'uploads')
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

ADMIN_EMAIL    = os.environ.get('ADMIN_EMAIL', 'admin@floodclaimpro.com')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'admin1234')
OPENROUTER_KEY = os.environ.get('OPENROUTER_API_KEY', '')

ALLOWED_EXT = {'png', 'jpg', 'jpeg', 'gif', 'webp'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXT

# ── DB ────────────────────────────────────────────────────────────────────────
def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db

@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db: db.close()

@app.after_request
def security_headers(response):
    response.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-XSS-Protection', '1; mode=block')
    response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    response.headers.setdefault('Permissions-Policy', 'geolocation=(), microphone=(), camera=()')
    response.headers.setdefault(
        'Content-Security-Policy',
        "default-src 'self' https: data: blob: 'unsafe-inline' 'unsafe-eval';"
    )
    return response

def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.executescript('''
        CREATE TABLE IF NOT EXISTS users (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            email       TEXT UNIQUE NOT NULL,
            name        TEXT NOT NULL DEFAULT '',
            password    TEXT NOT NULL,
            role        TEXT NOT NULL DEFAULT 'adjuster',
            created_at  TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS claims (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            claim_number    TEXT UNIQUE NOT NULL,
            adjuster_id     INTEGER REFERENCES users(id),
            client_name     TEXT NOT NULL,
            client_phone    TEXT DEFAULT '',
            client_phone_alt TEXT DEFAULT '',
            client_email    TEXT DEFAULT '',
            property_address TEXT NOT NULL,
            property_type   TEXT DEFAULT '',
            property_sqft   TEXT DEFAULT '',
            year_built      TEXT DEFAULT '',
            num_floors      TEXT DEFAULT '',
            flood_date      TEXT NOT NULL,
            flood_source    TEXT DEFAULT '',
            water_category  TEXT DEFAULT '',
            water_class     TEXT DEFAULT '',
            water_depth_in  TEXT DEFAULT '',
            date_water_removed TEXT DEFAULT '',
            inspection_date TEXT DEFAULT '',
            insurance_company TEXT DEFAULT '',
            policy_number   TEXT DEFAULT '',
            policy_type     TEXT DEFAULT '',
            coverage_building REAL DEFAULT 0,
            coverage_contents REAL DEFAULT 0,
            deductible      REAL DEFAULT 0,
            mortgage_company TEXT DEFAULT '',
            mortgage_loan_number TEXT DEFAULT '',
            cause_of_loss   TEXT DEFAULT '',
            priority        TEXT DEFAULT 'Normal',
            status          TEXT DEFAULT 'New',
            total_estimate  REAL DEFAULT 0,
            notes           TEXT DEFAULT '',
            created_at      TEXT DEFAULT CURRENT_TIMESTAMP,
            updated_at      TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS rooms (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            claim_id    INTEGER REFERENCES claims(id) ON DELETE CASCADE,
            name        TEXT NOT NULL,
            description TEXT DEFAULT '',
            subtotal    REAL DEFAULT 0,
            created_at  TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS line_items (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            room_id     INTEGER REFERENCES rooms(id) ON DELETE CASCADE,
            description TEXT NOT NULL,
            quantity    REAL DEFAULT 1,
            unit        TEXT DEFAULT 'ea',
            unit_cost   REAL DEFAULT 0,
            total       REAL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS photos (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            claim_id    INTEGER REFERENCES claims(id) ON DELETE CASCADE,
            room_id     INTEGER REFERENCES rooms(id) ON DELETE SET NULL,
            filename    TEXT NOT NULL,
            caption     TEXT DEFAULT '',
            ai_description TEXT DEFAULT '',
            created_at  TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS willie_conversations (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER REFERENCES users(id),
            title   TEXT NOT NULL DEFAULT 'New Conversation',
            created TEXT DEFAULT CURRENT_TIMESTAMP,
            updated TEXT DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS willie_messages (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            conversation_id INTEGER REFERENCES willie_conversations(id) ON DELETE CASCADE,
            role            TEXT NOT NULL,
            content         TEXT NOT NULL,
            created         TEXT DEFAULT CURRENT_TIMESTAMP
        );
    ''')
    cur = db.execute('SELECT id FROM users WHERE email=?', (ADMIN_EMAIL,))
    if not cur.fetchone():
        db.execute('INSERT INTO users (email, name, password, role) VALUES (?,?,?,?)',
                   (ADMIN_EMAIL, 'Admin', hash_pw(ADMIN_PASSWORD), 'admin'))
    db.commit()
    db.close()

def hash_pw(pw):
    """Hash password with bcrypt (12 rounds). Falls back to sha256 if bcrypt unavailable."""
    if BCRYPT_OK:
        return _bcrypt.hashpw(pw.encode(), _bcrypt.gensalt(12)).decode()
    return hashlib.sha256(pw.encode()).hexdigest()

def check_pw(pw, hashed):
    """Verify password — handles both bcrypt hashes and legacy sha256 hashes.
    On successful legacy login, transparently upgrades the stored hash to bcrypt.
    """
    if not hashed:
        return False
    # bcrypt hashes start with $2b$ or $2a$
    if BCRYPT_OK and hashed.startswith('$2'):
        try:
            return _bcrypt.checkpw(pw.encode(), hashed.encode())
        except Exception:
            return False
    # Legacy SHA-256 path
    return hashlib.sha256(pw.encode()).hexdigest() == hashed

init_db()

def migrate_claims_columns():
    new_cols = [
        ('client_phone_alt','TEXT DEFAULT ""'),
        ('property_type','TEXT DEFAULT ""'),
        ('property_sqft','TEXT DEFAULT ""'),
        ('year_built','TEXT DEFAULT ""'),
        ('num_floors','TEXT DEFAULT ""'),
        ('flood_source','TEXT DEFAULT ""'),
        ('water_category','TEXT DEFAULT ""'),
        ('water_class','TEXT DEFAULT ""'),
        ('water_depth_in','TEXT DEFAULT ""'),
        ('date_water_removed','TEXT DEFAULT ""'),
        ('inspection_date','TEXT DEFAULT ""'),
        ('policy_type','TEXT DEFAULT ""'),
        ('coverage_building','REAL DEFAULT 0'),
        ('coverage_contents','REAL DEFAULT 0'),
        ('deductible','REAL DEFAULT 0'),
        ('mortgage_company','TEXT DEFAULT ""'),
        ('mortgage_loan_number','TEXT DEFAULT ""'),
        ('cause_of_loss','TEXT DEFAULT ""'),
        ('priority','TEXT DEFAULT "Normal"'),
    ]
    try:
        db   = sqlite3.connect(DB_PATH)
        cols = [r[1] for r in db.execute('PRAGMA table_info(claims)').fetchall()]
        for col, typedef in new_cols:
            if col not in cols:
                db.execute(f'ALTER TABLE claims ADD COLUMN {col} {typedef}')
        db.commit()
        db.close()
    except Exception:
        pass

migrate_claims_columns()


def migrate_new_features():
    """Add tables/columns for new features — safe to run every boot."""
    try:
        db = sqlite3.connect(DB_PATH)
        db.executescript('''
            CREATE TABLE IF NOT EXISTS client_portal_tokens (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                claim_id   INTEGER REFERENCES claims(id) ON DELETE CASCADE,
                token      TEXT UNIQUE NOT NULL,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS signatures (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                claim_id   INTEGER REFERENCES claims(id) ON DELETE CASCADE,
                signer     TEXT NOT NULL,
                signed_at  TEXT DEFAULT CURRENT_TIMESTAMP,
                sig_data   TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS stripe_customers (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id         INTEGER UNIQUE REFERENCES users(id),
                stripe_customer TEXT,
                stripe_sub_id   TEXT,
                plan            TEXT DEFAULT 'basic',
                status          TEXT DEFAULT 'active',
                created_at      TEXT DEFAULT CURRENT_TIMESTAMP
            );
        ''')
        # Estimate jobs table — async polling so browser never times out
        db.execute('''
            CREATE TABLE IF NOT EXISTS estimate_jobs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                claim_id    INTEGER NOT NULL,
                status      TEXT DEFAULT 'pending',
                result      TEXT DEFAULT '',
                error       TEXT DEFAULT '',
                created_at  TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at  TEXT DEFAULT CURRENT_TIMESTAMP
            );
        ''')
        cols = [r[1] for r in db.execute('PRAGMA table_info(claims)').fetchall()]
        extras = [
            ('flood_zone',     'TEXT DEFAULT ""'),
            ('fema_map_number','TEXT DEFAULT ""'),
            ('lat',            'REAL DEFAULT 0'),
            ('lng',            'REAL DEFAULT 0'),
            ('maps_embed_url', 'TEXT DEFAULT ""'),
            ('client_token',   'TEXT DEFAULT ""'),
        ]
        for col, typedef in extras:
            if col not in cols:
                db.execute(f'ALTER TABLE claims ADD COLUMN {col} {typedef}')
        db.commit()
        db.close()
    except Exception as e:
        print(f'migrate_new_features error: {e}')

migrate_new_features()


def migrate_photos_columns():
    """Ensure photos table has room_id and ai_description columns (added in later versions)."""
    try:
        db   = sqlite3.connect(DB_PATH)
        cols = [r[1] for r in db.execute('PRAGMA table_info(photos)').fetchall()]
        if 'room_id' not in cols:
            db.execute('ALTER TABLE photos ADD COLUMN room_id INTEGER REFERENCES rooms(id) ON DELETE SET NULL')
        if 'ai_description' not in cols:
            db.execute('ALTER TABLE photos ADD COLUMN ai_description TEXT DEFAULT ""')
        if 'caption' not in cols:
            db.execute('ALTER TABLE photos ADD COLUMN caption TEXT DEFAULT ""')
        db.commit()
        db.close()
    except Exception as e:
        print(f'migrate_photos_columns error: {e}')

migrate_photos_columns()


def migrate_new_features_v2():
    """Add tables for Kanban, Scheduler, Notifications, Analytics, Activity Log — safe to run every boot."""
    try:
        db = sqlite3.connect(DB_PATH)
        db.executescript('''
            CREATE TABLE IF NOT EXISTS inspection_slots (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                claim_id    INTEGER REFERENCES claims(id) ON DELETE CASCADE,
                adjuster_id INTEGER REFERENCES users(id),
                slot_date   TEXT NOT NULL,
                slot_time   TEXT NOT NULL,
                status      TEXT DEFAULT 'pending',
                notes       TEXT DEFAULT '',
                created_at  TEXT DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS notifications_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                claim_id    INTEGER REFERENCES claims(id) ON DELETE CASCADE,
                type        TEXT NOT NULL,
                recipient   TEXT NOT NULL,
                message     TEXT NOT NULL,
                sent_at     TEXT DEFAULT CURRENT_TIMESTAMP,
                status      TEXT DEFAULT 'sent'
            );
            CREATE TABLE IF NOT EXISTS activity_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                claim_id    INTEGER REFERENCES claims(id) ON DELETE CASCADE,
                actor       TEXT NOT NULL DEFAULT 'System',
                action      TEXT NOT NULL,
                created_at  TEXT DEFAULT CURRENT_TIMESTAMP
            );
        ''')
        # Add inspection_date + kanban_order columns to claims if missing
        cols = [r[1] for r in db.execute('PRAGMA table_info(claims)').fetchall()]
        extras = [
            ('kanban_order',  'INTEGER DEFAULT 0'),
            ('sched_date',    'TEXT DEFAULT ""'),
            ('sched_time',    'TEXT DEFAULT ""'),
        ]
        for col, typedef in extras:
            if col not in cols:
                db.execute(f'ALTER TABLE claims ADD COLUMN {col} {typedef}')
        db.commit()
        db.close()
    except Exception as e:
        print(f'migrate_new_features_v2 error: {e}')

migrate_new_features_v2()


# ── Integrations: FEMA, Maps, Email (helpers only — routes defined after auth) ──

def lookup_fema_flood_zone(address):
    """Look up FEMA flood zone for an address using FEMA's free API."""
    try:
        # Geocode address via Census Bureau (free, no key)
        geo_url = 'https://geocoding.geo.census.gov/geocoder/locations/onelineaddress'
        r = _req.get(geo_url, params={'address': address, 'benchmark': 'Public_AR_Current', 'format': 'json'}, timeout=8)
        matches = r.json().get('result', {}).get('addressMatches', [])
        if not matches:
            return {}
        lat = matches[0]['coordinates']['y']
        lng = matches[0]['coordinates']['x']
        # FEMA flood zone via NFHL API
        fema_url = 'https://hazards.fema.gov/gis/nfhl/rest/services/public/NFHL/MapServer/28/query'
        fr = _req.get(fema_url, params={
            'geometry': f'{lng},{lat}', 'geometryType': 'esriGeometryPoint',
            'inSR': '4326', 'spatialRel': 'esriSpatialRelIntersects',
            'outFields': 'FLD_ZONE,DFIRM_ID', 'returnGeometry': 'false', 'f': 'json'
        }, timeout=8)
        features = fr.json().get('features', [])
        zone = features[0]['attributes']['FLD_ZONE'] if features else 'Unknown'
        map_num = features[0]['attributes']['DFIRM_ID'] if features else ''
        maps_url = f'https://www.google.com/maps/embed/v1/place?key=AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY&q={lat},{lng}&zoom=15'
        return {'lat': lat, 'lng': lng, 'flood_zone': zone, 'fema_map_number': map_num, 'maps_embed_url': maps_url}
    except Exception as e:
        print(f'FEMA lookup error: {e}')
        return {}


def send_email(to_email, subject, html_body):
    """Send email via SendGrid if configured, else log."""
    sg_key = get_setting('sendgrid_api_key') or os.environ.get('SENDGRID_API_KEY', '')
    from_email = get_setting('from_email') or os.environ.get('FROM_EMAIL', 'noreply@floodclaimpro.com')
    if not sg_key or not SENDGRID_OK:
        print(f'[EMAIL] To: {to_email} | Subject: {subject} | (SendGrid not configured)')
        return False
    try:
        msg = Mail(from_email=from_email, to_emails=to_email, subject=subject, html_content=html_body)
        SendGridAPIClient(sg_key).send(msg)
        return True
    except Exception as e:
        print(f'SendGrid error: {e}')
        return False


def notify_client_status_change(claim, new_status):
    """Email client when claim status changes."""
    if not claim['client_email']:
        return
    subject = f'FloodClaim Pro — Your Claim {claim["claim_number"]} Update'
    html = f'''<div style="font-family:sans-serif;max-width:600px;margin:0 auto">
        <h2 style="color:#0a1628">FloodClaim Pro Update</h2>
        <p>Hello {claim["client_name"]},</p>
        <p>Your flood damage claim <strong>{claim["claim_number"]}</strong> has been updated.</p>
        <p style="background:#f0fdf4;padding:12px;border-radius:8px;border-left:4px solid #10b981">
            <strong>New Status: {new_status}</strong></p>
        <p>If you have questions, please contact your adjuster directly.</p>
        <hr style="margin:24px 0;border:none;border-top:1px solid #e2e8f0">
        <p style="font-size:12px;color:#94a3b8">FloodClaim Pro · Professional Flood Damage Assessment</p>
    </div>'''
    send_email(claim['client_email'], subject, html)

# ── Auth ──────────────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
            flash('Your session expired — please log in again.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('role') != 'admin':
            flash('Admin access required.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated

# ── Helpers ───────────────────────────────────────────────────────────────────
def gen_claim_number():
    prefix = datetime.datetime.now().strftime('%Y%m')
    suffix = secrets.token_hex(3).upper()
    return f'FC-{prefix}-{suffix}'

def recalc_claim(claim_id):
    db = get_db()
    rooms = db.execute('SELECT id FROM rooms WHERE claim_id=?', (claim_id,)).fetchall()
    total = 0
    for room in rooms:
        rt = db.execute('SELECT COALESCE(SUM(total),0) as s FROM line_items WHERE room_id=?',
                        (room['id'],)).fetchone()['s']
        db.execute('UPDATE rooms SET subtotal=? WHERE id=?', (rt, room['id']))
        total += rt
    db.execute('UPDATE claims SET total_estimate=?, updated_at=CURRENT_TIMESTAMP WHERE id=?',
               (total, claim_id))
    db.commit()

def get_setting(key, default=''):
    try:
        db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        row = db.execute('SELECT value FROM settings WHERE key=?', (key,)).fetchone()
        db.close()
        return row['value'] if row else default
    except Exception:
        return default

app.jinja_env.globals['get_setting'] = get_setting

def set_setting(key, value):
    db = sqlite3.connect(DB_PATH)
    db.execute(
        'INSERT INTO settings (key, value) VALUES (?,?) '
        'ON CONFLICT(key) DO UPDATE SET value=excluded.value',
        (key, value))
    db.commit()
    db.close()

# ── Aquila API token ─────────────────────────────────────────────────────────────────
def get_willie_token():
    """Get or auto-generate the Aquila API token."""
    token = get_setting('willie_api_token')
    if not token:
        token = secrets.token_urlsafe(32)
        set_setting('willie_api_token', token)
    return token

def willie_auth():
    """Verify Willie API token from Authorization header."""
    auth  = request.headers.get('Authorization', '')
    token = auth.replace('Bearer ', '').strip() if auth.startswith('Bearer ') else ''
    return bool(token and token == get_setting('willie_api_token'))


# ── AI Adjuster Estimate — Async job system ────────────────────────────────────
import threading

def _run_estimate_job(job_id, claim_id, claim, rooms, photo_analyses, photo_section,
                      room_section, model, key):
    """Background thread: runs the AI call and writes result to estimate_jobs table."""
    import sqlite3 as _sq3
    db = _sq3.connect(DB_PATH)
    db.row_factory = _sq3.Row
    try:
        PRICING_KB = _build_pricing_kb()
        prompt = _build_estimate_prompt(claim, room_section, photo_section, PRICING_KB)
        estimate = call_openrouter([{'role': 'user', 'content': prompt}], model, key, max_tokens=4000)
        db.execute(
            'UPDATE estimate_jobs SET status=?, result=?, updated_at=CURRENT_TIMESTAMP WHERE id=?',
            ('done', estimate, job_id))
        db.commit()
    except Exception as e:
        db.execute(
            'UPDATE estimate_jobs SET status=?, error=?, updated_at=CURRENT_TIMESTAMP WHERE id=?',
            ('error', str(e), job_id))
        db.commit()
    finally:
        db.close()


def _build_pricing_kb():
    return """
=== 2026 FLOOD RESTORATION PRICING REFERENCE (USE THESE RATES) ===

NATIONAL AVERAGES (2026 — Palm Build, NuBilt, Angi, Xactimate):
- Average claim payout: $10,234–$11,605
- Full restoration (mitigation + rebuild): $5,000–$16,000
- Mitigation: $3.00–$7.50/sf | Full rebuild: $20.00–$37.00/sf
- Myrtle Beach / SC rate: $14–$16/sf cleanup, $20–$30/sf rebuild
- 1 inch floodwater → ~$25,000 damage (FEMA/NFIP)

WATER CATEGORIES (IICRC):
- Cat 1 (clean): $3.50/sf | Cat 2 (gray): $5.25/sf | Cat 3 (black/flood): $7.50/sf+
- Flood water from outside = ALWAYS Cat 3

MITIGATION (Xactimate 2024–2026):
- Emergency call: $271–$407 EA | Extraction: $0.75–$1.50/sf
- Air mover/24h: $38–$55 EA (1 per 50–100sf) | Dehumidifier/24h: $83–$110 EA
- Antimicrobial: $0.35–$0.75/sf | Moisture mapping: $250 flat
- Content pack-out: $77/hr | Debris/dumpster: $350–$600 EA

TEAR-OUT:
- Drywall Cat3: $1.79/sf | Insulation: $0.91/sf | Baseboard: $0.66/lf
- LVP/vinyl: $1.25–$2.00/sf | Hardwood: $5.82/sf | Tile+mortar: $3.50–$5.00/sf
- Subfloor: $2.00–$3.50/sf

RECONSTRUCTION:
- Drywall 1/2" hung/taped/floated: $3.99–$5.50/sf | Insulation R-19: $1.40–$2.00/sf
- Paint 2 coats: $1.50–$2.50/sf | Baseboard R&R: $5.51/lf
- LVP installed: $4.00–$8.00/sf ($5.50 mid) | Carpet+pad: $3.50–$6.50/sf
- Hardwood: $8.00–$14.00/sf | Tile: $7.00–$12.00/sf | Subfloor: $4.50–$6.00/sf

MOLD: $1,200–$3,800 flat (small) or $15–$30/sf | Encapsulation: $1.00–$2.50/sf
ELECTRICAL: Re-inspection $150–$400 | GFCI R&R $85–$150 EA
CABINETS: Base $175–$350/lf | Upper $125–$250/lf | Countertop $25–$40/lf
DOORS/WINDOWS: Interior door $401–$550 EA | Window $392–$550 EA

O&P + CONTINGENCY (always include):
- Contractor O&P: 20% of subtotal (standard insurance practice)
- Sales tax on materials: ~8% (SC rate)
- Contingency: 10% of subtotal

TYPICAL TOTALS: Single room $8k–$18k | Two rooms $15k–$30k | Full floor $25k–$60k
NFIP avg: $10,234 moderate / $66,000 severe

RULES:
1. NEVER estimate below $8,000 when photos show drywall + flooring damage
2. Floodwater from outside = Cat 3 always
3. Peeling drywall in photos = full replacement, NOT patch
4. Visible rotted/torn floor = full room replacement
5. Always include BOTH mitigation AND reconstruction phases
6. Always add O&P (20%) + contingency (10%)
7. Damage >48h old = add mold remediation line items
"""


def _build_estimate_prompt(claim, room_section, photo_section, pricing_kb):
    return f"""You are a licensed public adjuster with 20 years of flood damage experience.
Generate a complete professional insurance estimate using the 2026 pricing reference below.
USE THESE EXACT RATES. Do not guess or use outdated numbers.

{pricing_kb}

=== CLAIM ===
Claim #: {claim['claim_number']}
Client: {claim['client_name']}
Property: {claim['property_address']}
Flood Date: {claim['flood_date']}
Flood Source: {claim.get('flood_source') or 'Not specified'}
Water Category: {claim.get('water_category') or 'Not specified'}
Water Class: {claim.get('water_class') or 'Not specified'}
Water Depth: {claim.get('water_depth_in') or 'Not specified'} inches
Insurance Co: {claim.get('insurance_company') or 'Not specified'}
FEMA Zone: {claim.get('flood_zone') or 'Not determined'}

=== CURRENT ROOMS & LINE ITEMS ===
{room_section}
Current Total: ${claim['total_estimate']:.2f}

=== PHOTO ANALYSIS ===
{photo_section}

=== YOUR TASK ===
1. **PHOTO FINDINGS** — Specific damage per photo (water lines, mold, drywall, flooring, structural). Note water category/class.

2. **COMPLETE LINE-ITEM ESTIMATE** — Both mitigation AND reconstruction phases:
   | Item | Qty | Unit | Unit Cost | Total |
   Mark existing ✅, add missing ➕. Include drying equipment, antimicrobial, debris removal.

3. **ESTIMATE SUMMARY**
   - Subtotal per room
   - Contractor O&P (20%)
   - Sales tax (~8%)
   - Contingency (10%)
   - **GRAND TOTAL** (recommended claim amount)

4. **ADJUSTER NOTES** — Red flags, documentation gaps, is ${claim['total_estimate']:.2f} adequate?

Be thorough — this goes to the insurance company. Low estimates hurt the homeowner."""


@app.route('/claims/<int:claim_id>/ai-estimate', methods=['POST'])
def ai_estimate(claim_id):
    """Start AI estimate job. Returns job_id immediately; client polls /ai-estimate/<job_id>.
    Accepts session login OR Willie API token."""
    # Allow Willie token auth as fallback for cross-origin requests
    if not session.get('user_id'):
        if not willie_auth():
            return jsonify({'ok': False, 'error': 'Session expired — please refresh the page and log in again.'}), 401
    db = get_db()
    claim = db.execute('SELECT * FROM claims WHERE id=?', (claim_id,)).fetchone()
    if not claim:
        return jsonify({'ok': False, 'error': 'Claim not found'}), 404
    claim = dict(claim)  # convert sqlite3.Row → dict so .get() works

    key   = get_setting('openrouter_api_key') or OPENROUTER_KEY
    model = get_setting('ai_model') or 'openai/gpt-4o-mini'
    if not key:
        return jsonify({'ok': False, 'error': 'OpenRouter API key not configured. Go to Settings and add your key.'}), 400

    # Rooms + line items
    rooms = db.execute('SELECT * FROM rooms WHERE claim_id=? ORDER BY id', (claim_id,)).fetchall()
    room_section = ''
    for r in rooms:
        items = db.execute('SELECT * FROM line_items WHERE room_id=? ORDER BY id', (r['id'],)).fetchall()
        item_list = '; '.join([f"{i['description']} x{i['quantity']} {i['unit']} @${i['unit_cost']:.2f}" for i in items]) or 'No items'
        room_section += f"  {r['name']}: {item_list}\n"
    if not room_section:
        room_section = '  No rooms documented yet.\n'

    # Analyze photos (use cached AI descriptions or run fresh)
    photos = [dict(p) for p in db.execute('SELECT * FROM photos WHERE claim_id=? ORDER BY id', (claim_id,)).fetchall()]
    photo_analyses = []
    for photo in photos[:8]:
        photo_path = os.path.join(UPLOAD_DIR, photo['filename'])
        desc = photo.get('ai_description', '') or ''
        # Clear cached error strings so they get retried
        if desc.startswith('AI analysis failed') or desc.startswith('Error'):
            desc = ''
            db.execute('UPDATE photos SET ai_description=NULL WHERE id=?', (photo['id'],))
            db.commit()
        if not desc and os.path.exists(photo_path):
            desc = ai_describe_photo(photo_path)
            if desc:
                db.execute('UPDATE photos SET ai_description=? WHERE id=?', (desc, photo['id']))
                db.commit()
        if desc:
            label = photo.get('caption') or photo['filename']
            photo_analyses.append(f"  [{label}]: {desc}")
    photo_count = len(photos)
    missing_files = sum(1 for p in photos[:8] if not os.path.exists(os.path.join(UPLOAD_DIR, p['filename'])))
    photo_section = '\n'.join(photo_analyses) if photo_analyses else '  No photos uploaded yet.'
    if missing_files > 0:
        photo_section += f'\n  Note: {missing_files} photo file(s) not found on disk.'

    PRICING_KNOWLEDGE_BASE = """
=== 2026 FLOOD RESTORATION PRICING REFERENCE (USE THESE RATES) ===

NATIONAL AVERAGES (2026 data — Palm Build, NuBilt, Angi, Xactimate):
- Average water damage claim payout: $10,234–$11,605
- Typical full restoration (mitigation + rebuild): $5,000–$16,000
- Per sq ft mitigation only: $3.00–$7.50/sf
- Per sq ft full rebuild: $20.00–$37.00/sf
- Myrtle Beach / South Carolina local rate: $14–$16/sf (cleanup), $20–$30/sf (rebuild)
- 1 inch of standing floodwater → ~$25,000 in damage to a typical home (FEMA/NFIP data)

WATER CATEGORIES (IICRC):
- Cat 1 (clean water): $3.50/sf mitigation
- Cat 2 (gray water/appliance): $5.25/sf mitigation
- Cat 3 (black water/floodwater/sewage): $7.50/sf mitigation + biohazard uplift
  → Flood water from outside IS always Cat 3

WATER CLASSES:
- Class 1 (partial room, floors only): 24–48h dry-out
- Class 2 (full room, walls <24" wicking): 48–72h dry-out
- Class 3 (ceiling/walls saturated): 72–96h dry-out
- Class 4 (specialty — brick, hardwood, concrete): 120h+ dry-out

MITIGATION LINE ITEMS (Xactimate-based 2024–2026):
- Emergency service call (business hours): $271–$407 EA
- Water extraction / pumping: $0.75–$1.50/sf
- Air mover (per 24h): $38–$55 EA (typically 1 per 50–100 sf)
- Dehumidifier 70–109 ppd (per 24h): $83–$110 EA (typically 1 per 500–1,000 sf)
- Wall cavity drying — injection type (per 24h): $141 EA
- Antimicrobial treatment: $0.35–$0.50/sf
- Moisture mapping report: $250 flat
- Containment barriers: $0.18/sf
- Content manipulation / pack-out: $77/hr
- Debris hauling (dumpster): $350–$600 EA

DEMOLITION / TEAR-OUT:
- Tear out wet drywall Cat 3 (no bagging): $1.79/sf
- Tear out wet insulation (no bagging): $0.91/sf
- Tear out baseboard: $0.66/lf
- Tear out carpet + pad: $1.05–$1.50/sy (or $0.12–$0.17/sf)
- Tear out LVP/vinyl flooring: $1.25–$2.00/sf
- Tear out non-salvageable hardwood (bagged): $5.82/sf
- Tear out ceramic tile + mortar bed: $3.50–$5.00/sf
- Tear out subfloor (OSB/plywood): $2.00–$3.50/sf

DRYWALL REPLACEMENT:
- 1/2" drywall hung, taped, floated, ready for paint: $3.99–$5.50/sf
- Drywall repair (labor only, Myrtle Beach): $40–$60/hr
- Batt insulation 6" R19: $1.40–$2.00/sf
- Seal/prime + 2 coats paint walls: $1.50–$2.50/sf
- Baseboard 4-1/4" R&R: $5.51/lf
- Seal & paint baseboard: $2.75/lf

FLOORING REPLACEMENT:
- Luxury Vinyl Plank (LVP) installed: $4.00–$8.00/sf (mid-grade $5.50)
- Carpet + pad installed: $3.50–$6.50/sf (mid-grade $4.50)
- Hardwood installed (mid-grade): $8.00–$14.00/sf
- Ceramic/porcelain tile installed: $7.00–$12.00/sf
- Subfloor OSB 3/4" R&R: $4.50–$6.00/sf

MOLD REMEDIATION:
- HEPA air scrubber (per 24h): $80–$115 EA
- Antimicrobial application: $0.35–$0.75/sf
- Mold remediation (contained area): $1,200–$3,800 total; $15–$30/sf for large areas
- Encapsulation coating: $1.00–$2.50/sf

ELECTRICAL / MECHANICAL:
- Electrical safety re-inspection after flood: $150–$400
- GFCI outlet R&R: $85–$150 EA
- Electrical outlet/switch R&R (standard): $45–$90 EA

CABINETS / KITCHEN:
- Base cabinet removal & replace (per LF): $175–$350/lf
- Upper cabinet removal & replace (per LF): $125–$250/lf
- Countertop replace (laminate): $25–$40/lf

DOORS / WINDOWS:
- Interior door unit R&R: $401–$550 EA
- Vinyl window single-hung 9–12 sf R&R: $392–$550 EA
- Door frame/jamb R&R: $254–$350 EA

CONTINGENCY & OVERHEAD:
- Standard contingency: 10–15% of subtotal
- Contractor O&P (overhead & profit): 20% on top of labor + materials (standard insurance practice)
- Sales tax on materials: ~8% (SC rate)

AVERAGE TOTAL COSTS BY CLAIM TYPE (2026 insurance data):
- Single room flood (200–400 sf): $8,000–$18,000
- Two-room flood: $15,000–$30,000
- Full first-floor flood (1,000–1,500 sf): $25,000–$60,000
- Basement flood: $10,000–$30,000
- NFIP average payout for flood claims: $66,000 (severe) / $10,234 (moderate)

KEY RULES FOR ADJUSTER ESTIMATES:
1. NEVER estimate below $8,000 for any claim showing visible drywall damage + flooring damage in 2+ photos
2. Flood water from outside = Cat 3 black water ALWAYS — this triggers biohazard protocols and higher rates
3. Any peeling paint/drywall visible in photos = walls need full replacement, not patch repair
4. Rotted/torn flooring visible = full room flooring replacement, not partial
5. Always include mitigation phase (extraction/drying) AND reconstruction phase in estimate
6. Add 10% contingency + 20% O&P to all estimates
7. If mold risk present (damage >48h old), add mold remediation line items
"""

    prompt = f"""You are a licensed public adjuster and flood damage estimator with 20 years of experience.
Analyze this flood damage claim and produce a complete, professional estimate like you would submit to an insurance company.

You have access to a current 2026 pricing reference — USE THESE EXACT RATES, do not guess or use outdated numbers:
{PRICING_KNOWLEDGE_BASE}

=== CLAIM DETAILS ===
Claim #: {claim['claim_number']}
Client: {claim['client_name']}
Property: {claim['property_address']}
Flood Date: {claim['flood_date']}
Flood Source: {claim.get('flood_source') or 'Not specified'}
Water Category: {claim.get('water_category') or 'Not specified'}
Water Class: {claim.get('water_class') or 'Not specified'}
Water Depth: {claim.get('water_depth_in') or 'Not specified'} inches
Insurance Co: {claim.get('insurance_company') or 'Not specified'}
FEMA Flood Zone: {claim.get('flood_zone') or 'Not determined'}

=== CURRENT ROOMS & LINE ITEMS ===
{room_section}
Current Documented Total: ${claim['total_estimate']:.2f}

=== PHOTO ANALYSIS ===
{photo_section}

=== YOUR TASK ===
As a professional adjuster, provide:

1. 📸 PHOTO FINDINGS
Describe specific damage visible in each photo (water lines, peeling drywall, rotted flooring, mold, structural damage, etc.). Note the water category and class implied by what you see.

2. 📊 COMPLETE LINE-ITEM ESTIMATE
Using the pricing reference above, list EVERY repair needed — both mitigation phase and reconstruction phase:
| Item | Qty | Unit | Unit Cost | Total |
Mark existing items ✅ and new recommended items ➕
Do NOT omit standard line items like drying equipment, antimicrobial treatment, debris removal.

3. 💰 ESTIMATE SUMMARY
- Subtotal per room
- Contractor O&P (20%)
- Sales tax on materials (~8%)
- 10% contingency
- GRAND TOTAL (recommended claim amount)

4. ⚠️ ADJUSTER NOTES
Documentation gaps, red flags, items insurance may dispute, additional photos needed, and whether the current estimate of ${claim['total_estimate']:.2f} is adequate.

Be thorough — this goes directly to the insurance company. Low estimates hurt the homeowner."""

    # Launch background thread — returns job_id immediately so browser never times out
    cur = db.execute(
        'INSERT INTO estimate_jobs (claim_id, status) VALUES (?, ?)', (claim_id, 'pending'))
    db.commit()
    job_id = cur.lastrowid
    t = threading.Thread(
        target=_run_estimate_job,
        args=(job_id, claim_id, claim, rooms, photo_analyses, photo_section,
              room_section, model, key),
        daemon=True)
    t.start()
    return jsonify({'ok': True, 'job_id': job_id, 'status': 'pending',
                    'poll_url': f'/claims/{claim_id}/ai-estimate/{job_id}'})


@app.route('/claims/<int:claim_id>/ai-estimate/<int:job_id>', methods=['GET'])
def ai_estimate_poll(claim_id, job_id):
    if not session.get('user_id'):
        if not willie_auth():
            return jsonify({'ok': False, 'error': 'unauthorized'}), 401
    db = get_db()
    job = db.execute('SELECT * FROM estimate_jobs WHERE id=? AND claim_id=?',
                     (job_id, claim_id)).fetchone()
    if not job:
        return jsonify({'ok': False, 'error': 'Job not found'}), 404
    job = dict(job)
    if job['status'] == 'done':
        claim = dict(db.execute('SELECT * FROM claims WHERE id=?', (claim_id,)).fetchone())
        return jsonify({
            'ok': True, 'status': 'done',
            'estimate': job['result'],
            'claim_number': claim['claim_number'],
            'client': claim['client_name'],
            'current_total': float(claim['total_estimate']),
        })
    if job['status'] == 'error':
        return jsonify({'ok': False, 'status': 'error',
                        'error': job['error'] or 'AI estimate failed'})
    return jsonify({'ok': True, 'status': 'pending'})


@app.route('/claims/<int:claim_id>/update-estimate', methods=['POST'])
def update_claim_estimate(claim_id):
    """Update total_estimate from AI adjuster result. Accepts session or Willie token."""
    if not session.get('user_id') and not willie_auth():
        return jsonify({'ok': False, 'error': 'unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    total = data.get('total_estimate')
    if total is None:
        return jsonify({'ok': False, 'error': 'total_estimate required'}), 400
    try:
        total = float(total)
    except (ValueError, TypeError):
        return jsonify({'ok': False, 'error': 'Invalid total'}), 400
    db = get_db()
    db.execute('UPDATE claims SET total_estimate=?, updated_at=CURRENT_TIMESTAMP WHERE id=?', (total, claim_id))
    db.commit()
    return jsonify({'ok': True, 'total_estimate': total})


# ── PDF Export ────────────────────────────────────────────────────────────────
@app.route('/claims/<int:claim_id>/report/pdf')
@login_required
def report_pdf(claim_id):
    db = get_db()
    claim = db.execute('''SELECT c.*, u.name as adjuster_name, u.email as adjuster_email
        FROM claims c LEFT JOIN users u ON c.adjuster_id=u.id WHERE c.id=?''', (claim_id,)).fetchone()
    if not claim:
        flash('Claim not found.', 'error')
        return redirect(url_for('dashboard'))
    rooms = db.execute('SELECT * FROM rooms WHERE claim_id=? ORDER BY id', (claim_id,)).fetchall()
    room_data = []
    for room in rooms:
        items  = db.execute('SELECT * FROM line_items WHERE room_id=? ORDER BY id', (room['id'],)).fetchall()
        photos = db.execute('SELECT * FROM photos WHERE room_id=? ORDER BY id', (room['id'],)).fetchall()
        room_data.append({'room': room, 'line_items': items, 'room_photos': photos})
    unassigned_photos = db.execute('SELECT * FROM photos WHERE claim_id=? AND room_id IS NULL', (claim_id,)).fetchall()
    recalc_claim(claim_id)
    claim = db.execute('''SELECT c.*, u.name as adjuster_name, u.email as adjuster_email
        FROM claims c LEFT JOIN users u ON c.adjuster_id=u.id WHERE c.id=?''', (claim_id,)).fetchone()
    signature = db.execute(
        'SELECT * FROM signatures WHERE claim_id=? ORDER BY id DESC LIMIT 1',
        (claim_id,)).fetchone()
    return render_template('report.html', claim=claim, room_data=room_data,
                           unassigned_photos=unassigned_photos, pdf_mode=True, auto_print=True,
                           signature=signature,
                           generated=datetime.datetime.now().strftime('%B %d, %Y %I:%M %p'))


# ── Xactimate ESX Export ──────────────────────────────────────────────────────
@app.route('/claims/<int:claim_id>/export/xactimate')
@login_required
def export_xactimate(claim_id):
    db = get_db()
    claim = db.execute('SELECT * FROM claims WHERE id=?', (claim_id,)).fetchone()
    if not claim:
        flash('Claim not found.', 'error')
        return redirect(url_for('dashboard'))
    rooms = db.execute('SELECT * FROM rooms WHERE claim_id=? ORDER BY id', (claim_id,)).fetchall()
    now = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<XactimateEstimate version="1.0">',
        '  <ClaimInfo>',
        f'    <ClaimNumber>{claim["claim_number"]}</ClaimNumber>',
        f'    <InsuredName>{claim["client_name"]}</InsuredName>',
        f'    <LossAddress>{claim["property_address"]}</LossAddress>',
        f'    <DateOfLoss>{claim["flood_date"]}</DateOfLoss>',
        f'    <InsuranceCompany>{claim["insurance_company"]}</InsuranceCompany>',
        f'    <PolicyNumber>{claim["policy_number"]}</PolicyNumber>',
        f'    <FloodZone>{claim["flood_zone"]}</FloodZone>',
        f'    <TotalEstimate>{claim["total_estimate"]:.2f}</TotalEstimate>',
        f'    <ExportDate>{now}</ExportDate>',
        '  </ClaimInfo>',
        '  <Rooms>',
    ]
    for room in rooms:
        items = db.execute('SELECT * FROM line_items WHERE room_id=? ORDER BY id', (room['id'],)).fetchall()
        lines += ['    <Room>', f'      <Name>{room["name"]}</Name>',
                  f'      <Subtotal>{room["subtotal"]:.2f}</Subtotal>', '      <LineItems>']
        for item in items:
            lines += ['        <LineItem>',
                      f'          <Description>{item["description"]}</Description>',
                      f'          <Quantity>{item["quantity"]}</Quantity>',
                      f'          <Unit>{item["unit"]}</Unit>',
                      f'          <UnitCost>{item["unit_cost"]:.2f}</UnitCost>',
                      f'          <Total>{item["total"]:.2f}</Total>',
                      '        </LineItem>']
        lines += ['      </LineItems>', '    </Room>']
    lines += ['  </Rooms>', '</XactimateEstimate>']
    resp = make_response('\n'.join(lines))
    resp.headers['Content-Type'] = 'application/xml'
    resp.headers['Content-Disposition'] = f'attachment; filename="{claim["claim_number"]}-xactimate.esx"'
    return resp


# ── FEMA Flood Zone Lookup ────────────────────────────────────────────────────
@app.route('/claims/<int:claim_id>/fema-lookup', methods=['POST'])
@login_required
def fema_lookup(claim_id):
    db = get_db()
    claim = db.execute('SELECT * FROM claims WHERE id=?', (claim_id,)).fetchone()
    if not claim:
        return jsonify({'error': 'not found'}), 404
    result = lookup_fema_flood_zone(claim['property_address'])
    if result:
        result = dict(result) if not isinstance(result, dict) else result
        db.execute('UPDATE claims SET flood_zone=?,fema_map_number=?,lat=?,lng=?,maps_embed_url=? WHERE id=?',
                   (result.get('flood_zone',''), result.get('fema_map_number',''),
                    result.get('lat',0), result.get('lng',0), result.get('maps_embed_url',''), claim_id))
        db.commit()
    return jsonify({'ok': True, **result})


# ── Client Portal ─────────────────────────────────────────────────────────────
@app.route('/claims/<int:claim_id>/portal/generate', methods=['POST'])
@login_required
def generate_portal_link(claim_id):
    db = get_db()
    token = secrets.token_urlsafe(24)
    db.execute('DELETE FROM client_portal_tokens WHERE claim_id=?', (claim_id,))
    db.execute('INSERT INTO client_portal_tokens (claim_id, token) VALUES (?,?)', (claim_id, token))
    db.commit()
    portal_url = url_for('client_portal', token=token, _external=True)
    claim = db.execute('SELECT * FROM claims WHERE id=?', (claim_id,)).fetchone()
    if claim['client_email']:
        subject = f'View Your Flood Damage Claim — {claim["claim_number"]}'
        html = f'''<div style="font-family:sans-serif;max-width:600px;margin:0 auto">
            <h2 style="color:#0a1628">Your Claim Portal</h2>
            <p>Hello {claim["client_name"]},</p>
            <p>Your adjuster has shared your flood damage claim with you.</p>
            <p><a href="{portal_url}" style="background:#0a1628;color:#fff;padding:12px 24px;border-radius:8px;text-decoration:none;display:inline-block;margin:16px 0">View My Claim ↗</a></p>
            <p style="font-size:12px;color:#94a3b8">Claim: {claim["claim_number"]} · FloodClaim Pro</p></div>'''
        send_email(claim['client_email'], subject, html)
    return jsonify({'ok': True, 'portal_url': portal_url, 'token': token})


@app.route('/portal/<token>')
def client_portal(token):
    db = get_db()
    row = db.execute('SELECT claim_id FROM client_portal_tokens WHERE token=?', (token,)).fetchone()
    if not row:
        return render_template('portal_invalid.html'), 404
    claim_id = row['claim_id']
    claim = db.execute('''SELECT c.*, u.name as adjuster_name, u.email as adjuster_email
        FROM claims c LEFT JOIN users u ON c.adjuster_id=u.id WHERE c.id=?''', (claim_id,)).fetchone()
    rooms = db.execute('SELECT * FROM rooms WHERE claim_id=? ORDER BY id', (claim_id,)).fetchall()
    room_data = []
    for room in rooms:
        items  = db.execute('SELECT * FROM line_items WHERE room_id=? ORDER BY id', (room['id'],)).fetchall()
        photos = db.execute('SELECT * FROM photos WHERE room_id=? ORDER BY id', (room['id'],)).fetchall()
        room_data.append({'room': room, 'line_items': items, 'room_photos': photos})
    return render_template('client_portal.html', claim=claim, room_data=room_data, token=token,
                           generated=datetime.datetime.now().strftime('%B %d, %Y'))


# ── Digital Signature ─────────────────────────────────────────────────────────
@app.route('/claims/<int:claim_id>/sign', methods=['POST'])
def sign_claim(claim_id):
    data = request.get_json(silent=True) or {}
    signer   = data.get('signer', 'Client').strip()
    sig_data = data.get('sig_data', '').strip()
    if not sig_data:
        return jsonify({'error': 'sig_data required'}), 400
    db = get_db()
    db.execute('DELETE FROM signatures WHERE claim_id=?', (claim_id,))
    db.execute('INSERT INTO signatures (claim_id, signer, sig_data) VALUES (?,?,?)',
               (claim_id, signer, sig_data))
    db.commit()
    return jsonify({'ok': True, 'message': f'Claim signed by {signer}'})


@app.route('/claims/<int:claim_id>/signature')
@login_required
def get_signature(claim_id):
    db = get_db()
    sig = db.execute('SELECT * FROM signatures WHERE claim_id=? ORDER BY id DESC LIMIT 1', (claim_id,)).fetchone()
    if not sig:
        return jsonify({'signed': False})
    return jsonify({'signed': True, 'signer': sig['signer'], 'signed_at': sig['signed_at']})


# ── Stripe Subscriptions ──────────────────────────────────────────────────────
STRIPE_PLANS = [
    {'id': 'basic',  'name': 'Basic',  'price': '$49/mo',  'price_cents': 4900,
     'stripe_price_id': 'price_1TS3NiE50C70iVkQpmBiiQr0',
     'features': ['25 claims/mo', 'PDF export', 'Aquila AI', 'Client portal', 'NFIP Compliance']},
    {'id': 'pro',    'name': 'Pro',    'price': '$99/mo',  'price_cents': 9900,
     'stripe_price_id': 'price_1TS3NiE50C70iVkQGZYJRdNq',
     'features': ['100 claims/mo', 'Everything in Basic', 'Xactimate export', 'Analytics', 'Priority support']},
    {'id': 'agency', 'name': 'Agency', 'price': '$249/mo', 'price_cents': 24900,
     'stripe_price_id': 'price_1TS3NiE50C70iVkQD6vVFdsV',
     'features': ['Unlimited claims', 'Everything in Pro', 'Multi-adjuster team', 'White-label reports', 'SMS alerts']},
]

@app.route('/billing')
@login_required
def billing():
    db  = get_db()
    sub = db.execute('SELECT * FROM stripe_customers WHERE user_id=?', (session['user_id'],)).fetchone()
    stripe_pub = get_setting('stripe_publishable_key') or os.environ.get('STRIPE_PUBLISHABLE_KEY', '')
    return render_template('billing.html', plans=STRIPE_PLANS, sub=sub, stripe_pub=stripe_pub)

@app.route('/billing/checkout', methods=['POST'])
@login_required
@csrf_required
def billing_checkout():
    plan_id    = request.form.get('plan', 'basic')
    stripe_key = get_setting('stripe_secret_key') or os.environ.get('STRIPE_SECRET_KEY', '')
    if not stripe_key or not STRIPE_OK:
        flash('Stripe not configured — add your STRIPE_SECRET_KEY in Settings first.', 'error')
        return redirect(url_for('billing'))
    try:
        _stripe.api_key = stripe_key
        plan = next((p for p in STRIPE_PLANS if p['id'] == plan_id), STRIPE_PLANS[0])
        checkout = _stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{'price_data': {
                'currency': 'usd',
                'product_data': {'name': f'FloodClaim Pro — {plan["name"]} Plan'},
                'unit_amount': plan['price_cents'],
                'recurring': {'interval': 'month'},
            }, 'quantity': 1}],
            mode='subscription',
            success_url=url_for('billing_success', _external=True) + '?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=url_for('billing', _external=True),
            customer_email=session.get('email', ''),
            metadata={'user_id': str(session['user_id']), 'plan': plan_id},
        )
        return redirect(checkout.url, code=303)
    except Exception as e:
        flash(f'Stripe error: {e}', 'error')
        return redirect(url_for('billing'))

@app.route('/billing/success')
@login_required
def billing_success():
    session_id = request.args.get('session_id', '')
    stripe_key = get_setting('stripe_secret_key') or os.environ.get('STRIPE_SECRET_KEY', '')
    if session_id and stripe_key and STRIPE_OK:
        try:
            _stripe.api_key = stripe_key
            cs = _stripe.checkout.Session.retrieve(session_id)
            plan_id = cs.get('metadata', {}).get('plan', 'basic')
            db = get_db()
            db.execute('''
                INSERT INTO stripe_customers (user_id, stripe_customer, stripe_sub_id, plan, status)
                VALUES (?,?,?,?,?)
                ON CONFLICT(user_id) DO UPDATE SET
                  stripe_customer=excluded.stripe_customer,
                  stripe_sub_id=excluded.stripe_sub_id,
                  plan=excluded.plan, status=excluded.status
            ''', (session['user_id'], cs.get('customer',''), cs.get('subscription',''), plan_id, 'active'))
            db.commit()
        except Exception:
            pass
    flash('🎉 Subscription activated! Welcome to FloodClaim Pro.', 'success')
    return redirect(url_for('billing'))

@app.route('/billing/portal', methods=['POST'])
@login_required
@csrf_required
def billing_portal():
    stripe_key = get_setting('stripe_secret_key') or os.environ.get('STRIPE_SECRET_KEY', '')
    if not stripe_key or not STRIPE_OK:
        flash('Stripe not configured.', 'error')
        return redirect(url_for('billing'))
    db  = get_db()
    sub = db.execute('SELECT * FROM stripe_customers WHERE user_id=?', (session['user_id'],)).fetchone()
    if not sub or not sub['stripe_customer']:
        flash('No active subscription found.', 'error')
        return redirect(url_for('billing'))
    try:
        _stripe.api_key = stripe_key
        portal = _stripe.billing_portal.Session.create(
            customer=sub['stripe_customer'],
            return_url=url_for('billing', _external=True)
        )
        return redirect(portal.url, code=303)
    except Exception as e:
        flash(f'Stripe portal error: {e}', 'error')
        return redirect(url_for('billing'))

def call_openrouter(messages, model, key, max_tokens=4000):
    """Call OpenRouter chat completions API. Returns response text or error string."""
    try:
        r = _req.post(
            'https://openrouter.ai/api/v1/chat/completions',
            headers={'Authorization': f'Bearer {key}', 'Content-Type': 'application/json'},
            json={'model': model, 'messages': messages, 'max_tokens': max_tokens},
            timeout=90
        )
        if r.status_code == 401:
            return 'Error: Invalid or expired OpenRouter API key. Please update it in Settings.'
        if r.status_code == 402:
            return 'Error: OpenRouter account out of credits. Please add credits at openrouter.ai.'
        if r.status_code == 429:
            return 'Error: AI rate limit reached. Please wait a moment and try again.'
        data = r.json()
        if 'error' in data:
            return f'AI Error: {data["error"].get("message", str(data["error"]))}'
        return data['choices'][0]['message']['content'].strip()
    except Exception as e:
        return f'Error calling AI: {str(e)}'


def ai_describe_photo(image_path):
    key = get_setting('openrouter_api_key') or OPENROUTER_KEY
    if not key:
        try:
            kys_token = os.environ.get('KYS_API_TOKEN', '')
            kys_url   = os.environ.get('KYS_URL', 'https://ai-api-tracker-production.up.railway.app')
            if kys_token:
                r = _req.post(f'{kys_url}/api/fetch-key',
                              headers={'Authorization': f'Bearer {kys_token}',
                                       'Content-Type': 'application/json'},
                              json={'key': 'openrouter'}, timeout=5)
                d = r.json()
                if d.get('ok'):
                    key = d.get('value', '')
        except Exception:
            pass
    if not key:
        return ''   # No key — store blank, don't pollute the DB with error strings
    try:
        with open(image_path, 'rb') as f:
            img_b64 = base64.b64encode(f.read()).decode()
        ext  = image_path.rsplit('.', 1)[-1].lower()
        mime = f'image/{ext}' if ext != 'jpg' else 'image/jpeg'
        selected_model = get_setting('ai_model', 'openai/gpt-4o-mini')
        r = _req.post(
            'https://openrouter.ai/api/v1/chat/completions',
            headers={'Authorization': f'Bearer {key}', 'Content-Type': 'application/json'},
            json={
                'model': selected_model,
                'messages': [{
                    'role': 'user',
                    'content': [
                        {'type': 'text', 'text': (
                            'You are a flood damage assessor. Describe the flood damage '
                            'visible in this photo in 2-3 sentences. Be specific about what '
                            'is damaged, the severity, and likely repair needs. Be professional and concise.'
                        )},
                        {'type': 'image_url', 'image_url': {'url': f'data:{mime};base64,{img_b64}'}}
                    ]
                }],
                'max_tokens': 200
            }, timeout=30)
        return r.json()['choices'][0]['message']['content']
    except Exception as e:
        return ''  # Return empty so it can be retried — never pollute DB with error strings

# ── Routes ────────────────────────────────────────────────────────────────────

# In-memory rate limiter {key: [timestamp, ...]}
_rate_store: dict = {}

def is_rate_limited(key, max_calls=5, window=60):
    """Return True if key has exceeded max_calls within window seconds."""
    import time
    now = time.time()
    calls = [t for t in _rate_store.get(key, []) if now - t < window]
    _rate_store[key] = calls
    if len(calls) >= max_calls:
        return True
    _rate_store[key].append(now)
    return False

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
@csrf_required
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        ip    = request.remote_addr or 'unknown'
        if is_rate_limited(f'login:{ip}', max_calls=5, window=60):
            flash('Too many login attempts. Please wait a minute and try again.', 'error')
            return render_template('login.html')
        email = request.form.get('email', '').strip().lower()
        pw    = request.form.get('password', '')
        db    = get_db()
        user  = db.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
        if not user or not check_pw(pw, user['password']):
            flash('Invalid email or password.', 'error')
            return render_template('login.html')
        # Transparent bcrypt upgrade: if stored hash is legacy sha256, re-hash now
        if BCRYPT_OK and user['password'] and not user['password'].startswith('$2'):
            db.execute('UPDATE users SET password=? WHERE id=?',
                       (hash_pw(pw), user['id']))
            db.commit()
        session.permanent = True
        session['user_id'] = user['id']
        session['email']   = user['email']
        session['name']    = user['name']
        session['role']    = user['role']
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    db = get_db()
    # Search + filter params
    q          = request.args.get('q', '').strip()
    f_status   = request.args.get('status', '')
    f_adjuster = request.args.get('adjuster_id', '')
    f_priority = request.args.get('priority', '')
    f_date_from= request.args.get('date_from', '')
    f_date_to  = request.args.get('date_to', '')

    base_sql = '''SELECT c.*, u.name as adjuster_name
        FROM claims c LEFT JOIN users u ON c.adjuster_id=u.id WHERE 1=1'''
    params = []
    if session['role'] != 'admin':
        base_sql += ' AND c.adjuster_id=?'
        params.append(session['user_id'])
    if q:
        base_sql += ' AND (c.client_name LIKE ? OR c.claim_number LIKE ? OR c.property_address LIKE ?)'
        like = f'%{q}%'
        params += [like, like, like]
    if f_status:
        base_sql += ' AND c.status=?'
        params.append(f_status)
    if f_adjuster and session['role'] == 'admin':
        base_sql += ' AND c.adjuster_id=?'
        params.append(f_adjuster)
    if f_priority:
        base_sql += ' AND c.priority=?'
        params.append(f_priority)
    if f_date_from:
        base_sql += ' AND c.flood_date >= ?'
        params.append(f_date_from)
    if f_date_to:
        base_sql += ' AND c.flood_date <= ?'
        params.append(f_date_to)
    base_sql += ' ORDER BY c.created_at DESC'
    claims = db.execute(base_sql, params).fetchall()

    # Stats always from full set (no filters)
    if session['role'] == 'admin':
        all_claims = db.execute('SELECT status, total_estimate FROM claims').fetchall()
    else:
        all_claims = db.execute('SELECT status, total_estimate FROM claims WHERE adjuster_id=?',
                                (session['user_id'],)).fetchall()
    stats = {
        'total':       len(all_claims),
        'new':         sum(1 for c in all_claims if c['status'] == 'New'),
        'in_progress': sum(1 for c in all_claims if c['status'] == 'In Progress'),
        'submitted':   sum(1 for c in all_claims if c['status'] == 'Submitted'),
        'closed':      sum(1 for c in all_claims if c['status'] == 'Closed'),
        'pipeline':    sum(c['total_estimate'] for c in all_claims if c['status'] != 'Closed'),
    }
    adjusters = db.execute('SELECT * FROM users ORDER BY name').fetchall() \
                if session['role'] == 'admin' else []
    return render_template('dashboard.html', claims=claims, stats=stats, adjusters=adjusters,
                           q=q, f_status=f_status, f_adjuster=f_adjuster,
                           f_priority=f_priority, f_date_from=f_date_from, f_date_to=f_date_to)

@app.route('/claims/new', methods=['GET', 'POST'])
@login_required
@csrf_required
def new_claim():
    db = get_db()
    if request.method == 'POST':
        claim_num   = gen_claim_number()
        adjuster_id = request.form.get('adjuster_id') or session['user_id']
        g  = lambda k, d='': request.form.get(k, d)  # shorthand
        db.execute('''INSERT INTO claims
            (claim_number, adjuster_id, client_name, client_phone, client_phone_alt, client_email,
             property_address, property_type, property_sqft, year_built, num_floors,
             flood_date, flood_source, water_category, water_class, water_depth_in,
             date_water_removed, inspection_date,
             insurance_company, policy_number, policy_type,
             coverage_building, coverage_contents, deductible,
             mortgage_company, mortgage_loan_number,
             cause_of_loss, priority, notes)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)''',
            (claim_num, adjuster_id,
             g('client_name'), g('client_phone'), g('client_phone_alt'), g('client_email'),
             g('property_address'), g('property_type'), g('property_sqft'),
             g('year_built'), g('num_floors'),
             g('flood_date'), g('flood_source'), g('water_category'),
             g('water_class'), g('water_depth_in'), g('date_water_removed'),
             g('inspection_date'),
             g('insurance_company'), g('policy_number'), g('policy_type'),
             float(g('coverage_building') or 0), float(g('coverage_contents') or 0),
             float(g('deductible') or 0),
             g('mortgage_company'), g('mortgage_loan_number'),
             g('cause_of_loss'), g('priority', 'Normal'), g('notes')))
        db.commit()
        # Handle initial photos submitted with the form
        photos = request.files.getlist('initial_photos')
        claim  = db.execute('SELECT * FROM claims WHERE claim_number=?', (claim_num,)).fetchone()
        for photo in photos:
            if photo and photo.filename and allowed_file(photo.filename):
                ext      = photo.filename.rsplit('.', 1)[1].lower()
                filename = f'{secrets.token_hex(12)}.{ext}'
                save_path = os.path.join(UPLOAD_DIR, filename)
                photo.save(save_path)
                ai_desc = ai_describe_photo(save_path)
                db.execute(
                    'INSERT INTO photos (claim_id, filename, caption, ai_description) VALUES (?,?,?,?)',
                    (claim['id'], filename, 'Initial site photo', ai_desc))
        db.commit()
        flash(f'Claim {claim_num} created!', 'success')
        return redirect(url_for('claim_detail', claim_id=claim['id']))
    adjusters = db.execute('SELECT * FROM users ORDER BY name').fetchall() \
                if session['role'] == 'admin' else []
    return render_template('new_claim.html', adjusters=adjusters)

@app.route('/claims/<int:claim_id>/delete', methods=['POST'])
@login_required
@csrf_required
def delete_claim(claim_id):
    """Delete a claim and all its rooms, line items, and photos."""
    db = get_db()
    claim = db.execute('SELECT id, client_name, claim_number FROM claims WHERE id=?', (claim_id,)).fetchone()
    if not claim:
        flash('Claim not found.', 'error')
        return redirect(url_for('dashboard'))
    # Delete uploaded photo files from disk
    photos = db.execute('SELECT filename FROM photos WHERE claim_id=?', (claim_id,)).fetchall()
    for p in photos:
        try:
            path = os.path.join(UPLOAD_DIR, p['filename'])
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass
    db.execute('DELETE FROM claims WHERE id=?', (claim_id,))
    db.commit()
    flash(f'Claim {claim["claim_number"]} ({claim["client_name"]}) deleted.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/claims/<int:claim_id>/nfip-fill', methods=['POST'])
@login_required
@csrf_required
def nfip_quick_fill(claim_id):
    """Quick-fill all NFIP compliance fields in one shot."""
    db = get_db()
    claim = db.execute('SELECT id FROM claims WHERE id=?', (claim_id,)).fetchone()
    if not claim:
        flash('Claim not found.', 'error')
        return redirect(url_for('dashboard'))
    f = request.form
    db.execute('''
        UPDATE claims SET
            policy_type=?, coverage_building=?, coverage_contents=?, deductible=?,
            flood_source=?, water_category=?, water_class=?, water_depth_in=?,
            date_water_removed=?, flood_zone=?, fema_map_number=?, inspection_date=?,
            updated_at=CURRENT_TIMESTAMP
        WHERE id=?
    ''', (
        f.get('policy_type','').strip(),
        float(f.get('coverage_building') or 0),
        float(f.get('coverage_contents') or 0),
        float(f.get('deductible') or 0),
        f.get('flood_source','').strip(),
        f.get('water_category','').strip(),
        f.get('water_class','').strip(),
        f.get('water_depth_in','').strip(),
        f.get('date_water_removed','').strip(),
        f.get('flood_zone','').strip(),
        f.get('fema_map_number','').strip(),
        f.get('inspection_date','').strip(),
        claim_id
    ))
    db.commit()
    flash('NFIP fields saved — recheck your compliance score!', 'success')
    return redirect(url_for('claim_detail', claim_id=claim_id))


@app.route('/claims/<int:claim_id>/notes', methods=['POST'])
@login_required
@csrf_required
def update_claim_notes(claim_id):
    """Update the notes field on a claim."""
    db = get_db()
    claim = db.execute('SELECT id FROM claims WHERE id=?', (claim_id,)).fetchone()
    if not claim:
        return jsonify({'ok': False, 'error': 'Claim not found'}), 404
    notes = request.form.get('notes', '').strip()
    db.execute('UPDATE claims SET notes=?, updated_at=CURRENT_TIMESTAMP WHERE id=?', (notes, claim_id))
    db.commit()
    flash('Notes saved.', 'success')
    return redirect(url_for('claim_detail', claim_id=claim_id))


@app.route('/claims/<int:claim_id>')
@login_required
def claim_detail(claim_id):
    try:
        db = get_db()
        claim = db.execute('''SELECT c.*, u.name as adjuster_name
            FROM claims c LEFT JOIN users u ON c.adjuster_id=u.id WHERE c.id=?''',
            (claim_id,)).fetchone()
        if not claim:
            flash('Claim not found.', 'error')
            return redirect(url_for('dashboard'))
        rooms = db.execute('SELECT * FROM rooms WHERE claim_id=? ORDER BY id', (claim_id,)).fetchall()
        room_data = []
        for room in rooms:
            items  = db.execute('SELECT * FROM line_items WHERE room_id=? ORDER BY id', (room['id'],)).fetchall()
            photos = db.execute('SELECT * FROM photos WHERE room_id=? ORDER BY id',     (room['id'],)).fetchall()
            room_data.append({'room': room, 'line_items': items, 'room_photos': photos})
        unassigned_photos = db.execute(
            'SELECT * FROM photos WHERE claim_id=? AND room_id IS NULL ORDER BY id',
            (claim_id,)).fetchall()
        recalc_claim(claim_id)
        # Re-fetch after recalc so totals are fresh
        claim = db.execute('''SELECT c.*, u.name as adjuster_name
            FROM claims c LEFT JOIN users u ON c.adjuster_id=u.id WHERE c.id=?''',
            (claim_id,)).fetchone()
        if not claim:
            flash('Claim not found.', 'error')
            return redirect(url_for('dashboard'))
        signature = db.execute(
            'SELECT * FROM signatures WHERE claim_id=? ORDER BY id DESC LIMIT 1',
            (claim_id,)).fetchone()
        return render_template('claim_detail.html', claim=claim,
                               room_data=room_data, unassigned_photos=unassigned_photos,
                               signature=signature)
    except Exception as _claim_err:
        import traceback as _tb
        print(f'[claim_detail ERROR] claim_id={claim_id}: {_claim_err}\n{_tb.format_exc()}')
        flash(f'Error loading claim — check server logs for details: {_claim_err}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/claims/<int:claim_id>/status', methods=['POST'])
@login_required
@csrf_required
def update_status(claim_id):
    db = get_db()
    status = request.form.get('status')
    claim = db.execute('SELECT * FROM claims WHERE id=?', (claim_id,)).fetchone()
    db.execute('UPDATE claims SET status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?',
               (status, claim_id))
    db.commit()
    if claim:
        notify_client_status_change(claim, status)
        _log_activity(claim_id, f'Status changed to {status}')
    return redirect(url_for('claim_detail', claim_id=claim_id))

@app.route('/claims/<int:claim_id>/room/add', methods=['POST'])
@login_required
@csrf_required
def add_room(claim_id):
    db    = get_db()
    claim = db.execute('SELECT id FROM claims WHERE id=?', (claim_id,)).fetchone()
    if not claim:
        flash('Claim not found.', 'error')
        return redirect(url_for('dashboard'))
    name = request.form.get('room_name', '').strip()
    if name:
        db.execute('INSERT INTO rooms (claim_id, name) VALUES (?,?)', (claim_id, name))
        db.commit()
    return redirect(url_for('claim_detail', claim_id=claim_id))

@app.route('/rooms/<int:room_id>/delete', methods=['POST'])
@login_required
@csrf_required
def delete_room(room_id):
    db   = get_db()
    room = db.execute('SELECT * FROM rooms WHERE id=?', (room_id,)).fetchone()
    if not room:
        return redirect(url_for('dashboard'))
    claim_id = room['claim_id']
    # CASCADE in schema deletes line_items; unassign photos back to claim
    db.execute('UPDATE photos SET room_id=NULL WHERE room_id=?', (room_id,))
    db.execute('DELETE FROM rooms WHERE id=?', (room_id,))
    db.commit()
    recalc_claim(claim_id)
    return redirect(url_for('claim_detail', claim_id=claim_id))

@app.route('/rooms/<int:room_id>/item/add', methods=['POST'])
@login_required
@csrf_required
def add_item(room_id):
    db        = get_db()
    room      = db.execute('SELECT * FROM rooms WHERE id=?', (room_id,)).fetchone()
    if not room:
        return redirect(url_for('dashboard'))
    desc      = request.form.get('description', '')
    qty       = float(request.form.get('quantity', 1) or 1)
    unit      = request.form.get('unit', 'ea')
    unit_cost = float(request.form.get('unit_cost', 0) or 0)
    total     = qty * unit_cost
    db.execute(
        'INSERT INTO line_items (room_id, description, quantity, unit, unit_cost, total) '
        'VALUES (?,?,?,?,?,?)',
        (room_id, desc, qty, unit, unit_cost, total))
    db.commit()
    recalc_claim(room['claim_id'])
    return redirect(url_for('claim_detail', claim_id=room['claim_id']))

@app.route('/items/<int:item_id>/delete', methods=['POST'])
@login_required
@csrf_required
def delete_item(item_id):
    db   = get_db()
    item = db.execute(
        'SELECT r.claim_id FROM line_items li JOIN rooms r ON li.room_id=r.id WHERE li.id=?',
        (item_id,)).fetchone()
    db.execute('DELETE FROM line_items WHERE id=?', (item_id,))
    db.commit()
    if item:
        recalc_claim(item['claim_id'])
    return jsonify({'ok': True})

@app.route('/claims/<int:claim_id>/photo/upload', methods=['POST'])
@login_required
@csrf_required
def upload_photo(claim_id):
    db      = get_db()
    file    = request.files.get('photo')
    room_id = request.form.get('room_id') or None
    caption = request.form.get('caption', '')
    if not file or not allowed_file(file.filename):
        flash('Invalid file type. Please upload a PNG, JPG, GIF, or WEBP.', 'error')
        return redirect(url_for('claim_detail', claim_id=claim_id))
    ext       = file.filename.rsplit('.', 1)[1].lower()
    filename  = f'{secrets.token_hex(12)}.{ext}'
    save_path = os.path.join(UPLOAD_DIR, filename)
    file.save(save_path)
    ai_desc = ai_describe_photo(save_path)
    db.execute(
        'INSERT INTO photos (claim_id, room_id, filename, caption, ai_description) '
        'VALUES (?,?,?,?,?)',
        (claim_id, room_id, filename, caption, ai_desc))
    db.commit()
    flash('Photo uploaded!' + (' AI analysis complete.' if ai_desc else
          ' Add an OpenRouter key in Settings to enable AI analysis.'), 'success')
    return redirect(url_for('claim_detail', claim_id=claim_id))

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(UPLOAD_DIR, filename)

@app.route('/photos/<int:photo_id>/delete', methods=['POST'])
@login_required
@csrf_required
def delete_photo(photo_id):
    db    = get_db()
    photo = db.execute('SELECT * FROM photos WHERE id=?', (photo_id,)).fetchone()
    if not photo:
        return jsonify({'ok': False, 'error': 'Not found'}), 404
    # Delete the file from disk
    try:
        file_path = os.path.join(UPLOAD_DIR, photo['filename'])
        if os.path.exists(file_path):
            os.remove(file_path)
    except Exception:
        pass
    db.execute('DELETE FROM photos WHERE id=?', (photo_id,))
    db.commit()
    return jsonify({'ok': True})

@app.route('/photos/<int:photo_id>/ai-description', methods=['POST'])
@login_required
def edit_ai_description(photo_id):
    """Save a manually edited AI description for a photo."""
    data = request.get_json(silent=True) or {}
    description = data.get('description', '').strip()
    db = get_db()
    db.execute('UPDATE photos SET ai_description=? WHERE id=?', (description, photo_id))
    db.commit()
    return jsonify({'ok': True})


@app.route('/photos/<int:photo_id>/analyze', methods=['POST'])
@login_required
def analyze_photo_route(photo_id):
    db    = get_db()
    photo = db.execute('SELECT * FROM photos WHERE id=?', (photo_id,)).fetchone()
    if not photo:
        return jsonify({'error': 'Photo not found'}), 404
    image_path = os.path.join(UPLOAD_DIR, photo['filename'])
    if not os.path.exists(image_path):
        return jsonify({'error': 'Image file not found on disk'}), 404
    desc = ai_describe_photo(image_path)
    if not desc:
        return jsonify({'error': 'AI unavailable — add an OpenRouter key in ⚙️ Settings'})
    db.execute('UPDATE photos SET ai_description=? WHERE id=?', (desc, photo_id))
    db.commit()
    return jsonify({'ok': True, 'description': desc})

@app.route('/photos/<int:photo_id>/edit', methods=['POST'])
@login_required
@csrf_required
def edit_photo(photo_id):
    db      = get_db()
    photo   = db.execute('SELECT * FROM photos WHERE id=?', (photo_id,)).fetchone()
    if not photo:
        flash('Photo not found.', 'error')
        return redirect(url_for('dashboard'))
    caption = request.form.get('caption', '').strip()
    room_id = request.form.get('room_id') or None
    db.execute('UPDATE photos SET caption=?, room_id=? WHERE id=?',
               (caption, room_id, photo_id))
    db.commit()
    flash('Photo updated!', 'success')
    return redirect(url_for('claim_detail', claim_id=photo['claim_id']))

@app.route('/claims/<int:claim_id>/report')
@login_required
def report(claim_id):
    db    = get_db()
    claim = db.execute('''SELECT c.*, u.name as adjuster_name, u.email as adjuster_email
        FROM claims c LEFT JOIN users u ON c.adjuster_id=u.id WHERE c.id=?''',
        (claim_id,)).fetchone()
    if not claim:
        flash('Claim not found.', 'error')
        return redirect(url_for('dashboard'))
    rooms = db.execute('SELECT * FROM rooms WHERE claim_id=? ORDER BY id', (claim_id,)).fetchall()
    room_data = []
    for room in rooms:
        items  = db.execute('SELECT * FROM line_items WHERE room_id=? ORDER BY id', (room['id'],)).fetchall()
        photos = db.execute('SELECT * FROM photos WHERE room_id=? ORDER BY id',     (room['id'],)).fetchall()
        room_data.append({'room': room, 'line_items': items, 'room_photos': photos})
    unassigned_photos = db.execute(
        'SELECT * FROM photos WHERE claim_id=? AND room_id IS NULL', (claim_id,)).fetchall()
    recalc_claim(claim_id)
    claim = db.execute('''SELECT c.*, u.name as adjuster_name, u.email as adjuster_email
        FROM claims c LEFT JOIN users u ON c.adjuster_id=u.id WHERE c.id=?''',
        (claim_id,)).fetchone()
    signature = db.execute(
        'SELECT * FROM signatures WHERE claim_id=? ORDER BY id DESC LIMIT 1',
        (claim_id,)).fetchone()
    return render_template('report.html', claim=claim, room_data=room_data,
                           unassigned_photos=unassigned_photos, signature=signature,
                           generated=datetime.datetime.now().strftime('%B %d, %Y %I:%M %p'))

# ── Admin: Settings ───────────────────────────────────────────────────────────

@app.route('/admin/settings', methods=['GET', 'POST'])
@login_required
@admin_required
@csrf_required
def settings():
    if request.method == 'POST':
        openrouter_key = request.form.get('openrouter_api_key', '').strip()
        if openrouter_key:
            set_setting('openrouter_api_key', openrouter_key)
        elif request.form.get('clear_openrouter'):
            set_setting('openrouter_api_key', '')
        selected_model = request.form.get('ai_model', '').strip()
        if selected_model:
            set_setting('ai_model', selected_model)
        # New integration keys
        for key in ['sendgrid_api_key', 'from_email', 'stripe_secret_key',
                    'stripe_publishable_key', 'google_maps_api_key',
                    'twilio_account_sid', 'twilio_auth_token', 'twilio_from_number',
                    'admin_report_email']:
            val = request.form.get(key, '').strip()
            if val:
                set_setting(key, val)
        # Willie integration key
        willie_key_input = request.form.get('willie_agent_key', '').strip()
        if willie_key_input and not willie_key_input.endswith('...'):
            set_setting('willie_agent_key', willie_key_input)
        flash('Settings saved!', 'success')
        return redirect(url_for('settings'))
    current_key = get_setting('openrouter_api_key')
    masked_key  = ''
    if current_key:
        if len(current_key) > 12:
            masked_key = current_key[:8] + '•' * (len(current_key) - 12) + current_key[-4:]
        else:
            masked_key = '••••••••'
    env_key_set       = bool(OPENROUTER_KEY)
    current_model     = get_setting('ai_model', 'openai/gpt-4o-mini')
    current_willie_key = get_setting('willie_agent_key', '')
    return render_template('settings.html',
                           masked_key=masked_key,
                           key_is_set=bool(current_key),
                           env_key_set=env_key_set,
                           current_model=current_model,
                           current_willie_key=current_willie_key)

# ── Admin: Team Management ────────────────────────────────────────────────────

@app.route('/admin/team')
@login_required
@admin_required
def team():
    users = get_db().execute(
        'SELECT u.*, (SELECT COUNT(*) FROM claims WHERE adjuster_id=u.id) as claim_count '
        'FROM users u ORDER BY u.name').fetchall()
    return render_template('team.html', users=users)

@app.route('/admin/team/add', methods=['POST'])
@login_required
@admin_required
@csrf_required
def add_team_member():
    db    = get_db()
    email = request.form.get('email', '').strip().lower()
    name  = request.form.get('name', '').strip()
    pw    = request.form.get('password', '').strip()
    role  = request.form.get('role', 'adjuster')
    if not email or not pw:
        flash('Email and password required.', 'error')
        return redirect(url_for('team'))
    try:
        db.execute('INSERT INTO users (email, name, password, role) VALUES (?,?,?,?)',
                   (email, name, hash_pw(pw), role))
        db.commit()
        flash(f'Team member {name} added!', 'success')
    except sqlite3.IntegrityError:
        flash('Email already exists.', 'error')
    return redirect(url_for('team'))

@app.route('/admin/team/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
@csrf_required
def delete_team_member(user_id):
    if user_id == session['user_id']:
        flash("Can't delete yourself.", 'error')
        return redirect(url_for('team'))
    db = get_db()
    # Unassign their claims first to avoid FK constraint error
    db.execute('UPDATE claims SET adjuster_id=NULL WHERE adjuster_id=?', (user_id,))
    db.execute('DELETE FROM willie_conversations WHERE user_id=?', (user_id,))
    db.execute('DELETE FROM users WHERE id=?', (user_id,))
    db.commit()
    flash('Team member removed.', 'success')
    return redirect(url_for('team'))

# ── Aquila Chat ────────────────────────────────────────────────────────────────

@app.route('/willie')
@login_required
def willie():
    db    = get_db()
    convs = db.execute(
        'SELECT * FROM willie_conversations WHERE user_id=? ORDER BY updated DESC LIMIT 100',
        (session['user_id'],)).fetchall()
    return render_template('willie.html', conversations=convs)

@app.route('/willie/conversations', methods=['POST'])
@login_required
def willie_new_conversation():
    db  = get_db()
    cur = db.execute('INSERT INTO willie_conversations (user_id) VALUES (?)', (session['user_id'],))
    db.commit()
    return jsonify({'id': cur.lastrowid, 'title': 'New Conversation'})

@app.route('/willie/conversations/<int:conv_id>')
@login_required
def willie_get_conversation(conv_id):
    db   = get_db()
    conv = db.execute('SELECT * FROM willie_conversations WHERE id=? AND user_id=?',
                      (conv_id, session['user_id'])).fetchone()
    if not conv:
        return jsonify({'error': 'not found'}), 404
    msgs = db.execute('SELECT role,content,created FROM willie_messages WHERE conversation_id=? ORDER BY id',
                      (conv_id,)).fetchall()
    return jsonify({'conversation': dict(conv), 'messages': [dict(m) for m in msgs]})

@app.route('/willie/conversations/<int:conv_id>', methods=['DELETE'])
@login_required
def willie_delete_conversation(conv_id):
    db = get_db()
    db.execute('DELETE FROM willie_messages WHERE conversation_id=?', (conv_id,))
    db.execute('DELETE FROM willie_conversations WHERE id=? AND user_id=?', (conv_id, session['user_id']))
    db.commit()
    return jsonify({'ok': True})

@app.route('/willie/conversations/<int:conv_id>/messages', methods=['POST'])
@login_required
def willie_save_message(conv_id):
    db      = get_db()
    conv    = db.execute('SELECT * FROM willie_conversations WHERE id=? AND user_id=?',
                         (conv_id, session['user_id'])).fetchone()
    if not conv:
        return jsonify({'error': 'not found'}), 404
    data    = request.get_json(silent=True) or {}
    role    = data.get('role', 'user')
    content = data.get('content', '').strip()
    if not content:
        return jsonify({'error': 'content required'}), 400
    db.execute('INSERT INTO willie_messages (conversation_id, role, content) VALUES (?,?,?)',
               (conv_id, role, content))
    # Auto-title from first user message
    if role == 'user' and conv['title'] == 'New Conversation':
        title = content[:60] + ('...' if len(content) > 60 else '')
        db.execute('UPDATE willie_conversations SET title=?, updated=CURRENT_TIMESTAMP WHERE id=?',
                   (title, conv_id))
    else:
        db.execute('UPDATE willie_conversations SET updated=CURRENT_TIMESTAMP WHERE id=?', (conv_id,))
    db.commit()
    return jsonify({'ok': True})

@app.route('/willie/chat', methods=['POST'])
@login_required
def willie_chat():
    """Smart Aquila chat proxy — injects live app context into every message."""
    data       = request.get_json(silent=True) or {}
    message    = data.get('message', '').strip()
    history    = data.get('history', [])
    conv_id    = data.get('conversation_id')
    session_id = data.get('session_id', '')
    claim_id   = data.get('claim_id')       # passed when chatting from a claim page
    context_hint = data.get('context', '') # page context hint
    if not message:
        return jsonify({'error': 'message required'}), 400

    WILLIE_AGENT_ID = get_setting('willie_agent_id', 'F5J8yYT6a6GrppjviN6p8w')
    WIDGET_BASE     = 'https://ai-agent-widget-production.up.railway.app'
    FLOOD_BASE      = request.host_url.rstrip('/')
    flood_token     = get_willie_token()

    # ── Build rich live context ─────────────────────────────────────────
    db = get_db()
    now_str = datetime.datetime.now().strftime('%A %B %d, %Y %I:%M %p')

    # Dashboard stats
    if session['role'] == 'admin':
        all_claims = db.execute('SELECT id, claim_number, client_name, property_address, status, total_estimate, flood_date, adjuster_id FROM claims ORDER BY created_at DESC').fetchall()
    else:
        all_claims = db.execute('SELECT id, claim_number, client_name, property_address, status, total_estimate, flood_date, adjuster_id FROM claims WHERE adjuster_id=? ORDER BY created_at DESC', (session['user_id'],)).fetchall()

    stats = {
        'total': len(all_claims),
        'new': sum(1 for c in all_claims if c['status'] == 'New'),
        'in_progress': sum(1 for c in all_claims if c['status'] == 'In Progress'),
        'submitted': sum(1 for c in all_claims if c['status'] == 'Submitted'),
        'closed': sum(1 for c in all_claims if c['status'] == 'Closed'),
        'pipeline': sum(c['total_estimate'] for c in all_claims if c['status'] != 'Closed'),
    }

    # Recent claims summary (last 10)
    recent_summary = '\n'.join(
        f'  - [{c["id"]}] {c["claim_number"]} | {c["client_name"]} | {c["property_address"][:40]} | {c["status"]} | ${c["total_estimate"]:,.0f}'
        for c in all_claims[:10]
    ) or '  (no claims yet)'

    # Current claim context (if on a claim page)
    claim_context = ''
    if claim_id:
        claim = db.execute('''
            SELECT c.*, u.name as adjuster_name
            FROM claims c LEFT JOIN users u ON c.adjuster_id=u.id
            WHERE c.id=?
        ''', (claim_id,)).fetchone()
        if claim:
            rooms = db.execute('SELECT * FROM rooms WHERE claim_id=? ORDER BY id', (claim_id,)).fetchall()
            room_lines = []
            for room in rooms:
                items = db.execute('SELECT * FROM line_items WHERE room_id=? ORDER BY id', (room['id'],)).fetchall()
                item_text = ', '.join(f'{i["description"]} ({i["quantity"]} {i["unit"]} @ ${i["unit_cost"]})' for i in items) or 'no items yet'
                room_lines.append(f'    Room [{room["id"]}] {room["name"]} (${room["subtotal"]:,.2f}): {item_text}')
            photos = db.execute('SELECT COUNT(*) as c FROM photos WHERE claim_id=?', (claim_id,)).fetchone()

            _nl = chr(10)
            rooms_text = _nl.join(room_lines) if room_lines else '    (no rooms added yet)'
            claim_context = (
                _nl + '┌─ CURRENT CLAIM (you are viewing this right now) ─────────────────────────' + _nl
                + f'| Claim ID: {claim["id"]} | Claim #: {claim["claim_number"]}' + _nl
                + f'| Client: {claim["client_name"]} | Phone: {claim["client_phone"] or "N/A"}' + _nl
                + f'| Property: {claim["property_address"]}' + _nl
                + f'| Status: {claim["status"]} | Priority: {claim["priority"] or "Normal"}' + _nl
                + f'| Flood Date: {claim["flood_date"]} | Source: {claim["flood_source"] or "N/A"}' + _nl
                + f'| Water: Category {claim["water_category"] or "?"} / Class {claim["water_class"] or "?"} / {claim["water_depth_in"] or "?"} inches' + _nl
                + f'| Insurance: {claim["insurance_company"] or "N/A"} | Policy: {claim["policy_number"] or "N/A"}' + _nl
                + f'| Coverage: Bldg ${claim["coverage_building"]:,.0f} | Contents ${claim["coverage_contents"]:,.0f} | Deductible ${claim["deductible"]:,.0f}' + _nl
                + f'| FEMA Zone: {claim["flood_zone"] or "NOT LOOKED UP"} | Map: {claim["fema_map_number"] or "N/A"}' + _nl
                + f'| Total Estimate: ${claim["total_estimate"]:,.2f} | Photos: {photos["c"]}' + _nl
                + f'| Adjuster: {claim["adjuster_name"] or "Unassigned"}' + _nl
                + f'| Rooms ({len(rooms)}):' + _nl
                + rooms_text + _nl
                + '└' + '─' * 65
            )

    # Today's inspections
    today_str = datetime.date.today().isoformat()
    todays_slots = db.execute('''
        SELECT s.*, c.claim_number, c.client_name, c.property_address
        FROM inspection_slots s JOIN claims c ON s.claim_id=c.id
        WHERE s.slot_date=? AND s.status != 'cancelled'
        ORDER BY s.slot_time
    ''', (today_str,)).fetchall()
    todays_insp = '\n'.join(
        f'  {s["slot_time"]} — {s["claim_number"]} ({s["client_name"]}) at {s["property_address"][:50]}'
        for s in todays_slots
    ) or '  None scheduled today'

    # Build the enriched system context injected as first message
    system_context = f"""You are Aquila, an expert AI flood damage adjuster assistant embedded inside FloodClaim Pro.
You have FULL CONTROL of the app and can take actions directly on behalf of the adjuster.
Always be helpful, concise, and professional. Use your knowledge of NFIP rules and flood claim procedures.

CURRENT USER: {session.get('name') or session.get('email')} (role: {session.get('role', 'adjuster')})
CURRENT TIME: {now_str}
PAGE CONTEXT: {context_hint or 'Dashboard'}

APP SNAPSHOT:
- Total claims: {stats['total']} | New: {stats['new']} | In Progress: {stats['in_progress']} | Submitted: {stats['submitted']} | Closed: {stats['closed']}
- Open pipeline value: ${stats['pipeline']:,.2f}
- Today's inspections: 
{todays_insp}

RECENT CLAIMS (use claim IDs below for API actions):
{recent_summary}
{claim_context}
YOUR CAPABILITIES (you can do all of these right now):
1. CREATE claims — just ask for client name, address, flood date
2. UPDATE any claim field — status, priority, water category, coverage, notes, etc.
3. ADD rooms and line items to any claim with exact pricing
4. LOOK UP claims by name, number, or address
5. RUN AI estimates on any claim
6. ANALYZE photos on any claim and suggest rooms/items
7. SCHEDULE inspections with date, time, adjuster
8. MOVE claims between pipeline stages
9. CHECK NFIP compliance score for any claim
10. LOOK UP FEMA flood zones by address
11. SEND client notifications
12. VIEW analytics and team data
13. ADD team members
14. ANSWER any question about NFIP rules, flood damage, water categories, pricing, procedures

NFIP EXPERTISE:
- Water Categories: Cat 1=clean, Cat 2=gray water, Cat 3=black/flood water (always Cat 3 for rising floodwater)
- Water Classes: 1=floors only, 2=walls up 24”, 3=ceiling wet, 4=hardwood/brick specialty drying
- Proof of Loss must be filed within 60 days of flood date or claim is denied
- 2026 national avg flood claim: $10,234-$11,605 | Full restoration: $5,000-$16,000
- Mitigation rates: Cat3 extraction $0.75-$1.50/sf, air movers $38-$55/day, dehumidifier $83-$110/day
- Drywall Cat3 tear-out: $1.79/sf | LVP/vinyl: $1.25-$2.00/sf | Hardwood: $5.82/sf
- Reconstruction: drywall $3.99-$5.50/sf | paint $1.50-$2.50/sf | baseboard R&R $5.51/lf
- FEMA flood zones: A/AE/AO/AH=high risk, B/X=moderate, C/X=minimal risk

When the user asks you to DO something (create a claim, add a room, update status, etc.):
1. Confirm what you are about to do
2. Use your API actions to execute it immediately
3. Report back what was done with specifics
4. Suggest the logical next step

When asked for advice, give specific, actionable NFIP-compliant guidance.
When referencing a claim, always use its claim number AND name so it's clear."""

    # Build payload with context prepended as a system message in history
    enriched_history = [
        {'role': 'system', 'content': system_context}
    ] + history[-8:]

    try:
        payload = json.dumps({
            'message':    message,
            'history':    enriched_history,
            'session_id': session_id or f'willie-{session["user_id"]}'
        }).encode()
        req = _req.post(
            f'{WIDGET_BASE}/chat/{WILLIE_AGENT_ID}',
            headers={'Content-Type': 'application/json'},
            data=payload, timeout=45
        )
        result = req.json()
        reply  = result.get('reply', 'Aquila is unavailable right now.')
    except Exception as e:
        reply = f'Aquila is unavailable right now. ({str(e)[:80]})'

    # Save to conversation history
    if conv_id:
        conv = db.execute('SELECT * FROM willie_conversations WHERE id=? AND user_id=?',
                          (conv_id, session['user_id'])).fetchone()
        if conv:
            db.execute('INSERT INTO willie_messages (conversation_id,role,content) VALUES (?,?,?)',
                       (conv_id, 'user', message))
            db.execute('INSERT INTO willie_messages (conversation_id,role,content) VALUES (?,?,?)',
                       (conv_id, 'assistant', reply))
            if conv['title'] == 'New Conversation':
                title = message[:60] + ('...' if len(message) > 60 else '')
                db.execute('UPDATE willie_conversations SET title=?,updated=CURRENT_TIMESTAMP WHERE id=?',
                           (title, conv_id))
            else:
                db.execute('UPDATE willie_conversations SET updated=CURRENT_TIMESTAMP WHERE id=?', (conv_id,))
            db.commit()

    return jsonify({'reply': reply})

# ── Aquila External API ──────────────────────────────────────────────────────────────
# All routes accept: Authorization: Bearer <willie_token>
# Get token from: GET /willie/token (admin session required)

# ── Instant AI photo analysis (used by new claim form before submit) ────────────────

@app.route('/api/analyze-photo', methods=['POST'])
@login_required
def api_analyze_photo():
    data     = request.get_json(silent=True) or {}
    img_b64  = data.get('image', '')
    mime     = data.get('mime', 'image/jpeg')
    if not img_b64:
        return jsonify({'error': 'no image'}), 400
    key = get_setting('openrouter_api_key') or OPENROUTER_KEY
    if not key:
        return jsonify({'description': ''})
    try:
        selected_model = get_setting('ai_model', 'openai/gpt-4o-mini')
        r = _req.post(
            'https://openrouter.ai/api/v1/chat/completions',
            headers={'Authorization': f'Bearer {key}', 'Content-Type': 'application/json'},
            json={
                'model': selected_model,
                'messages': [{'role': 'user', 'content': [
                    {'type': 'text', 'text': (
                        'You are a professional flood damage adjuster. Analyze this photo and provide '
                        'a concise 2-3 sentence assessment covering: (1) what is damaged, '
                        '(2) severity and water category if visible, '
                        '(3) immediate repair needs. Be specific and professional.'
                    )},
                    {'type': 'image_url', 'image_url': {'url': f'data:{mime};base64,{img_b64}'}}
                ]}],
                'max_tokens': 200
            }, timeout=30)
        desc = r.json()['choices'][0]['message']['content']
        return jsonify({'description': desc})
    except Exception:
        return jsonify({'description': ''})

@app.route('/willie/token')
@login_required
def willie_token():
    """Show the Willie API token to admin users."""
    if session.get('role') != 'admin':
        return jsonify({'error': 'admin required'}), 403
    return jsonify({'token': get_willie_token(),
                    'base_url': request.host_url.rstrip('/'),
                    'note': 'Use this as Authorization: Bearer <token> in Willie actions'})

@app.route('/willie/api/claims', methods=['GET'])
def willie_list_claims():
    if not willie_auth():
        return jsonify({'error': 'unauthorized'}), 401
    db = get_db()
    claims = db.execute('''
        SELECT c.id, c.claim_number, c.client_name, c.property_address,
               c.flood_date, c.status, c.total_estimate,
               u.name as adjuster_name
        FROM claims c LEFT JOIN users u ON c.adjuster_id=u.id
        ORDER BY c.created_at DESC LIMIT 50
    ''').fetchall()
    return jsonify({'ok': True, 'claims': [dict(c) for c in claims], 'count': len(claims)})

@app.route('/willie/api/claims/lookup', methods=['GET'])
def willie_lookup_claim():
    """Look up a claim by claim_number (e.g. FC-202604-FBA7C7) or partial client name."""
    if not willie_auth():
        return jsonify({'error': 'unauthorized'}), 401
    claim_number = request.args.get('claim_number', '').strip()
    client_name  = request.args.get('client_name', '').strip()
    db = get_db()
    if claim_number:
        claim = db.execute(
            'SELECT c.*, u.name as adjuster_name FROM claims c LEFT JOIN users u ON c.adjuster_id=u.id WHERE c.claim_number=?',
            (claim_number,)).fetchone()
        if not claim:
            return jsonify({'ok': False, 'error': f'No claim found with number {claim_number}'}), 404
        rooms = db.execute('SELECT * FROM rooms WHERE claim_id=? ORDER BY id', (claim['id'],)).fetchall()
        room_data = []
        for r in rooms:
            items = db.execute('SELECT * FROM line_items WHERE room_id=? ORDER BY id', (r['id'],)).fetchall()
            room_data.append({'room': dict(r), 'line_items': [dict(i) for i in items]})
        return jsonify({'ok': True, 'claim': dict(claim), 'rooms': room_data})
    elif client_name:
        claims = db.execute(
            'SELECT id, claim_number, client_name, status, total_estimate FROM claims WHERE client_name LIKE ? ORDER BY created_at DESC',
            (f'%{client_name}%',)).fetchall()
        return jsonify({'ok': True, 'claims': [dict(c) for c in claims], 'count': len(claims)})
    return jsonify({'error': 'Provide claim_number or client_name as query param'}), 400


@app.route('/willie/api/claims/<int:claim_id>/estimate', methods=['POST'])
def willie_generate_estimate(claim_id):
    """Use AI (with photo vision) to generate a full adjuster-style estimate."""
    if not willie_auth():
        return jsonify({'error': 'unauthorized'}), 401
    db = get_db()
    claim = db.execute('SELECT * FROM claims WHERE id=?', (claim_id,)).fetchone()
    if not claim:
        return jsonify({'error': 'Claim not found'}), 404
    claim = dict(claim)  # convert sqlite3.Row → dict so .get() works

    key = get_setting('openrouter_api_key') or OPENROUTER_KEY
    model = get_setting('ai_model') or 'openai/gpt-4o-mini'
    if not key:
        return jsonify({'error': 'OpenRouter API key not configured. Add it in Settings.'}), 400

    # Gather rooms + items
    rooms = db.execute('SELECT * FROM rooms WHERE claim_id=? ORDER BY id', (claim_id,)).fetchall()
    room_summary = []
    for r in rooms:
        items = db.execute('SELECT * FROM line_items WHERE room_id=? ORDER BY id', (r['id'],)).fetchall()
        item_list = '; '.join([f"{i['description']} x{i['quantity']} {i['unit']} @${i['unit_cost']:.2f}" for i in items]) or 'No line items yet'
        room_summary.append(f"  Room: {r['name']}\n  Items: {item_list}")

    # Analyze all photos with vision AI
    photos = [dict(p) for p in db.execute('SELECT * FROM photos WHERE claim_id=? ORDER BY id', (claim_id,)).fetchall()]
    photo_analyses = []
    for photo in photos[:8]:  # limit to 8 photos to avoid token overflow
        photo_path = os.path.join(UPLOAD_DIR, photo['filename'])
        desc = photo.get('ai_description', '') or ''
        # Clear cached error strings so they get retried
        if desc.startswith('AI analysis failed') or desc.startswith('Error'):
            desc = ''
            db.execute('UPDATE photos SET ai_description=NULL WHERE id=?', (photo['id'],))
            db.commit()
        if not desc and os.path.exists(photo_path):
            desc = ai_describe_photo(photo_path)
            if desc:
                db.execute('UPDATE photos SET ai_description=? WHERE id=?', (desc, photo['id']))
                db.commit()
        if desc:
            photo_analyses.append(f"Photo ({photo['caption'] or photo['filename']}): {desc}")

    photo_section = '\n'.join(photo_analyses) if photo_analyses else 'No photos uploaded yet.'
    room_section  = '\n'.join(room_summary) if room_summary else 'No rooms documented yet.'

    PRICING_KNOWLEDGE_BASE = """
=== 2026 FLOOD RESTORATION PRICING REFERENCE (USE THESE RATES) ===

NATIONAL AVERAGES (2026 data — Palm Build, NuBilt, Angi, Xactimate):
- Average water damage claim payout: $10,234–$11,605
- Typical full restoration (mitigation + rebuild): $5,000–$16,000
- Per sq ft mitigation only: $3.00–$7.50/sf
- Per sq ft full rebuild: $20.00–$37.00/sf
- Myrtle Beach / South Carolina local rate: $14–$16/sf (cleanup), $20–$30/sf (rebuild)
- 1 inch of standing floodwater → ~$25,000 in damage to a typical home (FEMA/NFIP data)

WATER CATEGORIES (IICRC):
- Cat 1 (clean water): $3.50/sf mitigation
- Cat 2 (gray water/appliance): $5.25/sf mitigation
- Cat 3 (black water/floodwater/sewage): $7.50/sf mitigation + biohazard uplift
  → Flood water from outside IS always Cat 3

WATER CLASSES:
- Class 1 (partial room, floors only): 24–48h dry-out
- Class 2 (full room, walls <24" wicking): 48–72h dry-out
- Class 3 (ceiling/walls saturated): 72–96h dry-out
- Class 4 (specialty — brick, hardwood, concrete): 120h+ dry-out

MITIGATION LINE ITEMS (Xactimate-based 2024–2026):
- Emergency service call (business hours): $271–$407 EA
- Water extraction / pumping: $0.75–$1.50/sf
- Air mover (per 24h): $38–$55 EA (typically 1 per 50–100 sf)
- Dehumidifier 70–109 ppd (per 24h): $83–$110 EA (typically 1 per 500–1,000 sf)
- Wall cavity drying — injection type (per 24h): $141 EA
- Antimicrobial treatment: $0.35–$0.50/sf
- Moisture mapping report: $250 flat
- Containment barriers: $0.18/sf
- Content manipulation / pack-out: $77/hr
- Debris hauling (dumpster): $350–$600 EA

DEMOLITION / TEAR-OUT:
- Tear out wet drywall Cat 3 (no bagging): $1.79/sf
- Tear out wet insulation (no bagging): $0.91/sf
- Tear out baseboard: $0.66/lf
- Tear out carpet + pad: $1.05–$1.50/sy (or $0.12–$0.17/sf)
- Tear out LVP/vinyl flooring: $1.25–$2.00/sf
- Tear out non-salvageable hardwood (bagged): $5.82/sf
- Tear out ceramic tile + mortar bed: $3.50–$5.00/sf
- Tear out subfloor (OSB/plywood): $2.00–$3.50/sf

DRYWALL REPLACEMENT:
- 1/2" drywall hung, taped, floated, ready for paint: $3.99–$5.50/sf
- Drywall repair (labor only, Myrtle Beach): $40–$60/hr
- Batt insulation 6" R19: $1.40–$2.00/sf
- Seal/prime + 2 coats paint walls: $1.50–$2.50/sf
- Baseboard 4-1/4" R&R: $5.51/lf
- Seal & paint baseboard: $2.75/lf

FLOORING REPLACEMENT:
- Luxury Vinyl Plank (LVP) installed: $4.00–$8.00/sf (mid-grade $5.50)
- Carpet + pad installed: $3.50–$6.50/sf (mid-grade $4.50)
- Hardwood installed (mid-grade): $8.00–$14.00/sf
- Ceramic/porcelain tile installed: $7.00–$12.00/sf
- Subfloor OSB 3/4" R&R: $4.50–$6.00/sf

MOLD REMEDIATION:
- HEPA air scrubber (per 24h): $80–$115 EA
- Antimicrobial application: $0.35–$0.75/sf
- Mold remediation (contained area): $1,200–$3,800 total; $15–$30/sf for large areas
- Encapsulation coating: $1.00–$2.50/sf

ELECTRICAL / MECHANICAL:
- Electrical safety re-inspection after flood: $150–$400
- GFCI outlet R&R: $85–$150 EA
- Electrical outlet/switch R&R (standard): $45–$90 EA

CABINETS / KITCHEN:
- Base cabinet removal & replace (per LF): $175–$350/lf
- Upper cabinet removal & replace (per LF): $125–$250/lf
- Countertop replace (laminate): $25–$40/lf

DOORS / WINDOWS:
- Interior door unit R&R: $401–$550 EA
- Vinyl window single-hung 9–12 sf R&R: $392–$550 EA
- Door frame/jamb R&R: $254–$350 EA

CONTINGENCY & OVERHEAD:
- Standard contingency: 10–15% of subtotal
- Contractor O&P (overhead & profit): 20% on top of labor + materials (standard insurance practice)
- Sales tax on materials: ~8% (SC rate)

AVERAGE TOTAL COSTS BY CLAIM TYPE (2026 insurance data):
- Single room flood (200–400 sf): $8,000–$18,000
- Two-room flood: $15,000–$30,000
- Full first-floor flood (1,000–1,500 sf): $25,000–$60,000
- Basement flood: $10,000–$30,000
- NFIP average payout for flood claims: $66,000 (severe) / $10,234 (moderate)

KEY RULES FOR ADJUSTER ESTIMATES:
1. NEVER estimate below $8,000 for any claim showing visible drywall damage + flooring damage in 2+ photos
2. Flood water from outside = Cat 3 black water ALWAYS — this triggers biohazard protocols and higher rates
3. Any peeling paint/drywall visible in photos = walls need full replacement, not patch repair
4. Rotted/torn flooring visible = full room flooring replacement, not partial
5. Always include mitigation phase (extraction/drying) AND reconstruction phase in estimate
6. Add 10% contingency + 20% O&P to all estimates
7. If mold risk present (damage >48h old), add mold remediation line items
"""

    prompt = f"""You are a licensed public adjuster and flood damage estimator with 20 years of experience.
Analyze this flood damage claim and produce a complete professional estimate like you would submit to an insurance company.

You have access to a current 2026 pricing reference — USE THESE EXACT RATES, do not guess or use outdated numbers:
{PRICING_KNOWLEDGE_BASE}

=== CLAIM DETAILS ===
Claim #: {claim['claim_number']}
Client: {claim['client_name']}
Property: {claim['property_address']}
Flood Date: {claim['flood_date']}
Flood Source: {claim.get('flood_source') or 'Not specified'}
Water Category: {claim.get('water_category') or 'Not specified'}
Water Class: {claim.get('water_class') or 'Not specified'}
Water Depth: {claim.get('water_depth_in') or 'Not specified'} inches
Insurance Co: {claim.get('insurance_company') or 'Not specified'}
FEMA Flood Zone: {claim.get('flood_zone') or 'Not determined'}

=== CURRENT ROOMS & LINE ITEMS ===
{room_section}

Current Total: ${claim['total_estimate']:.2f}

=== PHOTO ANALYSIS ===
{photo_section}

=== YOUR TASK ===
Based on the photos, claim details, and current line items, provide:

1. **PHOTO FINDINGS** — What damage did you observe in each photo? Be specific (water staining, mold, structural damage, flooring damage, etc.). Note water category/class implied by the damage.

2. **COMPLETE LINE-ITEM ESTIMATE** — Using the pricing reference above, list EVERY repair needed — both mitigation phase and reconstruction phase:
   - Description
   - Quantity + Unit (sq ft, ln ft, ea, hr)
   - Unit Cost (from the pricing reference above)
   - Line Total
   Mark items already documented with ✅, missing items with ➕
   Do NOT omit drying equipment, antimicrobial treatment, or debris removal.

3. **ESTIMATE SUMMARY**
   - Subtotal by room
   - Contractor O&P (20%)
   - Sales tax on materials (~8%)
   - 10% contingency
   - GRAND TOTAL (recommended claim amount)

4. **ADJUSTER NOTES** — Red flags, documentation gaps, items insurance will scrutinize, and whether the current estimate of ${claim['total_estimate']:.2f} is adequate.

Be thorough — this goes directly to the insurance company. Low estimates hurt the homeowner."""

    estimate = call_openrouter([{'role': 'user', 'content': prompt}], model, key)
    return jsonify({
        'ok': True,
        'claim_number': claim['claim_number'],
        'client': claim['client_name'],
        'property': claim['property_address'],
        'current_total': claim['total_estimate'],
        'photos_analyzed': len(photo_analyses),
        'estimate': estimate
    })


@app.route('/willie/api/claims', methods=['POST'])
def willie_create_claim():
    if not willie_auth():
        return jsonify({'error': 'unauthorized'}), 401
    data = request.get_json(silent=True) or {}

    # Fill in demo data for any missing fields
    client_name      = data.get('client_name', 'Demo Client').strip() or 'Demo Client'
    client_phone     = data.get('client_phone', '(555) 000-0000')
    client_email     = data.get('client_email', '')
    property_address = data.get('property_address', '123 Flood St, Liberty, NC 27298').strip() or '123 Flood St, Liberty, NC 27298'
    flood_date       = data.get('flood_date', datetime.datetime.now().strftime('%Y-%m-%d'))
    insurance_company= data.get('insurance_company', '')
    policy_number    = data.get('policy_number', '')
    notes            = data.get('notes', '')

    db = get_db()
    # Get first admin user as default adjuster
    adjuster = db.execute("SELECT id FROM users WHERE role='admin' ORDER BY id LIMIT 1").fetchone()
    adjuster_id = adjuster['id'] if adjuster else 1

    claim_num = gen_claim_number()
    db.execute('''INSERT INTO claims
        (claim_number, adjuster_id, client_name, client_phone, client_email,
         property_address, flood_date, insurance_company, policy_number, notes)
        VALUES (?,?,?,?,?,?,?,?,?,?)''',
        (claim_num, adjuster_id, client_name, client_phone, client_email,
         property_address, flood_date, insurance_company, policy_number, notes))
    db.commit()
    claim = db.execute('SELECT * FROM claims WHERE claim_number=?', (claim_num,)).fetchone()
    return jsonify({
        'ok': True,
        'claim_id': claim['id'],
        'claim_number': claim_num,
        'message': f'Claim {claim_num} created for {client_name} at {property_address}',
        'url': f'https://billy-floods.up.railway.app/claims/{claim["id"]}'
    }), 201

@app.route('/willie/api/claims/<int:claim_id>', methods=['GET'])
def willie_get_claim(claim_id):
    if not willie_auth():
        return jsonify({'error': 'unauthorized'}), 401
    db = get_db()
    claim = db.execute('''
        SELECT c.*, u.name as adjuster_name FROM claims c
        LEFT JOIN users u ON c.adjuster_id=u.id WHERE c.id=?
    ''', (claim_id,)).fetchone()
    if not claim:
        return jsonify({'error': 'Claim not found'}), 404
    rooms = db.execute('SELECT * FROM rooms WHERE claim_id=? ORDER BY id', (claim_id,)).fetchall()
    room_data = []
    for r in rooms:
        items = db.execute('SELECT * FROM line_items WHERE room_id=? ORDER BY id', (r['id'],)).fetchall()
        room_data.append({'room': dict(r), 'line_items': [dict(i) for i in items]})
    return jsonify({'ok': True, 'claim': dict(claim), 'rooms': room_data})

@app.route('/willie/api/claims/by-number/<claim_number>', methods=['DELETE'])
def willie_delete_claim_by_number(claim_number):
    """Delete a claim by claim number (e.g. FC-202604-AF52D2) in one step."""
    if not willie_auth():
        return jsonify({'error': 'unauthorized'}), 401
    db = get_db()
    claim = db.execute('SELECT id, client_name, claim_number FROM claims WHERE claim_number=?', (claim_number,)).fetchone()
    if not claim:
        return jsonify({'ok': False, 'error': f'No claim found with number {claim_number}'}), 404
    db.execute('DELETE FROM claims WHERE id=?', (claim['id'],))
    db.commit()
    # Verify it's gone
    check = db.execute('SELECT id FROM claims WHERE id=?', (claim['id'],)).fetchone()
    if check:
        return jsonify({'ok': False, 'error': 'Delete failed — claim still exists'}), 500
    remaining = db.execute('SELECT COUNT(*) as c FROM claims').fetchone()['c']
    return jsonify({'ok': True, 'message': f'Claim {claim_number} ({claim["client_name"]}) permanently deleted. {remaining} claims remaining.', 'deleted_id': claim['id'], 'deleted_client': claim['client_name'], 'remaining_claims': remaining})


@app.route('/willie/api/claims/<int:claim_id>', methods=['DELETE'])
def willie_delete_claim(claim_id):
    if not willie_auth():
        return jsonify({'error': 'unauthorized'}), 401
    db = get_db()
    claim = db.execute('SELECT id, client_name FROM claims WHERE id=?', (claim_id,)).fetchone()
    if not claim:
        return jsonify({'error': 'Claim not found'}), 404
    # CASCADE deletes rooms, line_items, photos automatically
    db.execute('DELETE FROM claims WHERE id=?', (claim_id,))
    db.commit()
    return jsonify({'ok': True, 'message': f'Claim {claim_id} ({claim["client_name"]}) and all records deleted.'})


@app.route('/willie/api/claims/<int:claim_id>/status', methods=['POST'])
def willie_update_status(claim_id):
    if not willie_auth():
        return jsonify({'error': 'unauthorized'}), 401
    data   = request.get_json(silent=True) or {}
    status = data.get('status', '').strip()
    valid  = ['New', 'In Progress', 'Submitted', 'Closed']
    if status not in valid:
        return jsonify({'error': f'status must be one of: {valid}'}), 400
    db = get_db()
    claim = db.execute('SELECT * FROM claims WHERE id=?', (claim_id,)).fetchone()
    db.execute('UPDATE claims SET status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?', (status, claim_id))
    db.commit()
    if claim:
        notify_client_status_change(claim, status)
    return jsonify({'ok': True, 'claim_id': claim_id, 'status': status,
                    'message': f'Claim {claim_id} status updated to {status}'})

@app.route('/willie/api/claims/<int:claim_id>/rooms', methods=['POST'])
def willie_add_room(claim_id):
    if not willie_auth():
        return jsonify({'error': 'unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    name = data.get('room_name', data.get('name', '')).strip()
    if not name:
        return jsonify({'error': 'room_name required'}), 400
    db    = get_db()
    claim = db.execute('SELECT id FROM claims WHERE id=?', (claim_id,)).fetchone()
    if not claim:
        return jsonify({'error': 'Claim not found'}), 404
    cur = db.execute('INSERT INTO rooms (claim_id, name) VALUES (?,?)', (claim_id, name))
    db.commit()
    return jsonify({'ok': True, 'room_id': cur.lastrowid, 'room_name': name,
                    'message': f'Room "{name}" added to claim {claim_id}'})

@app.route('/willie/api/claims/<int:claim_id>/rooms/<int:room_id>/items', methods=['POST'])
def willie_add_item(claim_id, room_id):
    if not willie_auth():
        return jsonify({'error': 'unauthorized'}), 401
    data      = request.get_json(silent=True) or {}
    desc      = data.get('description', '').strip()
    qty       = float(data.get('quantity', 1) or 1)
    unit      = data.get('unit', 'ea')
    unit_cost = float(data.get('unit_cost', 0) or 0)
    total     = qty * unit_cost
    if not desc:
        return jsonify({'error': 'description required'}), 400
    db = get_db()
    db.execute('INSERT INTO line_items (room_id,description,quantity,unit,unit_cost,total) VALUES (?,?,?,?,?,?)',
               (room_id, desc, qty, unit, unit_cost, total))
    db.commit()
    recalc_claim(claim_id)
    return jsonify({'ok': True, 'description': desc, 'total': total,
                    'message': f'Added "{desc}" — {qty} {unit} @ ${unit_cost} = ${total:.2f}'})

@app.route('/willie/api/team', methods=['GET'])
def willie_list_team():
    if not willie_auth():
        return jsonify({'error': 'unauthorized'}), 401
    db    = get_db()
    users = db.execute(
        'SELECT id, name, email, role, created_at, '
        '(SELECT COUNT(*) FROM claims WHERE adjuster_id=users.id) as claim_count '
        'FROM users ORDER BY name'
    ).fetchall()
    return jsonify({'ok': True, 'team': [dict(u) for u in users], 'count': len(users)})

@app.route('/willie/api/team', methods=['POST'])
def willie_add_team_member():
    if not willie_auth():
        return jsonify({'error': 'unauthorized'}), 401
    data  = request.get_json(silent=True) or {}
    name  = data.get('name', '').strip()
    email = data.get('email', '').strip().lower()
    pw    = data.get('password', '').strip()
    role  = data.get('role', 'adjuster').strip().lower()
    if role not in ('admin', 'adjuster'):
        role = 'adjuster'
    if not name:
        return jsonify({'error': 'name is required'}), 400
    if not email:
        return jsonify({'error': 'email is required'}), 400
    if not pw:
        pw = secrets.token_urlsafe(10)
    db = get_db()
    try:
        db.execute('INSERT INTO users (name, email, password, role) VALUES (?,?,?,?)',
                   (name, email, hash_pw(pw), role))
        db.commit()
        user = db.execute('SELECT id, name, email, role FROM users WHERE email=?', (email,)).fetchone()
        return jsonify({
            'ok': True,
            'user_id':  user['id'],
            'name':     user['name'],
            'email':    user['email'],
            'role':     user['role'],
            'password': pw,
            'message':  f'Team member {name} added as {role}. Login: {email} / {pw}'
        }), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': f'Email {email} already exists'}), 409

@app.route('/willie/api/dashboard', methods=['GET'])
def willie_dashboard():
    if not willie_auth():
        return jsonify({'error': 'unauthorized'}), 401
    db = get_db()
    claims = db.execute('SELECT status, total_estimate FROM claims').fetchall()
    stats = {
        'total':       len(claims),
        'new':         sum(1 for c in claims if c['status'] == 'New'),
        'in_progress': sum(1 for c in claims if c['status'] == 'In Progress'),
        'submitted':   sum(1 for c in claims if c['status'] == 'Submitted'),
        'closed':      sum(1 for c in claims if c['status'] == 'Closed'),
        'pipeline_value': sum(c['total_estimate'] for c in claims if c['status'] != 'Closed'),
    }
    recent = db.execute('''
        SELECT c.id, c.claim_number, c.client_name, c.status, c.total_estimate
        FROM claims c ORDER BY c.created_at DESC LIMIT 5
    ''').fetchall()
    return jsonify({'ok': True, 'stats': stats, 'recent_claims': [dict(r) for r in recent]})

@app.route('/willie/api/claims/<int:claim_id>/rooms', methods=['GET'])
def willie_list_rooms(claim_id):
    if not willie_auth(): return jsonify({'error': 'unauthorized'}), 401
    db = get_db()
    claim = db.execute('SELECT id FROM claims WHERE id=?', (claim_id,)).fetchone()
    if not claim: return jsonify({'error': 'Claim not found'}), 404
    rooms = db.execute('SELECT id, name, subtotal FROM rooms WHERE claim_id=? ORDER BY id', (claim_id,)).fetchall()
    rooms_out = []
    for r in rooms:
        items = db.execute('SELECT id, room_id, description, quantity, unit, unit_cost, total FROM line_items WHERE room_id=? ORDER BY id', (r['id'],)).fetchall()
        rooms_out.append({'id': r['id'], 'name': r['name'], 'subtotal': r['subtotal'], 'line_items': [dict(i) for i in items]})
    return jsonify({'ok': True, 'claim_id': claim_id, 'rooms': rooms_out, 'count': len(rooms_out)})


@app.route('/willie/api/claims/<int:claim_id>/rooms/<int:room_id>', methods=['DELETE'])
def willie_delete_room(claim_id, room_id):
    if not willie_auth(): return jsonify({'error': 'unauthorized'}), 401
    db = get_db()
    room = db.execute('SELECT id, name FROM rooms WHERE id=? AND claim_id=?', (room_id, claim_id)).fetchone()
    if not room: return jsonify({'error': 'Room not found'}), 404
    db.execute('DELETE FROM rooms WHERE id=?', (room_id,))
    db.commit()
    return jsonify({'ok': True, 'message': f'Room "{room["name"]}" and all its line items deleted.'})


@app.route('/willie/api/line-items/<int:item_id>', methods=['DELETE'])
def willie_delete_line_item(item_id):
    if not willie_auth(): return jsonify({'error': 'unauthorized'}), 401
    db = get_db()
    item = db.execute('SELECT id, description FROM line_items WHERE id=?', (item_id,)).fetchone()
    if not item: return jsonify({'error': 'Line item not found'}), 404
    db.execute('DELETE FROM line_items WHERE id=?', (item_id,))
    db.commit()
    return jsonify({'ok': True, 'message': f'Line item "{item["description"]}" deleted.'})


@app.route('/willie/api/team/<int:user_id>', methods=['DELETE'])
def willie_delete_team_member(user_id):
    if not willie_auth(): return jsonify({'error': 'unauthorized'}), 401
    db = get_db()
    user = db.execute('SELECT id, name FROM users WHERE id=?', (user_id,)).fetchone()
    if not user: return jsonify({'error': 'Team member not found'}), 404
    db.execute('DELETE FROM users WHERE id=?', (user_id,))
    db.commit()
    return jsonify({'ok': True, 'message': f'Team member "{user["name"]}" deleted.'})


@app.route('/willie/api/claims/<int:claim_id>/report', methods=['GET'])
def willie_get_report(claim_id):
    if not willie_auth(): return jsonify({'error': 'unauthorized'}), 401
    db = get_db()
    claim = db.execute('SELECT * FROM claims WHERE id=?', (claim_id,)).fetchone()
    if not claim: return jsonify({'error': 'Claim not found'}), 404
    rooms = db.execute('SELECT * FROM rooms WHERE claim_id=? ORDER BY id', (claim_id,)).fetchall()
    report = dict(claim)
    report['rooms'] = []
    for r in rooms:
        items = db.execute('SELECT * FROM line_items WHERE room_id=? ORDER BY id', (r['id'],)).fetchall()
        room_data = dict(r)
        room_data['line_items'] = [dict(i) for i in items]
        report['rooms'].append(room_data)
    return jsonify({'ok': True, 'report': report})


@app.route('/willie/api/settings', methods=['GET'])
def willie_get_settings():
    if not willie_auth(): return jsonify({'error': 'unauthorized'}), 401
    db = get_db()
    settings = db.execute('SELECT key, value FROM settings').fetchall()
    return jsonify({'ok': True, 'settings': {s['key']: s['value'] for s in settings}})


@app.route('/willie/api/settings', methods=['POST'])
def willie_update_settings():
    if not willie_auth(): return jsonify({'error': 'unauthorized'}), 401
    data = request.get_json(silent=True) or {}
    db = get_db()
    # Accept both 'ai_model' and legacy 'openrouter_model' alias
    allowed = {'openrouter_api_key', 'ai_model', 'openrouter_model', 'willie_agent_key', 'willie_agent_id'}
    updated = []
    for key, value in data.items():
        if key in allowed:
            store_key = 'ai_model' if key == 'openrouter_model' else key
            db.execute('INSERT INTO settings (key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', (store_key, value))
            updated.append(store_key)
    db.commit()
    return jsonify({'ok': True, 'updated': updated})


@app.route('/willie/fix-identity', methods=['POST'])
@login_required
@admin_required
@csrf_required
def willie_fix_identity():
    """Fix Willie's name/identity in the widget — call after a redeploy."""
    WIDGET_BASE     = 'https://ai-agent-widget-production.up.railway.app'
    WILLIE_AGENT_ID = get_setting('willie_agent_id', 'F5J8yYT6a6GrppjviN6p8w')
    willie_key      = get_setting('willie_agent_key', '')
    if not willie_key:
        flash('Aquila API key not set in Settings yet.', 'error')
        return redirect(url_for('settings'))

    IDENTITY = """# IDENTITY

- Name: Aquila
- Full name: Aquila The Flood Expert
- Role: AI flood damage adjuster assistant inside FloodClaim Pro
- Built by: Alexander AI Integrated Solutions

## Who I am
I am Aquila — NOT Billy, NOT an unnamed assistant. My name is Aquila.
I am an expert flood damage adjuster AI assistant embedded inside FloodClaim Pro.
I have deep knowledge of NFIP rules, flood claim procedures, and 2026 pricing rates.

## What I can do
- Create, view, and update flood damage claims
- Add rooms and damage line items with correct NFIP pricing
- Move claims through the pipeline (New → In Progress → Submitted → Closed)
- Schedule inspections and assign adjusters
- Check NFIP compliance scores
- Look up FEMA flood zones
- Send client notifications via email or SMS
- Run AI estimates on claims
- Analyze damage photos and suggest scope of work
- Answer any question about flood claims, NFIP rules, water categories, and pricing

## My personality
Professional, knowledgeable, helpful, and direct. I give specific answers with real numbers.
I always refer to myself as Aquila."""

    SYSTEM_PROMPT = """You are Aquila, an expert AI flood damage adjuster assistant inside FloodClaim Pro.
Your name is Aquila — always introduce yourself as Aquila, never as Billy or any other name.
You have deep knowledge of NFIP flood insurance rules, water damage categories, 2026 restoration pricing,
and the full FloodClaim Pro platform. You can take direct actions in the app on behalf of adjusters.
Always be professional, specific, and helpful. When you don’t know something, say so honestly."""

    try:
        r = _req.post(
            f'{WIDGET_BASE}/agent/{WILLIE_AGENT_ID}/brain/update',
            json={
                'token':         willie_key,
                'identity_md':   IDENTITY,
                'system_prompt': SYSTEM_PROMPT,
                'name':          'Aquila The Flood Expert',
                'tagline':       'Hi! I am Aquila your flood damage expert. How can I help?',
            },
            timeout=15
        )
        d = r.json()
        if d.get('ok'):
            flash(f'✅ Willie’s identity fixed! Updated: {", ".join(d.get("updated", []))}.', 'success')
        else:
            flash(f'❌ Could not update Willie: {d.get("error", str(d))}', 'error')
    except Exception as e:
        flash(f'❌ Network error: {e}', 'error')
    return redirect(url_for('settings'))


@app.route('/willie/api/actions/sync', methods=['POST'])
def willie_sync_actions():
    """Push all FloodClaim actions to Willie's widget so he can use them correctly.
    Requires willie_agent_key to be set in settings (Willie's own widget API key).
    Auth: Willie token OR admin session."""
    if not session.get('user_id') and not willie_auth():
        return jsonify({'error': 'unauthorized'}), 401

    WIDGET_BASE     = 'https://ai-agent-widget-production.up.railway.app'
    FLOOD_BASE      = 'https://billy-floods.up.railway.app'
    WILLIE_AGENT_ID = get_setting('willie_agent_id', 'F5J8yYT6a6GrppjviN6p8w')
    willie_key      = get_setting('willie_agent_key', '')
    flood_token     = get_willie_token()

    if not willie_key:
        return jsonify({'ok': False,
                        'error': 'aquila_agent_key not set. Go to Settings and paste Aquila\'s widget API key.'}), 400

    # Full correct action definitions — {param} placeholders get substituted by the widget engine
    ACTIONS = [
        {
            'name':        'get_dashboard',
            'description': 'Get FloodClaim Pro dashboard stats: total claims, pipeline value, status breakdown, recent claims.',
            'method':      'GET',
            'url':         f'{FLOOD_BASE}/willie/api/dashboard',
            'headers':     {'Authorization': f'Bearer {flood_token}'},
            'body':        {},
        },
        {
            'name':        'list_claims',
            'description': 'List all flood damage claims. Use this to find a claim ID from a client name or claim number.',
            'method':      'GET',
            'url':         f'{FLOOD_BASE}/willie/api/claims',
            'headers':     {'Authorization': f'Bearer {flood_token}'},
            'body':        {},
        },
        {
            'name':        'lookup_claim',
            'description': 'Look up a specific claim by claim_number (e.g. FC-202604-XXXX) or partial client name. Always do this before adding rooms/items to find the correct claim ID.',
            'method':      'GET',
            'url':         f'{FLOOD_BASE}/willie/api/claims/lookup?claim_number={{claim_number}}',
            'headers':     {'Authorization': f'Bearer {flood_token}'},
            'body':        {},
        },
        {
            'name':        'get_claim',
            'description': 'Get full details of a claim including rooms and line items. Requires numeric claim_id.',
            'method':      'GET',
            'url':         f'{FLOOD_BASE}/willie/api/claims/{{claim_id}}',
            'headers':     {'Authorization': f'Bearer {flood_token}'},
            'body':        {},
        },
        {
            'name':        'create_claim',
            'description': 'Create a new flood damage claim. Requires client_name, property_address, flood_date.',
            'method':      'POST',
            'url':         f'{FLOOD_BASE}/willie/api/claims',
            'headers':     {'Authorization': f'Bearer {flood_token}'},
            'body':        {'client_name': '{client_name}', 'property_address': '{property_address}',
                            'flood_date': '{flood_date}', 'insurance_company': '{insurance_company}'},
        },
        {
            'name':        'update_claim_status',
            'description': 'Update the status of a claim. Status must be one of: New, In Progress, Submitted, Closed.',
            'method':      'POST',
            'url':         f'{FLOOD_BASE}/willie/api/claims/{{claim_id}}/status',
            'headers':     {'Authorization': f'Bearer {flood_token}'},
            'body':        {'status': '{status}'},
        },
        {
            'name':        'add_room',
            'description': 'Add a room to a claim. ALWAYS call lookup_claim first to get the numeric claim_id. Requires claim_id (number) and room_name.',
            'method':      'POST',
            'url':         f'{FLOOD_BASE}/willie/api/claims/{{claim_id}}/rooms',
            'headers':     {'Authorization': f'Bearer {flood_token}'},
            'body':        {'room_name': '{room_name}'},
        },
        {
            'name':        'list_rooms',
            'description': 'List all rooms and line items for a claim. Requires numeric claim_id.',
            'method':      'GET',
            'url':         f'{FLOOD_BASE}/willie/api/claims/{{claim_id}}/rooms',
            'headers':     {'Authorization': f'Bearer {flood_token}'},
            'body':        {},
        },
        {
            'name':        'add_line_item',
            'description': 'Add a line item (damage item) to a room. ALWAYS call list_rooms first to get the numeric room_id. Requires claim_id, room_id, description, quantity, unit, unit_cost.',
            'method':      'POST',
            'url':         f'{FLOOD_BASE}/willie/api/claims/{{claim_id}}/rooms/{{room_id}}/items',
            'headers':     {'Authorization': f'Bearer {flood_token}'},
            'body':        {'description': '{description}', 'quantity': '{quantity}',
                            'unit': '{unit}', 'unit_cost': '{unit_cost}'},
        },
        {
            'name':        'delete_room',
            'description': 'Delete a room and all its line items from a claim.',
            'method':      'DELETE',
            'url':         f'{FLOOD_BASE}/willie/api/claims/{{claim_id}}/rooms/{{room_id}}',
            'headers':     {'Authorization': f'Bearer {flood_token}'},
            'body':        {},
        },
        {
            'name':        'delete_line_item',
            'description': 'Delete a single line item by its numeric item_id.',
            'method':      'DELETE',
            'url':         f'{FLOOD_BASE}/willie/api/line-items/{{item_id}}',
            'headers':     {'Authorization': f'Bearer {flood_token}'},
            'body':        {},
        },
        {
            'name':        'get_report',
            'description': 'Get a full damage report for a claim including all rooms and line items.',
            'method':      'GET',
            'url':         f'{FLOOD_BASE}/willie/api/claims/{{claim_id}}/report',
            'headers':     {'Authorization': f'Bearer {flood_token}'},
            'body':        {},
        },
        {
            'name':        'generate_estimate',
            'description': 'Trigger AI estimate generation for a claim. Returns a job_id to poll for results.',
            'method':      'POST',
            'url':         f'{FLOOD_BASE}/willie/api/claims/{{claim_id}}/estimate',
            'headers':     {'Authorization': f'Bearer {flood_token}'},
            'body':        {},
        },
        {
            'name':        'list_team',
            'description': 'List all adjusters and team members.',
            'method':      'GET',
            'url':         f'{FLOOD_BASE}/willie/api/team',
            'headers':     {'Authorization': f'Bearer {flood_token}'},
            'body':        {},
        },
        {
            'name':        'add_team_member',
            'description': 'Add a new adjuster or team member. Requires name, email, password, role (adjuster or admin).',
            'method':      'POST',
            'url':         f'{FLOOD_BASE}/willie/api/team',
            'headers':     {'Authorization': f'Bearer {flood_token}'},
            'body':        {'name': '{name}', 'email': '{email}',
                            'password': '{password}', 'role': '{role}'},
        },
        {
            'name':        'delete_team_member',
            'description': 'Remove a team member by their numeric user_id.',
            'method':      'DELETE',
            'url':         f'{FLOOD_BASE}/willie/api/team/{{user_id}}',
            'headers':     {'Authorization': f'Bearer {flood_token}'},
            'body':        {},
        },
        {
            'name':        'get_settings',
            'description': 'Get current FloodClaim Pro app settings (AI model, etc.)',
            'method':      'GET',
            'url':         f'{FLOOD_BASE}/willie/api/settings',
            'headers':     {'Authorization': f'Bearer {flood_token}'},
            'body':        {},
        },
        {
            'name':        'schedule_inspection',
            'description': 'Schedule an inspection for a claim. Requires claim_id, date (YYYY-MM-DD), time (HH:MM). Optional: adjuster_id, notes.',
            'method':      'POST',
            'url':         f'{FLOOD_BASE}/willie/api/claims/{{claim_id}}/schedule',
            'headers':     {'Authorization': f'Bearer {flood_token}'},
            'body':        {{'date': '{{date}}', 'time': '{{time}}', 'notes': '{{notes}}'}},
        },
        {
            'name':        'check_compliance',
            'description': 'Check NFIP compliance score for a claim. Returns percent complete, grade, and list of missing items. Use before submitting.',
            'method':      'GET',
            'url':         f'{FLOOD_BASE}/willie/api/claims/{{claim_id}}/compliance',
            'headers':     {'Authorization': f'Bearer {flood_token}'},
            'body':        {{}},
        },
        {
            'name':        'fema_flood_zone_lookup',
            'description': 'Look up the FEMA flood zone for a claim property address. Updates the claim automatically.',
            'method':      'POST',
            'url':         f'{FLOOD_BASE}/willie/api/claims/{{claim_id}}/fema-lookup',
            'headers':     {'Authorization': f'Bearer {flood_token}'},
            'body':        {{}},
        },
        {
            'name':        'notify_client',
            'description': 'Send a notification to the client. Requires claim_id and message. Optional: method (email, sms, both).',
            'method':      'POST',
            'url':         f'{FLOOD_BASE}/willie/api/claims/{{claim_id}}/notify',
            'headers':     {'Authorization': f'Bearer {flood_token}'},
            'body':        {{'message': '{{message}}', 'method': '{{method}}'}},
        },
        {
            'name':        'move_pipeline',
            'description': 'Move a claim to a new pipeline stage. Status must be: New, In Progress, Submitted, or Closed. Also notifies client.',
            'method':      'POST',
            'url':         f'{FLOOD_BASE}/willie/api/claims/{{claim_id}}/move-pipeline',
            'headers':     {'Authorization': f'Bearer {flood_token}'},
            'body':        {{'status': '{{status}}'}},
        },
        {
            'name':        'get_analytics',
            'description': 'Get business analytics: total claims, pipeline value, closed revenue, average cycle time, status breakdown.',
            'method':      'GET',
            'url':         f'{FLOOD_BASE}/willie/api/analytics',
            'headers':     {'Authorization': f'Bearer {flood_token}'},
            'body':        {{}},
        },
        {
            'name':        'get_schedule',
            'description': 'Get all upcoming scheduled inspections from today onward.',
            'method':      'GET',
            'url':         f'{FLOOD_BASE}/willie/api/schedule',
            'headers':     {'Authorization': f'Bearer {flood_token}'},
            'body':        {{}},
        },
        {
            'name':        'analyze_photos',
            'description': 'Run AI vision analysis on all claim photos. Returns water category, damage summary, suggested rooms and line items. Use update_claim to apply the recommendations.',
            'method':      'POST',
            'url':         f'{FLOOD_BASE}/willie/api/claims/{{claim_id}}/analyze',
            'headers':     {'Authorization': f'Bearer {flood_token}'},
            'body':        {{}},
        },
        {
            'name':        'update_claim_fields',
            'description': 'Update multiple fields on a claim at once. Can set water_category, water_class, flood_source, cause_of_loss, notes, priority, coverage_building, coverage_contents, deductible, policy_number, insurance_company, etc.',
            'method':      'POST',
            'url':         f'{FLOOD_BASE}/willie/api/claims/{{claim_id}}/update',
            'headers':     {'Authorization': f'Bearer {flood_token}'},
            'body':        {{'water_category': '{{water_category}}', 'water_class': '{{water_class}}', 'notes': '{{notes}}', 'priority': '{{priority}}'}},
        },
    ]

    pushed = []
    errors = []
    for action in ACTIONS:
        payload = {
            'name':        action['name'],
            'description': action['description'],
            'method':      action['method'],
            'url':         action['url'],
            'headers':     action['headers'],
            'body':        action['body'],
        }
        try:
            r = _req.post(
                f'{WIDGET_BASE}/agent/{WILLIE_AGENT_ID}/actions/api',
                headers={'Authorization': f'Bearer {willie_key}',
                         'Content-Type': 'application/json'},
                json=payload, timeout=15)
            d = r.json()
            if d.get('ok'):
                pushed.append(action['name'])
            else:
                errors.append({'action': action['name'], 'error': d.get('error', str(d))})
        except Exception as e:
            errors.append({'action': action['name'], 'error': str(e)})

    return jsonify({
        'ok':     len(errors) == 0,
        'pushed': pushed,
        'errors': errors,
        'total':  len(ACTIONS),
        'message': f'{len(pushed)}/{len(ACTIONS)} actions synced to Willie'
    })


@app.route('/willie/api/claims/<int:claim_id>/update', methods=['POST'])
@app.route('/willie/api/claims/<int:claim_id>', methods=['PATCH'])
def willie_update_claim(claim_id):
    """Update any field(s) on a claim. Accepts a JSON body with any claim columns.
    Willie uses this to fill in form fields after analyzing photos or reviewing the claim."""
    if not willie_auth(): return jsonify({'error': 'unauthorized'}), 401
    db = get_db()
    claim = db.execute('SELECT * FROM claims WHERE id=?', (claim_id,)).fetchone()
    if not claim: return jsonify({'error': 'Claim not found'}), 404

    data = request.get_json(silent=True) or {}

    # Allowed fields Willie can update
    UPDATABLE = {
        'client_name', 'client_phone', 'client_phone_alt', 'client_email',
        'property_address', 'property_type', 'property_sqft', 'year_built',
        'num_floors', 'flood_date', 'flood_source', 'water_category', 'water_class',
        'water_depth_in', 'date_water_removed', 'inspection_date',
        'insurance_company', 'policy_number', 'policy_type',
        'coverage_building', 'coverage_contents', 'deductible',
        'mortgage_company', 'mortgage_loan_number', 'cause_of_loss',
        'priority', 'notes',
    }

    updates = {k: v for k, v in data.items() if k in UPDATABLE}
    if not updates:
        return jsonify({'error': 'No valid fields provided. Updatable fields: ' + ', '.join(sorted(UPDATABLE))}), 400

    set_clause = ', '.join(f'{k}=?' for k in updates)
    values     = list(updates.values()) + [claim_id]
    db.execute(f'UPDATE claims SET {set_clause}, updated_at=CURRENT_TIMESTAMP WHERE id=?', values)
    db.commit()

    updated_claim = dict(db.execute('SELECT * FROM claims WHERE id=?', (claim_id,)).fetchone())
    return jsonify({
        'ok':      True,
        'updated': list(updates.keys()),
        'message': f'Updated {len(updates)} field(s) on claim {claim["claim_number"]}',
        'claim':   {k: updated_claim.get(k) for k in updates},
    })


# ── Willie: Schedule Inspection ────────────────────────────────────────────────
@app.route('/willie/api/claims/<int:claim_id>/schedule', methods=['POST'])
def willie_schedule_inspection(claim_id):
    if not willie_auth(): return jsonify({'error': 'unauthorized'}), 401
    db    = get_db()
    claim = db.execute('SELECT * FROM claims WHERE id=?', (claim_id,)).fetchone()
    if not claim: return jsonify({'error': 'Claim not found'}), 404
    data      = request.get_json(silent=True) or {}
    slot_date = data.get('date', '').strip()
    slot_time = data.get('time', '09:00').strip()
    adj_id    = data.get('adjuster_id') or claim['adjuster_id']
    notes     = data.get('notes', '').strip()
    if not slot_date:
        return jsonify({'error': 'date is required (YYYY-MM-DD)'}), 400
    db.execute(
        'INSERT INTO inspection_slots (claim_id, adjuster_id, slot_date, slot_time, notes) VALUES (?,?,?,?,?)',
        (claim_id, adj_id, slot_date, slot_time, notes)
    )
    db.execute('UPDATE claims SET sched_date=?, sched_time=?, inspection_date=?, updated_at=CURRENT_TIMESTAMP WHERE id=?',
               (slot_date, slot_time, slot_date, claim_id))
    db.commit()
    _log_activity(claim_id, f'Inspection scheduled for {slot_date} at {slot_time} (by Aquila)', 'Aquila')
    return jsonify({'ok': True, 'claim_id': claim_id, 'date': slot_date, 'time': slot_time,
                    'message': f'Inspection scheduled for {claim["claim_number"]} on {slot_date} at {slot_time}'})


# ── Willie: Compliance Score ────────────────────────────────────────────────
@app.route('/willie/api/claims/<int:claim_id>/compliance', methods=['GET'])
def willie_compliance_check(claim_id):
    if not willie_auth(): return jsonify({'error': 'unauthorized'}), 401
    db    = get_db()
    claim = db.execute('SELECT * FROM claims WHERE id=?', (claim_id,)).fetchone()
    if not claim: return jsonify({'error': 'Claim not found'}), 404
    rooms  = db.execute('SELECT id FROM rooms WHERE claim_id=?', (claim_id,)).fetchall()
    photos = db.execute('SELECT id FROM photos WHERE claim_id=?', (claim_id,)).fetchall()
    checks = {
        'policy_number':     bool(claim['policy_number']),
        'policy_type':       bool(claim['policy_type']),
        'coverage_building': bool(claim['coverage_building']),
        'coverage_contents': bool(claim['coverage_contents']),
        'deductible':        bool(claim['deductible']),
        'flood_date':        bool(claim['flood_date']),
        'flood_source':      bool(claim['flood_source']),
        'water_category':    bool(claim['water_category']),
        'water_class':       bool(claim['water_class']),
        'water_depth':       bool(claim['water_depth_in']),
        'date_water_removed':bool(claim['date_water_removed']),
        'inspection_date':   bool(claim['inspection_date']),
        'flood_zone':        bool(claim['flood_zone'] and claim['flood_zone'] != 'Unknown'),
        'fema_map':          bool(claim['fema_map_number']),
        'photos_3plus':      len(photos) >= 3,
        'rooms_documented':  len(rooms) >= 1,
        'estimate_done':     bool(claim['total_estimate']),
    }
    score   = sum(1 for v in checks.values() if v)
    total   = len(checks)
    pct     = round(score / total * 100)
    missing = [k for k, v in checks.items() if not v]
    grade   = 'Excellent' if pct >= 90 else 'Good' if pct >= 75 else 'Needs Work' if pct >= 50 else 'Incomplete'
    # 60-day deadline
    deadline = None
    if claim['flood_date']:
        try:
            dl = datetime.datetime.strptime(claim['flood_date'], '%Y-%m-%d') + datetime.timedelta(days=60)
            deadline = dl.strftime('%B %d, %Y')
        except Exception:
            pass
    return jsonify({'ok': True, 'claim_id': claim_id, 'claim_number': claim['claim_number'],
                    'score': score, 'total': total, 'percent': pct, 'grade': grade,
                    'missing': missing, 'proof_of_loss_deadline': deadline,
                    'message': f'{claim["claim_number"]} is {pct}% complete ({grade}). Missing: {missing if missing else "nothing"}'})


# ── Willie: FEMA Lookup ────────────────────────────────────────────────────
@app.route('/willie/api/claims/<int:claim_id>/fema-lookup', methods=['POST'])
def willie_fema_lookup(claim_id):
    if not willie_auth(): return jsonify({'error': 'unauthorized'}), 401
    db    = get_db()
    claim = db.execute('SELECT * FROM claims WHERE id=?', (claim_id,)).fetchone()
    if not claim: return jsonify({'error': 'Claim not found'}), 404
    result = lookup_fema_flood_zone(claim['property_address'])
    if result and result.get('flood_zone'):
        db.execute('''
            UPDATE claims SET flood_zone=?, fema_map_number=?, lat=?, lng=?,
            maps_embed_url=?, updated_at=CURRENT_TIMESTAMP WHERE id=?
        ''', (result['flood_zone'], result.get('fema_map_number',''),
              result.get('lat',0), result.get('lng',0), result.get('maps_embed_url',''), claim_id))
        db.commit()
        _log_activity(claim_id, f'FEMA flood zone looked up: Zone {result["flood_zone"]} (by Aquila)', 'Aquila')
        return jsonify({'ok': True, 'flood_zone': result['flood_zone'],
                        'fema_map_number': result.get('fema_map_number'),
                        'message': f'FEMA lookup complete. Zone: {result["flood_zone"]}, Map Panel: {result.get("fema_map_number","N/A")}'})
    return jsonify({'ok': False, 'error': 'Could not determine flood zone for this address'})


# ── Willie: Send Notification ────────────────────────────────────────────────
@app.route('/willie/api/claims/<int:claim_id>/notify', methods=['POST'])
def willie_notify_client(claim_id):
    if not willie_auth(): return jsonify({'error': 'unauthorized'}), 401
    db    = get_db()
    claim = db.execute('SELECT * FROM claims WHERE id=?', (claim_id,)).fetchone()
    if not claim: return jsonify({'error': 'Claim not found'}), 404
    data    = request.get_json(silent=True) or {}
    message = data.get('message', '').strip()
    method  = data.get('method', 'email').lower()  # email or sms
    if not message:
        return jsonify({'error': 'message is required'}), 400
    sent_email = sent_sms_flag = False
    if method in ('email', 'both') and claim['client_email']:
        subject = f'Update on your FloodClaim — {claim["claim_number"]}'
        html = f'<div style="font-family:sans-serif"><h2>FloodClaim Pro Update</h2><p>Hello {claim["client_name"]},</p><p>{message}</p><hr><small>Claim: {claim["claim_number"]}</small></div>'
        sent_email = send_email(claim['client_email'], subject, html)
        if sent_email:
            _log_notification(claim_id, 'manual', claim['client_email'], message)
    if method in ('sms', 'both'):
        sent_sms_flag = notify_client_sms(claim, f'FloodClaim Pro | {claim["claim_number"]}: {message}')
    result = []
    if sent_email: result.append('email')
    if sent_sms_flag: result.append('SMS')
    if not result:
        return jsonify({'ok': False, 'message': 'Notification not sent — check SendGrid/Twilio config in Settings'})
    _log_activity(claim_id, f'Notification sent via {" and ".join(result)} (by Aquila)', 'Aquila')
    return jsonify({'ok': True, 'sent_via': result,
                    'message': f'Notification sent to {claim["client_name"]} via {" and ".join(result)}'})


# ── Willie: Move Pipeline Status ────────────────────────────────────────────────
@app.route('/willie/api/claims/<int:claim_id>/move-pipeline', methods=['POST'])
def willie_move_pipeline(claim_id):
    if not willie_auth(): return jsonify({'error': 'unauthorized'}), 401
    data   = request.get_json(silent=True) or {}
    status = data.get('status', '').strip()
    valid  = ['New', 'In Progress', 'Submitted', 'Closed']
    if status not in valid:
        return jsonify({'error': f'status must be one of {valid}'}), 400
    db    = get_db()
    claim = db.execute('SELECT * FROM claims WHERE id=?', (claim_id,)).fetchone()
    if not claim: return jsonify({'error': 'Claim not found'}), 404
    old_status = claim['status']
    db.execute('UPDATE claims SET status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?', (status, claim_id))
    db.commit()
    if old_status != status:
        notify_client_status_change(claim, status)
        _log_activity(claim_id, f'Moved from {old_status} → {status} (by Aquila)', 'Aquila')
    return jsonify({'ok': True, 'old_status': old_status, 'new_status': status,
                    'message': f'{claim["claim_number"]} moved from {old_status} to {status}'})


# ── Willie: Analytics Summary ────────────────────────────────────────────────
@app.route('/willie/api/analytics', methods=['GET'])
def willie_analytics():
    if not willie_auth(): return jsonify({'error': 'unauthorized'}), 401
    db     = get_db()
    claims = db.execute('SELECT * FROM claims ORDER BY created_at ASC').fetchall()
    closed = [c for c in claims if c['status'] == 'Closed']
    open_c = [c for c in claims if c['status'] != 'Closed']
    cycle_times = []
    for c in closed:
        try:
            s = datetime.datetime.fromisoformat(c['created_at'])
            e = datetime.datetime.fromisoformat(c['updated_at'])
            diff = (e - s).days
            if diff >= 0: cycle_times.append(diff)
        except Exception:
            pass
    avg_cycle = round(sum(cycle_times)/len(cycle_times), 1) if cycle_times else None
    return jsonify({'ok': True,
                    'total_claims':    len(claims),
                    'open_pipeline':   sum(c['total_estimate'] for c in open_c),
                    'closed_revenue':  sum(c['total_estimate'] for c in closed),
                    'avg_cycle_days':  avg_cycle,
                    'new':             sum(1 for c in claims if c['status'] == 'New'),
                    'in_progress':     sum(1 for c in claims if c['status'] == 'In Progress'),
                    'submitted':       sum(1 for c in claims if c['status'] == 'Submitted'),
                    'closed':          len(closed),
                    'message': f'{len(claims)} total claims. Pipeline: ${sum(c["total_estimate"] for c in open_c):,.2f}. Avg cycle: {avg_cycle} days.'})


# ── Willie: Get Upcoming Schedule ───────────────────────────────────────────────
@app.route('/willie/api/schedule', methods=['GET'])
def willie_get_schedule():
    if not willie_auth(): return jsonify({'error': 'unauthorized'}), 401
    db    = get_db()
    today = datetime.date.today().isoformat()
    slots = db.execute('''
        SELECT s.*, c.claim_number, c.client_name, c.property_address, u.name as adjuster_name
        FROM inspection_slots s
        JOIN claims c ON s.claim_id=c.id
        LEFT JOIN users u ON s.adjuster_id=u.id
        WHERE s.slot_date >= ? AND s.status != 'cancelled'
        ORDER BY s.slot_date, s.slot_time LIMIT 20
    ''', (today,)).fetchall()
    return jsonify({'ok': True, 'today': today, 'upcoming': [dict(s) for s in slots],
                    'count': len(slots),
                    'message': f'{len(slots)} upcoming inspection(s) from today onward'})


@app.route('/willie/api/claims/<int:claim_id>/analyze', methods=['POST'])
def willie_analyze_claim(claim_id):
    """Run vision AI on all claim photos and return structured field recommendations.
    Willie uses this to fill in water_category, water_class, flood_source, damage description,
    and suggested rooms/line items based purely on what the photos show."""
    if not willie_auth(): return jsonify({'error': 'unauthorized'}), 401
    db  = get_db()
    claim = db.execute('SELECT * FROM claims WHERE id=?', (claim_id,)).fetchone()
    if not claim: return jsonify({'error': 'Claim not found'}), 404
    claim = dict(claim)

    key   = get_setting('openrouter_api_key') or OPENROUTER_KEY
    model = get_setting('ai_model') or 'openai/gpt-4o-mini'
    if not key:
        return jsonify({'error': 'OpenRouter API key not configured'}), 400

    photos = [dict(p) for p in db.execute(
        'SELECT * FROM photos WHERE claim_id=? ORDER BY id', (claim_id,)).fetchall()]

    if not photos:
        return jsonify({'ok': False, 'error': 'No photos on this claim yet. Upload photos first so I can analyze them.'}), 400

    # Run fresh vision analysis on all photos (up to 8)
    photo_analyses = []
    for photo in photos[:8]:
        photo_path = os.path.join(UPLOAD_DIR, photo['filename'])
        if not os.path.exists(photo_path):
            continue
        # Always re-run for analyze endpoint — we want fresh detailed descriptions
        desc = ai_describe_photo_detailed(photo_path, key, model)
        if desc:
            label = photo.get('caption') or photo['filename']
            photo_analyses.append({'label': label, 'description': desc, 'photo_id': photo['id']})
            db.execute('UPDATE photos SET ai_description=? WHERE id=?', (desc, photo['id']))
    db.commit()

    if not photo_analyses:
        return jsonify({'ok': False, 'error': 'Could not analyze photos. Check your OpenRouter API key in Settings.'}), 400

    # Build structured analysis prompt
    photos_text = '\n'.join(f'Photo [{p["label"]}]: {p["description"]}' for p in photo_analyses)

    analysis_prompt = f"""You are a licensed flood damage adjuster analyzing photos of a flood-damaged property.

Claim: {claim['claim_number']} | Client: {claim['client_name']} | Address: {claim['property_address']}
Flood Date: {claim['flood_date']}

PHOTO ANALYSES:
{photos_text}

Based ONLY on what you can see in these photos, provide a structured JSON response with your assessment.
Return ONLY valid JSON, no other text:

{{
  "water_category": "1, 2, or 3 (3=floodwater/black water, 2=gray water, 1=clean)",
  "water_class": "1, 2, 3, or 4 (4=hardwood/brick/specialty, 3=ceiling saturated, 2=full room walls, 1=floors only)",
  "flood_source": "brief description of flood source visible in photos",
  "water_depth_in": "estimated water depth in inches based on water lines visible, or empty string",
  "cause_of_loss": "what caused the damage (e.g. Storm surge, Pipe burst, Roof leak, Rising floodwater)",
  "property_type": "Single Family, Condo, Commercial, Mobile Home, or empty",
  "damage_summary": "2-3 sentence professional summary of all damage visible across all photos",
  "suggested_rooms": [
    {{
      "name": "room name",
      "damage_notes": "what needs to be done in this room",
      "line_items": [
        {{"description": "work item", "quantity": number, "unit": "sf/lf/ea", "unit_cost": dollar_amount}}
      ]
    }}
  ],
  "recommended_field_updates": {{
    "water_category": "value",
    "water_class": "value",
    "flood_source": "value",
    "water_depth_in": "value or empty",
    "cause_of_loss": "value",
    "notes": "professional damage summary for claim notes"
  }}
}}"""

    raw = call_openrouter([{'role': 'user', 'content': analysis_prompt}], model, key, max_tokens=2000)

    # Parse JSON from response
    import re as _re
    json_match = _re.search(r'\{[\s\S]+\}', raw)
    if not json_match:
        return jsonify({'ok': False, 'error': 'AI returned non-JSON response', 'raw': raw[:300]}), 500

    try:
        analysis = json.loads(json_match.group(0))
    except Exception:
        return jsonify({'ok': False, 'error': 'Could not parse AI response as JSON', 'raw': raw[:300]}), 500

    return jsonify({
        'ok':             True,
        'claim_id':       claim_id,
        'claim_number':   claim['claim_number'],
        'photos_analyzed': len(photo_analyses),
        'analysis':       analysis,
        'message':        f'Analyzed {len(photo_analyses)} photo(s). Use update_claim_fields to apply the recommendations.',
    })


def ai_describe_photo_detailed(image_path, key, model):
    """Run vision AI on a photo with a detailed damage-focused prompt."""
    try:
        with open(image_path, 'rb') as f:
            img_b64 = base64.b64encode(f.read()).decode()
        ext  = image_path.rsplit('.', 1)[-1].lower()
        mime = f'image/{ext}' if ext != 'jpg' else 'image/jpeg'
        r = _req.post(
            'https://openrouter.ai/api/v1/chat/completions',
            headers={'Authorization': f'Bearer {key}', 'Content-Type': 'application/json'},
            json={
                'model': model,
                'messages': [{
                    'role': 'user',
                    'content': [
                        {'type': 'text', 'text': (
                            'You are a flood damage assessor. Describe ALL visible damage in this photo in detail. '
                            'Include: what materials are damaged (drywall, flooring, ceiling, cabinets, etc.), '
                            'the severity (minor/moderate/severe), visible water lines or staining, '
                            'mold or mildew presence, structural concerns, and estimated affected square footage. '
                            'Be specific and professional. 3-5 sentences.'
                        )},
                        {'type': 'image_url', 'image_url': {'url': f'data:{mime};base64,{img_b64}'}}
                    ]
                }],
                'max_tokens': 300
            }, timeout=30)
        return r.json()['choices'][0]['message']['content']
    except Exception:
        return ''


# ─────────────────────────────────────────────────────────────────────────────
# CLAIM DUPLICATE
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/claims/<int:claim_id>/duplicate', methods=['POST'])
@login_required
@csrf_required
def duplicate_claim(claim_id):
    db    = get_db()
    src   = db.execute('SELECT * FROM claims WHERE id=?', (claim_id,)).fetchone()
    if not src:
        flash('Claim not found.', 'error')
        return redirect(url_for('dashboard'))
    new_num = gen_claim_number()
    db.execute('''
        INSERT INTO claims
          (claim_number, adjuster_id, client_name, client_phone, client_phone_alt, client_email,
           property_address, property_type, property_sqft, year_built, num_floors,
           flood_date, flood_source, water_category, water_class, water_depth_in,
           date_water_removed, inspection_date, insurance_company, policy_number, policy_type,
           coverage_building, coverage_contents, deductible, mortgage_company, mortgage_loan_number,
           cause_of_loss, priority, notes, flood_zone, fema_map_number)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    ''', (new_num, src['adjuster_id'], src['client_name'], src['client_phone'],
          src['client_phone_alt'], src['client_email'], src['property_address'],
          src['property_type'], src['property_sqft'], src['year_built'], src['num_floors'],
          src['flood_date'], src['flood_source'], src['water_category'], src['water_class'],
          src['water_depth_in'], src['date_water_removed'], src['inspection_date'],
          src['insurance_company'], src['policy_number'], src['policy_type'],
          src['coverage_building'], src['coverage_contents'], src['deductible'],
          src['mortgage_company'], src['mortgage_loan_number'],
          src['cause_of_loss'], src['priority'],
          f'[Duplicated from {src["claim_number"]}] {src["notes"]}',
          src['flood_zone'], src['fema_map_number']))
    db.commit()
    new_claim = db.execute('SELECT id FROM claims WHERE claim_number=?', (new_num,)).fetchone()
    # Copy rooms + line items (not photos)
    rooms = db.execute('SELECT * FROM rooms WHERE claim_id=?', (claim_id,)).fetchall()
    for room in rooms:
        db.execute('INSERT INTO rooms (claim_id, name, description) VALUES (?,?,?)',
                   (new_claim['id'], room['name'], room['description']))
        db.commit()
        new_room = db.execute('SELECT id FROM rooms WHERE claim_id=? ORDER BY id DESC LIMIT 1',
                              (new_claim['id'],)).fetchone()
        items = db.execute('SELECT * FROM line_items WHERE room_id=?', (room['id'],)).fetchall()
        for item in items:
            db.execute('INSERT INTO line_items (room_id, description, quantity, unit, unit_cost, total) VALUES (?,?,?,?,?,?)',
                       (new_room['id'], item['description'], item['quantity'], item['unit'], item['unit_cost'], item['total']))
    db.commit()
    recalc_claim(new_claim['id'])
    _log_activity(new_claim['id'], 'Claim duplicated from ' + src['claim_number'])
    flash(f'Claim duplicated as {new_num}.', 'success')
    return redirect(url_for('claim_detail', claim_id=new_claim['id']))


# ─────────────────────────────────────────────────────────────────────────────
# ACTIVITY / AUDIT LOG
# ─────────────────────────────────────────────────────────────────────────────

def _log_activity(claim_id, action, user_name=None):
    """Write an entry to the claim activity log."""
    try:
        db   = get_db()
        who  = user_name or session.get('name', 'System')
        db.execute(
            'INSERT INTO activity_log (claim_id, actor, action) VALUES (?,?,?)',
            (claim_id, who, action)
        )
        db.commit()
    except Exception as e:
        print(f'_log_activity error: {e}')


@app.route('/claims/<int:claim_id>/activity')
@login_required
def claim_activity(claim_id):
    db    = get_db()
    claim = db.execute('SELECT * FROM claims WHERE id=?', (claim_id,)).fetchone()
    if not claim:
        flash('Claim not found.', 'error')
        return redirect(url_for('dashboard'))
    logs = db.execute(
        'SELECT * FROM activity_log WHERE claim_id=? ORDER BY created_at DESC LIMIT 100',
        (claim_id,)
    ).fetchall()
    return render_template('activity.html', claim=claim, logs=logs)


# ─────────────────────────────────────────────────────────────────────────────
# SMS VIA TWILIO
# ─────────────────────────────────────────────────────────────────────────────

def send_sms(to_number, body):
    """Send SMS via Twilio. Returns True on success."""
    sid   = get_setting('twilio_account_sid')  or os.environ.get('TWILIO_ACCOUNT_SID', '')
    token = get_setting('twilio_auth_token')   or os.environ.get('TWILIO_AUTH_TOKEN', '')
    from_ = get_setting('twilio_from_number')  or os.environ.get('TWILIO_FROM_NUMBER', '')
    if not sid or not token or not from_:
        print(f'[SMS] Twilio not configured. To: {to_number} | {body}')
        return False
    try:
        r = _req.post(
            f'https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json',
            auth=(sid, token),
            data={'From': from_, 'To': to_number, 'Body': body},
            timeout=10
        )
        return r.status_code in (200, 201)
    except Exception as e:
        print(f'Twilio error: {e}')
        return False


def notify_client_sms(claim, message):
    """Send SMS to client if they have a phone number."""
    phone = claim['client_phone'] or claim['client_phone_alt'] or ''
    if not phone:
        return False
    # Normalize to E.164 (basic: strip non-digits, add +1 for US)
    digits = ''.join(c for c in phone if c.isdigit())
    if len(digits) == 10:
        digits = '1' + digits
    if not digits.startswith('1') or len(digits) != 11:
        return False
    e164 = '+' + digits
    sent = send_sms(e164, message)
    if sent:
        _log_notification(claim['id'], 'sms', e164, message)
    return sent


@app.route('/claims/<int:claim_id>/sms', methods=['POST'])
@login_required
@csrf_required
def send_claim_sms(claim_id):
    """Manually send an SMS update to the claim client."""
    db    = get_db()
    claim = db.execute('SELECT * FROM claims WHERE id=?', (claim_id,)).fetchone()
    if not claim:
        return jsonify({'ok': False, 'error': 'Claim not found'}), 404
    msg = request.form.get('message', '').strip()
    if not msg:
        return jsonify({'ok': False, 'error': 'Message required'}), 400
    full_msg = f'FloodClaim Pro | {claim["claim_number"]}: {msg}'
    sent = notify_client_sms(claim, full_msg)
    if sent:
        flash(f'SMS sent to {claim["client_phone"]}.', 'success')
    else:
        flash('SMS not sent — configure Twilio in Settings.', 'error')
    return redirect(url_for('claim_detail', claim_id=claim_id))


# ─────────────────────────────────────────────────────────────────────────────
# MOBILE PHOTO UPLOAD (QR code portal)
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/claims/<int:claim_id>/mobile-upload')
def mobile_upload_page(claim_id):
    """Public mobile upload page — no login, accessed via QR code."""
    token = request.args.get('t', '')
    db    = get_db()
    # Validate token matches claim
    row = db.execute(
        'SELECT claim_id FROM client_portal_tokens WHERE token=? AND claim_id=?',
        (token, claim_id)
    ).fetchone()
    if not row:
        return '<h2 style="font-family:sans-serif;text-align:center;margin-top:4rem">Link expired or invalid.</h2>', 403
    claim = db.execute('SELECT * FROM claims WHERE id=?', (claim_id,)).fetchone()
    rooms = db.execute('SELECT * FROM rooms WHERE claim_id=? ORDER BY id', (claim_id,)).fetchall()
    return render_template('mobile_upload.html', claim=claim, rooms=rooms, token=token)


@app.route('/claims/<int:claim_id>/mobile-upload', methods=['POST'])
def mobile_upload_post(claim_id):
    """Accept photo uploads from mobile upload page."""
    token = request.args.get('t', '')
    db    = get_db()
    row = db.execute(
        'SELECT claim_id FROM client_portal_tokens WHERE token=? AND claim_id=?',
        (token, claim_id)
    ).fetchone()
    if not row:
        return jsonify({'ok': False, 'error': 'Invalid token'}), 403
    files   = request.files.getlist('photos')
    room_id = request.form.get('room_id') or None
    caption = request.form.get('caption', 'Mobile upload')
    saved   = 0
    for f in files:
        if f and allowed_file(f.filename):
            ext      = f.filename.rsplit('.', 1)[1].lower()
            filename = f'{secrets.token_hex(12)}.{ext}'
            path     = os.path.join(UPLOAD_DIR, filename)
            f.save(path)
            ai_desc = ai_describe_photo(path)
            db.execute(
                'INSERT INTO photos (claim_id, room_id, filename, caption, ai_description) VALUES (?,?,?,?,?)',
                (claim_id, room_id, filename, caption, ai_desc)
            )
            saved += 1
    db.commit()
    return jsonify({'ok': True, 'saved': saved})


@app.route('/claims/<int:claim_id>/qr')
@login_required
def claim_qr(claim_id):
    """Show a QR code for mobile photo upload — generates/reuses the portal token."""
    db    = get_db()
    claim = db.execute('SELECT * FROM claims WHERE id=?', (claim_id,)).fetchone()
    if not claim:
        flash('Claim not found.', 'error')
        return redirect(url_for('dashboard'))
    # Reuse or create portal token
    row = db.execute('SELECT token FROM client_portal_tokens WHERE claim_id=?', (claim_id,)).fetchone()
    if row:
        token = row['token']
    else:
        token = secrets.token_urlsafe(32)
        db.execute('INSERT INTO client_portal_tokens (claim_id, token) VALUES (?,?)', (claim_id, token))
        db.commit()
    upload_url = url_for('mobile_upload_page', claim_id=claim_id, t=token, _external=True)
    # Generate QR as SVG using a simple URL-based QR service (no lib needed)
    qr_img_url = f'https://api.qrserver.com/v1/create-qr-code/?size=250x250&data={upload_url}'
    return render_template('qr_upload.html', claim=claim, upload_url=upload_url, qr_img_url=qr_img_url)


# ─────────────────────────────────────────────────────────────────────────────
# BULK ACTIONS + DASHBOARD SEARCH
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/claims/bulk', methods=['POST'])
@login_required
@csrf_required
def bulk_action():
    action   = request.form.get('bulk_action', '')
    ids_raw  = request.form.getlist('claim_ids')
    ids      = [int(i) for i in ids_raw if i.isdigit()]
    if not ids:
        flash('No claims selected.', 'error')
        return redirect(url_for('dashboard'))
    db = get_db()
    if action == 'delete':
        for cid in ids:
            photos = db.execute('SELECT filename FROM photos WHERE claim_id=?', (cid,)).fetchall()
            for p in photos:
                try:
                    path = os.path.join(UPLOAD_DIR, p['filename'])
                    if os.path.exists(path): os.remove(path)
                except Exception: pass
            db.execute('DELETE FROM claims WHERE id=?', (cid,))
        db.commit()
        flash(f'Deleted {len(ids)} claim(s).', 'success')
    elif action in ('set_new', 'set_in_progress', 'set_submitted', 'set_closed'):
        status_map = {'set_new': 'New', 'set_in_progress': 'In Progress',
                      'set_submitted': 'Submitted', 'set_closed': 'Closed'}
        new_status = status_map[action]
        for cid in ids:
            claim = db.execute('SELECT * FROM claims WHERE id=?', (cid,)).fetchone()
            db.execute('UPDATE claims SET status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?',
                       (new_status, cid))
            if claim and claim['client_email']:
                notify_client_status_change(claim, new_status)
        db.commit()
        flash(f'Updated {len(ids)} claim(s) to “{new_status}”.', 'success')
    elif action == 'assign':
        adj_id = request.form.get('assign_adjuster')
        if adj_id:
            for cid in ids:
                db.execute('UPDATE claims SET adjuster_id=?, updated_at=CURRENT_TIMESTAMP WHERE id=?',
                           (adj_id, cid))
            db.commit()
            flash(f'Assigned {len(ids)} claim(s).', 'success')
    else:
        flash('Unknown action.', 'error')
    return redirect(url_for('dashboard'))


# ─────────────────────────────────────────────────────────────────────────────
# WEEKLY SUMMARY REPORT (email)
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/admin/weekly-report', methods=['POST'])
@login_required
@admin_required
@csrf_required
def send_weekly_report():
    db     = get_db()
    claims = db.execute('SELECT * FROM claims').fetchall()
    week_ago = (datetime.datetime.now() - datetime.timedelta(days=7)).isoformat()
    new_this_week    = [c for c in claims if c['created_at'] >= week_ago]
    closed_this_week = [c for c in claims if c['status'] == 'Closed' and c['updated_at'] >= week_ago]
    open_claims      = [c for c in claims if c['status'] != 'Closed']
    pipeline         = sum(c['total_estimate'] for c in open_claims)
    admin_email      = get_setting('admin_report_email') or ADMIN_EMAIL
    html = f'''
    <div style="font-family:sans-serif;max-width:640px;margin:0 auto">
      <div style="background:#0a1628;color:#fff;padding:1.5rem 2rem;border-radius:12px 12px 0 0">
        <h2 style="margin:0;font-size:1.3rem">FloodClaim Pro — Weekly Summary</h2>
        <p style="margin:.25rem 0 0;opacity:.7;font-size:.85rem">{datetime.datetime.now().strftime("%B %d, %Y")}</p>
      </div>
      <div style="background:#f8fafc;padding:1.5rem 2rem;border:1px solid #e2e8f0;border-top:none">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:1rem;margin-bottom:1.5rem">
          <div style="background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:1rem;text-align:center">
            <div style="font-size:1.8rem;font-weight:800;color:#3b82f6">{len(new_this_week)}</div>
            <div style="font-size:.75rem;color:#64748b;font-weight:700;text-transform:uppercase">New This Week</div>
          </div>
          <div style="background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:1rem;text-align:center">
            <div style="font-size:1.8rem;font-weight:800;color:#10b981">{len(closed_this_week)}</div>
            <div style="font-size:.75rem;color:#64748b;font-weight:700;text-transform:uppercase">Closed This Week</div>
          </div>
          <div style="background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:1rem;text-align:center">
            <div style="font-size:1.8rem;font-weight:800;color:#f59e0b">{len(open_claims)}</div>
            <div style="font-size:.75rem;color:#64748b;font-weight:700;text-transform:uppercase">Open Claims</div>
          </div>
          <div style="background:#fff;border:1px solid #e2e8f0;border-radius:10px;padding:1rem;text-align:center">
            <div style="font-size:1.8rem;font-weight:800;color:#6366f1">${pipeline:,.0f}</div>
            <div style="font-size:.75rem;color:#64748b;font-weight:700;text-transform:uppercase">Pipeline Value</div>
          </div>
        </div>
        <p style="font-size:.85rem;color:#64748b">Log in to <a href="https://billy-floods.up.railway.app">FloodClaim Pro</a> to view full details.</p>
      </div>
    </div>'''
    sent = send_email(admin_email, f'FloodClaim Pro — Weekly Report ({datetime.datetime.now().strftime("%b %d")})', html)
    if sent:
        flash(f'📧 Weekly report sent to {admin_email}.', 'success')
    else:
        flash('Email not sent — configure SendGrid in Settings.', 'error')
    return redirect(url_for('settings'))


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE 1: KANBAN PIPELINE VIEW
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/pipeline')
@login_required
def pipeline():
    db = get_db()
    if session['role'] == 'admin':
        claims = db.execute('''
            SELECT c.*, u.name as adjuster_name
            FROM claims c LEFT JOIN users u ON c.adjuster_id=u.id
            ORDER BY c.kanban_order ASC, c.created_at DESC
        ''').fetchall()
    else:
        claims = db.execute('''
            SELECT c.*, u.name as adjuster_name
            FROM claims c LEFT JOIN users u ON c.adjuster_id=u.id
            WHERE c.adjuster_id=?
            ORDER BY c.kanban_order ASC, c.created_at DESC
        ''', (session['user_id'],)).fetchall()
    cols = ['New', 'In Progress', 'Submitted', 'Closed']
    board = {col: [c for c in claims if c['status'] == col] for col in cols}
    return render_template('pipeline.html', board=board, cols=cols)


@app.route('/pipeline/move', methods=['POST'])
@login_required
def pipeline_move():
    """AJAX: move a claim to a new status column."""
    data      = request.get_json() or {}
    claim_id  = data.get('claim_id')
    new_status = data.get('status')
    valid = ['New', 'In Progress', 'Submitted', 'Closed']
    if not claim_id or new_status not in valid:
        return jsonify({'ok': False, 'error': 'Invalid'}), 400
    db = get_db()
    claim = db.execute('SELECT * FROM claims WHERE id=?', (claim_id,)).fetchone()
    if not claim:
        return jsonify({'ok': False, 'error': 'Not found'}), 404
    if session['role'] != 'admin' and claim['adjuster_id'] != session['user_id']:
        return jsonify({'ok': False, 'error': 'Forbidden'}), 403
    old_status = claim['status']
    db.execute('UPDATE claims SET status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?',
               (new_status, claim_id))
    db.commit()
    # Fire status-change notification
    if old_status != new_status and claim['client_email']:
        notify_client_status_change(claim, new_status)
        _log_notification(claim_id, 'status_change',
                          claim['client_email'],
                          f'Claim {claim["claim_number"]} moved to {new_status}')
    return jsonify({'ok': True})


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE 2: INSPECTION SCHEDULER
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/schedule')
@login_required
def schedule():
    db = get_db()
    if session['role'] == 'admin':
        slots = db.execute('''
            SELECT s.*, c.claim_number, c.client_name, c.property_address,
                   u.name as adjuster_name
            FROM inspection_slots s
            JOIN claims c ON s.claim_id = c.id
            LEFT JOIN users u ON s.adjuster_id = u.id
            ORDER BY s.slot_date ASC, s.slot_time ASC
        ''').fetchall()
        claims = db.execute('''
            SELECT id, claim_number, client_name, property_address, adjuster_id
            FROM claims WHERE status != 'Closed' ORDER BY created_at DESC
        ''').fetchall()
        adjusters = db.execute('SELECT id, name FROM users ORDER BY name').fetchall()
    else:
        slots = db.execute('''
            SELECT s.*, c.claim_number, c.client_name, c.property_address,
                   u.name as adjuster_name
            FROM inspection_slots s
            JOIN claims c ON s.claim_id = c.id
            LEFT JOIN users u ON s.adjuster_id = u.id
            WHERE s.adjuster_id = ?
            ORDER BY s.slot_date ASC, s.slot_time ASC
        ''', (session['user_id'],)).fetchall()
        claims = db.execute('''
            SELECT id, claim_number, client_name, property_address, adjuster_id
            FROM claims WHERE adjuster_id=? AND status != 'Closed'
            ORDER BY created_at DESC
        ''', (session['user_id'],)).fetchall()
        adjusters = []
    today = datetime.date.today().isoformat()
    return render_template('schedule.html', slots=slots, claims=claims,
                           adjusters=adjusters, today=today)


@app.route('/schedule/add', methods=['POST'])
@login_required
@csrf_required
def schedule_add():
    db        = get_db()
    claim_id  = request.form.get('claim_id')
    slot_date = request.form.get('slot_date')
    slot_time = request.form.get('slot_time')
    notes     = request.form.get('notes', '')
    adj_id    = request.form.get('adjuster_id') or session['user_id']
    if not claim_id or not slot_date or not slot_time:
        flash('Claim, date and time are required.', 'error')
        return redirect(url_for('schedule'))
    db.execute('''
        INSERT INTO inspection_slots (claim_id, adjuster_id, slot_date, slot_time, notes)
        VALUES (?,?,?,?,?)
    ''', (claim_id, adj_id, slot_date, slot_time, notes))
    # Update claim's sched fields
    db.execute('UPDATE claims SET sched_date=?, sched_time=?, inspection_date=?, updated_at=CURRENT_TIMESTAMP WHERE id=?',
               (slot_date, slot_time, slot_date, claim_id))
    db.commit()
    claim = db.execute('SELECT * FROM claims WHERE id=?', (claim_id,)).fetchone()
    # Email adjuster
    adj = db.execute('SELECT * FROM users WHERE id=?', (adj_id,)).fetchone()
    if adj and adj['email']:
        send_email(adj['email'],
                   f'Inspection Scheduled — {claim["claim_number"]}',
                   f'<p>An inspection has been scheduled for claim <strong>{claim["claim_number"]}</strong> '
                   f'({claim["client_name"]}) on <strong>{slot_date} at {slot_time}</strong>.</p>'
                   f'<p>Property: {claim["property_address"]}</p>'
                   f'<p>Notes: {notes or "None"}</p>')
    flash(f'Inspection scheduled for {slot_date} at {slot_time}.', 'success')
    return redirect(url_for('schedule'))


@app.route('/schedule/<int:slot_id>/status', methods=['POST'])
@login_required
def schedule_update_status(slot_id):
    new_status = request.form.get('status', 'pending')
    db = get_db()
    db.execute('UPDATE inspection_slots SET status=? WHERE id=?', (new_status, slot_id))
    db.commit()
    return redirect(url_for('schedule'))


@app.route('/schedule/<int:slot_id>/delete', methods=['POST'])
@login_required
@csrf_required
def schedule_delete(slot_id):
    db = get_db()
    db.execute('DELETE FROM inspection_slots WHERE id=?', (slot_id,))
    db.commit()
    flash('Inspection removed.', 'success')
    return redirect(url_for('schedule'))


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE 3: AUTOMATED NOTIFICATIONS
# ─────────────────────────────────────────────────────────────────────────────

def _log_notification(claim_id, notif_type, recipient, message):
    """Log a sent notification to the DB."""
    try:
        db = get_db()
        db.execute(
            'INSERT INTO notifications_log (claim_id, type, recipient, message) VALUES (?,?,?,?)',
            (claim_id, notif_type, recipient, message)
        )
        db.commit()
    except Exception as e:
        print(f'_log_notification error: {e}')


@app.route('/notifications')
@login_required
def notifications():
    db = get_db()
    if session['role'] == 'admin':
        logs = db.execute('''
            SELECT n.*, c.claim_number, c.client_name
            FROM notifications_log n
            LEFT JOIN claims c ON n.claim_id = c.id
            ORDER BY n.sent_at DESC LIMIT 200
        ''').fetchall()
    else:
        logs = db.execute('''
            SELECT n.*, c.claim_number, c.client_name
            FROM notifications_log n
            LEFT JOIN claims c ON n.claim_id = c.id
            WHERE c.adjuster_id = ?
            ORDER BY n.sent_at DESC LIMIT 200
        ''', (session['user_id'],)).fetchall()
    return render_template('notifications.html', logs=logs)


@app.route('/notifications/send', methods=['POST'])
@login_required
@csrf_required
def notifications_send():
    """Manually send a status update email for a claim."""
    claim_id = request.form.get('claim_id')
    message  = request.form.get('message', '').strip()
    db = get_db()
    claim = db.execute('SELECT * FROM claims WHERE id=?', (claim_id,)).fetchone()
    if not claim:
        flash('Claim not found.', 'error')
        return redirect(url_for('notifications'))
    if not claim['client_email']:
        flash('No client email on this claim.', 'error')
        return redirect(url_for('notifications'))
    subject = f'Update on your FloodClaim — {claim["claim_number"]}'
    html = f'''<div style="font-family:sans-serif;max-width:600px;margin:0 auto">
        <h2 style="color:#0a1628">FloodClaim Pro — Claim Update</h2>
        <p>Hello {claim["client_name"]},</p>
        <p>{message}</p>
        <p style="background:#f0fdf4;padding:12px;border-radius:8px;border-left:4px solid #10b981">
            <strong>Claim #: {claim["claim_number"]}</strong><br>
            Status: {claim["status"]}
        </p>
        <hr style="margin:24px 0;border:none;border-top:1px solid #e2e8f0">
        <p style="font-size:12px;color:#94a3b8">FloodClaim Pro · Professional Flood Damage Assessment</p>
    </div>'''
    sent = send_email(claim['client_email'], subject, html)
    if sent:
        _log_notification(claim_id, 'manual', claim['client_email'], message)
        flash(f'Notification sent to {claim["client_email"]}.', 'success')
    else:
        flash('Email not sent — configure SendGrid in Settings.', 'error')
    return redirect(url_for('notifications'))


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE 4: NFIP COMPLIANCE CHECKLIST
# ─────────────────────────────────────────────────────────────────────────────

NFIP_CHECKLIST = [
    ('policy',         'Policy number recorded'),
    ('policy_type',    'Policy type identified (Building/Contents/Both)'),
    ('coverage_bldg',  'Building coverage amount documented'),
    ('coverage_cont',  'Contents coverage amount documented'),
    ('deductible',     'Deductible amount confirmed'),
    ('flood_date',     'Date of loss (flood date) recorded'),
    ('flood_source',   'Flood source documented (river, storm, sewer, etc.)'),
    ('water_cat',      'Water category assigned (Cat 1/2/3)'),
    ('water_class',    'Water class assigned (Class 1–4)'),
    ('water_depth',    'Water depth documented (inches)'),
    ('water_removed',  'Date water removed recorded'),
    ('inspection',     'Inspection date scheduled/completed'),
    ('flood_zone',     'FEMA flood zone looked up'),
    ('fema_map',       'FEMA map panel number recorded'),
    ('photos',         'Damage photos uploaded'),
    ('rooms',          'Room-by-room scope documented'),
    ('estimate',       'AI estimate generated'),
    ('mortgage',       'Mortgage company/loan # recorded (if applicable)'),
]


@app.route('/claims/<int:claim_id>/compliance')
@login_required
def compliance(claim_id):
    db    = get_db()
    claim = db.execute('SELECT * FROM claims WHERE id=?', (claim_id,)).fetchone()
    if not claim:
        flash('Claim not found.', 'error')
        return redirect(url_for('dashboard'))
    rooms  = db.execute('SELECT id FROM rooms WHERE claim_id=?', (claim_id,)).fetchall()
    photos = db.execute('SELECT id FROM photos WHERE claim_id=?', (claim_id,)).fetchall()
    checks = {
        'policy':        bool(claim['policy_number']),
        'policy_type':   bool(claim['policy_type']),
        'coverage_bldg': bool(claim['coverage_building']),
        'coverage_cont': bool(claim['coverage_contents']),
        'deductible':    bool(claim['deductible']),
        'flood_date':    bool(claim['flood_date']),
        'flood_source':  bool(claim['flood_source']),
        'water_cat':     bool(claim['water_category']),
        'water_class':   bool(claim['water_class']),
        'water_depth':   bool(claim['water_depth_in']),
        'water_removed': bool(claim['date_water_removed']),
        'inspection':    bool(claim['inspection_date'] or claim['sched_date']),
        'flood_zone':    bool(claim['flood_zone'] and claim['flood_zone'] != 'Unknown'),
        'fema_map':      bool(claim['fema_map_number']),
        'photos':        len(photos) >= 1,
        'rooms':         len(rooms) >= 1,
        'estimate':      bool(claim['total_estimate']),
        'mortgage':      True,  # optional — always pass
    }
    score  = sum(1 for v in checks.values() if v)
    total  = len(checks)
    pct    = round(score / total * 100)
    return render_template('compliance.html', claim=claim, checklist=NFIP_CHECKLIST,
                           checks=checks, score=score, total=total, pct=pct)


# ─────────────────────────────────────────────────────────────────────────────
# FEATURE 5: ANALYTICS DASHBOARD
# ─────────────────────────────────────────────────────────────────────────────

@app.route('/analytics')
@login_required
def analytics():
    db = get_db()
    # All claims visible to this user
    if session['role'] == 'admin':
        claims = db.execute('SELECT * FROM claims ORDER BY created_at ASC').fetchall()
    else:
        claims = db.execute('SELECT * FROM claims WHERE adjuster_id=? ORDER BY created_at ASC',
                            (session['user_id'],)).fetchall()

    total   = len(claims)
    closed  = [c for c in claims if c['status'] == 'Closed']
    open_c  = [c for c in claims if c['status'] != 'Closed']
    pipeline_val = sum(c['total_estimate'] for c in open_c)
    closed_val   = sum(c['total_estimate'] for c in closed)

    # Avg cycle time (created_at → last updated_at for closed claims)
    cycle_times = []
    for c in closed:
        try:
            start = datetime.datetime.fromisoformat(c['created_at'])
            end   = datetime.datetime.fromisoformat(c['updated_at'])
            diff  = (end - start).days
            if diff >= 0:
                cycle_times.append(diff)
        except Exception:
            pass
    avg_cycle = round(sum(cycle_times) / len(cycle_times), 1) if cycle_times else None

    # Claims by month (last 12 months)
    from collections import defaultdict
    monthly = defaultdict(lambda: {'count': 0, 'value': 0.0})
    for c in claims:
        try:
            mo = c['created_at'][:7]  # 'YYYY-MM'
            monthly[mo]['count'] += 1
            monthly[mo]['value'] += c['total_estimate']
        except Exception:
            pass
    months_sorted = sorted(monthly.keys())[-12:]
    chart_labels  = months_sorted
    chart_counts  = [monthly[m]['count'] for m in months_sorted]
    chart_values  = [round(monthly[m]['value'], 2) for m in months_sorted]

    # Status breakdown
    status_counts = {
        'New':         sum(1 for c in claims if c['status'] == 'New'),
        'In Progress': sum(1 for c in claims if c['status'] == 'In Progress'),
        'Submitted':   sum(1 for c in claims if c['status'] == 'Submitted'),
        'Closed':      sum(1 for c in claims if c['status'] == 'Closed'),
    }

    # Top adjusters (admin only)
    top_adjusters = []
    if session['role'] == 'admin':
        rows = db.execute('''
            SELECT u.name, COUNT(c.id) as cnt, COALESCE(SUM(c.total_estimate),0) as total
            FROM claims c JOIN users u ON c.adjuster_id=u.id
            GROUP BY c.adjuster_id ORDER BY cnt DESC LIMIT 10
        ''').fetchall()
        top_adjusters = [dict(r) for r in rows]

    return render_template('analytics.html',
                           total=total, pipeline_val=pipeline_val, closed_val=closed_val,
                           avg_cycle=avg_cycle, status_counts=status_counts,
                           chart_labels=json.dumps(chart_labels),
                           chart_counts=json.dumps(chart_counts),
                           chart_values=json.dumps(chart_values),
                           top_adjusters=top_adjusters)


# ─────────────────────────────────────────────────────────────────────────────
# SUBMIT PACKAGE — one-click carrier submission export
# ─────────────────────────────────────────────────────────────────────────────

def _build_proof_of_loss_text(claim, rooms, room_data):
    """Generate a plain-text Proof of Loss document pre-filled with claim data."""
    now  = datetime.datetime.now().strftime('%B %d, %Y')
    lines = [
        'PROOF OF LOSS',
        'NATIONAL FLOOD INSURANCE PROGRAM (NFIP)',
        'Standard Flood Insurance Policy',
        '=' * 60,
        '',
        f'Date of Statement:        {now}',
        f'Claim Number:             {claim["claim_number"]}',
        f'Policy Number:            {claim["policy_number"] or "_________________________"}',
        f'Policy Type:              {claim["policy_type"] or "Building + Contents"}',
        f'Insurance Company:        {claim["insurance_company"] or "_________________________"}',
        '',
        'INSURED (POLICYHOLDER)',
        '-' * 40,
        f'Name:                     {claim["client_name"]}',
        f'Phone:                    {claim["client_phone"] or "_________________________"}',
        f'Email:                    {claim["client_email"] or "_________________________"}',
        '',
        'PROPERTY',
        '-' * 40,
        f'Property Address:         {claim["property_address"]}',
        f'Property Type:            {claim["property_type"] or "_________________________"}',
        f'Year Built:               {claim["year_built"] or "_________________________"}',
        f'Square Footage:           {claim["property_sqft"] or "_________________________"}',
        f'FEMA Flood Zone:          {claim["flood_zone"] or "_________________________"}',
        f'FEMA Map Panel Number:    {claim["fema_map_number"] or "_________________________"}',
        '',
        'LOSS INFORMATION',
        '-' * 40,
        f'Date of Loss:             {claim["flood_date"]}',
        f'Cause of Loss:            {claim["flood_source"] or claim["cause_of_loss"] or "Flood"}',
        f'Water Category:           Category {claim["water_category"] or "3"} (Flood water)',
        f'Water Class:              Class {claim["water_class"] or "_"}',
        f'Water Depth (inches):     {claim["water_depth_in"] or "_________________________"}',
        f'Date Water Removed:       {claim["date_water_removed"] or "_________________________"}',
        f'Inspection Date:          {claim["inspection_date"] or "_________________________"}',
        '',
        'COVERAGE',
        '-' * 40,
        f'Building Coverage:        ${claim["coverage_building"]:,.2f}',
        f'Contents Coverage:        ${claim["coverage_contents"]:,.2f}',
        f'Deductible:               ${claim["deductible"]:,.2f}',
        '',
        'MORTGAGE',
        '-' * 40,
        f'Mortgage Company:         {claim["mortgage_company"] or "N/A"}',
        f'Loan Number:              {claim["mortgage_loan_number"] or "N/A"}',
        '',
        'DAMAGE SUMMARY BY ROOM',
        '-' * 40,
    ]
    for rd in room_data:
        room  = rd['room']
        items = rd['line_items']
        lines.append(f'\n  {room["name"]}   Subtotal: ${room["subtotal"]:,.2f}')
        for item in items:
            lines.append(f'    - {item["description"]:40s}  {item["quantity"]} {item["unit"]:8s}  '
                         f'@ ${item["unit_cost"]:8.2f}  =  ${item["total"]:10.2f}')
    lines += [
        '',
        '=' * 60,
        f'TOTAL CLAIM ESTIMATE:     ${claim["total_estimate"]:,.2f}',
        f'Less Deductible:          ${claim["deductible"]:,.2f}',
        f'NET CLAIM AMOUNT:         ${max(0, claim["total_estimate"] - claim["deductible"]):,.2f}',
        '=' * 60,
        '',
        'CERTIFICATION',
        '-' * 40,
        'The insured hereby certifies that the above information is true and',
        'accurate to the best of their knowledge and belief, and that this Proof',
        'of Loss is submitted pursuant to the Standard Flood Insurance Policy.',
        '',
        f'Insured Signature:        _________________________ Date: __________',
        f'Printed Name:             {claim["client_name"]}',
        '',
        f'Adjuster Name:            {claim["adjuster_name"] or "_________________________"}',
        f'Adjuster Signature:       _________________________ Date: __________',
        f'Flood Control Number:     _________________________',
        '',
        '--- Generated by FloodClaim Pro ---',
    ]
    return '\n'.join(lines)


def _build_building_worksheet_text(claim, room_data):
    """Generate NFIP-style Building Property Worksheet."""
    now = datetime.datetime.now().strftime('%B %d, %Y')
    lines = [
        'NFIP BUILDING PROPERTY WORKSHEET',
        '=' * 60,
        f'Claim Number:     {claim["claim_number"]}',
        f'Policy Number:    {claim["policy_number"] or "_________________________"}',
        f'Insured:          {claim["client_name"]}',
        f'Property:         {claim["property_address"]}',
        f'Date of Loss:     {claim["flood_date"]}',
        f'Prepared:         {now}',
        f'Adjuster:         {claim["adjuster_name"] or "_________________________"}',
        '',
        'BUILDING CHARACTERISTICS',
        '-' * 40,
        f'Type:             {claim["property_type"] or "_________________________"}',
        f'Year Built:       {claim["year_built"] or "_________________________"}',
        f'Square Footage:   {claim["property_sqft"] or "_________________________"} sq ft',
        f'Floors:           {claim["num_floors"] or "_________________________"}',
        f'Flood Zone:       {claim["flood_zone"] or "_________________________"}',
        f'FIRM Panel:       {claim["fema_map_number"] or "_________________________"}',
        '',
        'WATER/DAMAGE DETAILS',
        '-' * 40,
        f'Water Source:     {claim["flood_source"] or "Flood"}',
        f'Water Category:   Category {claim["water_category"] or "3"}',
        f'Water Class:      Class {claim["water_class"] or "_"}',
        f'Depth (in):       {claim["water_depth_in"] or "_"}',
        f'Date Removed:     {claim["date_water_removed"] or "_________________________"}',
        '',
        'ROOM-BY-ROOM DAMAGE',
        '-' * 40,
    ]
    for rd in room_data:
        room  = rd['room']
        items = rd['line_items']
        lines.append(f'\nRoom: {room["name"]}  (Subtotal: ${room["subtotal"]:,.2f})')
        lines.append(f'  {"Description":<42} {"Qty":>6} {"Unit":<8} {"Unit $":>9} {"Total":>10}')
        lines.append('  ' + '-' * 78)
        for item in items:
            lines.append(f'  {item["description"]:<42} {item["quantity"]:>6} '
                         f'{item["unit"]:<8} {item["unit_cost"]:>9.2f} {item["total"]:>10.2f}')
    lines += [
        '',
        '=' * 60,
        f'TOTAL BUILDING ESTIMATE:  ${claim["total_estimate"]:,.2f}',
        '=' * 60,
    ]
    return '\n'.join(lines)


def _build_xactimate_esx(claim, rooms_data):
    """Build Xactimate-compatible ESX (XML) content."""
    now = datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<XactimateEstimate version="1.0" xmlns="http://www.xactware.com/xactimate">',
        '  <Header>',
        f'    <FileType>ESX</FileType>',
        f'    <CreatedBy>FloodClaim Pro</CreatedBy>',
        f'    <ExportDate>{now}</ExportDate>',
        '  </Header>',
        '  <ClaimInfo>',
        f'    <ClaimNumber>{claim["claim_number"]}</ClaimNumber>',
        f'    <TypeOfLoss>Flood</TypeOfLoss>',
        f'    <DateOfLoss>{claim["flood_date"]}</DateOfLoss>',
        f'    <InsuredName>{claim["client_name"]}</InsuredName>',
        f'    <InsuredPhone>{claim["client_phone"] or ""}</InsuredPhone>',
        f'    <InsuredEmail>{claim["client_email"] or ""}</InsuredEmail>',
        f'    <LossAddress>{claim["property_address"]}</LossAddress>',
        f'    <InsuranceCompany>{claim["insurance_company"] or ""}</InsuranceCompany>',
        f'    <PolicyNumber>{claim["policy_number"] or ""}</PolicyNumber>',
        f'    <PolicyType>{claim["policy_type"] or ""}</PolicyType>',
        f'    <CoverageBuilding>{claim["coverage_building"]:.2f}</CoverageBuilding>',
        f'    <CoverageContents>{claim["coverage_contents"]:.2f}</CoverageContents>',
        f'    <Deductible>{claim["deductible"]:.2f}</Deductible>',
        f'    <FloodZone>{claim["flood_zone"] or ""}</FloodZone>',
        f'    <FIRMPanelNumber>{claim["fema_map_number"] or ""}</FIRMPanelNumber>',
        f'    <WaterCategory>{claim["water_category"] or ""}</WaterCategory>',
        f'    <WaterClass>{claim["water_class"] or ""}</WaterClass>',
        f'    <WaterDepthInches>{claim["water_depth_in"] or ""}</WaterDepthInches>',
        f'    <MortgageCompany>{claim["mortgage_company"] or ""}</MortgageCompany>',
        f'    <MortgageLoanNumber>{claim["mortgage_loan_number"] or ""}</MortgageLoanNumber>',
        f'    <AdjusterName>{claim["adjuster_name"] or ""}</AdjusterName>',
        f'    <TotalEstimate>{claim["total_estimate"]:.2f}</TotalEstimate>',
        '  </ClaimInfo>',
        '  <Rooms>',
    ]
    for rd in rooms_data:
        room  = rd['room']
        items = rd['line_items']
        lines += [
            '    <Room>',
            f'      <Name>{room["name"]}</Name>',
            f'      <Description>{room["description"] or ""}</Description>',
            f'      <Subtotal>{room["subtotal"]:.2f}</Subtotal>',
            '      <LineItems>',
        ]
        for item in items:
            lines += [
                '        <LineItem>',
                f'          <Description>{item["description"]}</Description>',
                f'          <Quantity>{item["quantity"]}</Quantity>',
                f'          <Unit>{item["unit"]}</Unit>',
                f'          <UnitCost>{item["unit_cost"]:.2f}</UnitCost>',
                f'          <Total>{item["total"]:.2f}</Total>',
                '        </LineItem>',
            ]
        lines += ['      </LineItems>', '    </Room>']
    lines += ['  </Rooms>', '</XactimateEstimate>']
    return '\n'.join(lines)


def _build_photo_manifest(claim, room_data, unassigned):
    """Build a plain-text photo manifest listing all photos and their rooms."""
    lines = [
        f'PHOTO MANIFEST',
        f'Claim: {claim["claim_number"]} — {claim["client_name"]}',
        f'Property: {claim["property_address"]}',
        f'Generated: {datetime.datetime.now().strftime("%B %d, %Y %I:%M %p")}',
        '=' * 60, ''
    ]
    total = 0
    for rd in room_data:
        photos = rd.get('room_photos', [])
        if photos:
            lines.append(f'Room: {rd["room"]["name"]} ({len(photos)} photos)')
            for p in photos:
                lines.append(f'  - {p["filename"]}  |  {p["caption"] or "No caption"}')
                if p['ai_description']:
                    lines.append(f'    AI: {p["ai_description"][:120]}')
            total += len(photos)
    if unassigned:
        lines.append(f'Unassigned Photos ({len(unassigned)})')
        for p in unassigned:
            lines.append(f'  - {p["filename"]}  |  {p["caption"] or "No caption"}')
        total += len(unassigned)
    lines += ['', '=' * 60, f'Total Photos: {total}']
    return '\n'.join(lines)


@app.route('/claims/<int:claim_id>/submit')
@login_required
def submit_package_page(claim_id):
    """Show the Submit Package page for a claim."""
    db    = get_db()
    claim = db.execute('''SELECT c.*, u.name as adjuster_name, u.email as adjuster_email
        FROM claims c LEFT JOIN users u ON c.adjuster_id=u.id WHERE c.id=?''', (claim_id,)).fetchone()
    if not claim:
        flash('Claim not found.', 'error')
        return redirect(url_for('dashboard'))
    rooms = db.execute('SELECT * FROM rooms WHERE claim_id=? ORDER BY id', (claim_id,)).fetchall()
    room_data = []
    photo_count = 0
    for room in rooms:
        items  = db.execute('SELECT * FROM line_items WHERE room_id=? ORDER BY id', (room['id'],)).fetchall()
        photos = db.execute('SELECT * FROM photos WHERE room_id=? ORDER BY id', (room['id'],)).fetchall()
        room_data.append({'room': room, 'line_items': items, 'room_photos': photos})
        photo_count += len(photos)
    unassigned = db.execute('SELECT * FROM photos WHERE claim_id=? AND room_id IS NULL', (claim_id,)).fetchall()
    photo_count += len(unassigned)
    recalc_claim(claim_id)
    claim = db.execute('''SELECT c.*, u.name as adjuster_name, u.email as adjuster_email
        FROM claims c LEFT JOIN users u ON c.adjuster_id=u.id WHERE c.id=?''', (claim_id,)).fetchone()

    # Compliance score
    photos_all = db.execute('SELECT id FROM photos WHERE claim_id=?', (claim_id,)).fetchall()
    checks = {
        'policy':       bool(claim['policy_number']),
        'flood_zone':   bool(claim['flood_zone'] and claim['flood_zone'] != 'Unknown'),
        'photos':       len(photos_all) >= 3,
        'rooms':        len(rooms) >= 1,
        'estimate':     bool(claim['total_estimate']),
        'flood_date':   bool(claim['flood_date']),
        'water_cat':    bool(claim['water_category']),
        'insurance':    bool(claim['insurance_company']),
    }
    compliance_pct = round(sum(checks.values()) / len(checks) * 100)

    CARRIERS = [
        {'id': 'generic',     'name': 'Generic / Any Carrier',     'icon': '📦', 'desc': 'ZIP with all documents + photos'},
        {'id': 'wright',      'name': 'Wright Flood',               'icon': '🏗️', 'desc': 'Wright Flood adjuster package format'},
        {'id': 'nfip_direct', 'name': 'NFIP Direct (FEMA)',         'icon': '🏙️', 'desc': 'NFIP Direct claim submission package'},
        {'id': 'allstate',    'name': 'Allstate',                   'icon': '🛡️', 'desc': 'Allstate adjuster submission package'},
        {'id': 'statefarm',   'name': 'State Farm',                 'icon': '🧱', 'desc': 'State Farm flood claim package'},
        {'id': 'assurant',    'name': 'Assurant',                   'icon': '📊', 'desc': 'Assurant flood claim package'},
        {'id': 'nationwide',  'name': 'Nationwide',                 'icon': '🏦', 'desc': 'Nationwide flood claim package'},
        {'id': 'xactanalysis','name': 'XactAnalysis (Xactimate)',   'icon': '📝', 'desc': 'ESX estimate + supporting docs for XactAnalysis'},
    ]
    # 60-day Proof of Loss deadline
    flood_date_deadline = None
    if claim['flood_date']:
        try:
            dl = datetime.datetime.strptime(claim['flood_date'], '%Y-%m-%d') + datetime.timedelta(days=60)
            flood_date_deadline = dl.strftime('%B %d, %Y')
        except Exception:
            pass

    return render_template('submit_package.html', claim=claim, room_data=room_data,
                           unassigned=unassigned, photo_count=photo_count,
                           compliance_pct=compliance_pct, checks=checks,
                           carriers=CARRIERS, flood_date_deadline=flood_date_deadline)


@app.route('/claims/<int:claim_id>/submit/download', methods=['POST'])
@login_required
@csrf_required
def submit_package_download(claim_id):
    """Generate and download the submission ZIP package."""
    db      = get_db()
    carrier = request.form.get('carrier', 'generic')
    include_photos = request.form.get('include_photos', 'yes') == 'yes'

    claim = db.execute('''SELECT c.*, u.name as adjuster_name, u.email as adjuster_email
        FROM claims c LEFT JOIN users u ON c.adjuster_id=u.id WHERE c.id=?''', (claim_id,)).fetchone()
    if not claim:
        flash('Claim not found.', 'error')
        return redirect(url_for('dashboard'))
    rooms = db.execute('SELECT * FROM rooms WHERE claim_id=? ORDER BY id', (claim_id,)).fetchall()
    room_data = []
    for room in rooms:
        items  = db.execute('SELECT * FROM line_items WHERE room_id=? ORDER BY id', (room['id'],)).fetchall()
        photos = db.execute('SELECT * FROM photos WHERE room_id=? ORDER BY id', (room['id'],)).fetchall()
        room_data.append({'room': room, 'line_items': items, 'room_photos': photos})
    unassigned = db.execute('SELECT * FROM photos WHERE claim_id=? AND room_id IS NULL', (claim_id,)).fetchall()
    recalc_claim(claim_id)
    claim = db.execute('''SELECT c.*, u.name as adjuster_name, u.email as adjuster_email
        FROM claims c LEFT JOIN users u ON c.adjuster_id=u.id WHERE c.id=?''', (claim_id,)).fetchone()

    cn = claim['claim_number']
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w', zipfile.ZIP_DEFLATED) as zf:

        # 1. Proof of Loss
        pol_text = _build_proof_of_loss_text(claim, rooms, room_data)
        zf.writestr(f'{cn}/01_Proof_of_Loss_{cn}.txt', pol_text)

        # 2. Building Worksheet
        bw_text = _build_building_worksheet_text(claim, room_data)
        zf.writestr(f'{cn}/02_Building_Worksheet_{cn}.txt', bw_text)

        # 3. Xactimate ESX estimate
        esx_content = _build_xactimate_esx(claim, room_data)
        zf.writestr(f'{cn}/03_Estimate_{cn}.esx', esx_content)

        # 4. Photo manifest
        manifest = _build_photo_manifest(claim, room_data, unassigned)
        zf.writestr(f'{cn}/04_Photo_Manifest_{cn}.txt', manifest)

        # 5. Claim summary JSON (for portal APIs)
        summary = {
            'claim_number':      claim['claim_number'],
            'client_name':       claim['client_name'],
            'client_phone':      claim['client_phone'],
            'client_email':      claim['client_email'],
            'property_address':  claim['property_address'],
            'flood_date':        claim['flood_date'],
            'flood_source':      claim['flood_source'],
            'water_category':    claim['water_category'],
            'water_class':       claim['water_class'],
            'water_depth_in':    claim['water_depth_in'],
            'insurance_company': claim['insurance_company'],
            'policy_number':     claim['policy_number'],
            'policy_type':       claim['policy_type'],
            'coverage_building': claim['coverage_building'],
            'coverage_contents': claim['coverage_contents'],
            'deductible':        claim['deductible'],
            'flood_zone':        claim['flood_zone'],
            'fema_map_number':   claim['fema_map_number'],
            'total_estimate':    claim['total_estimate'],
            'net_claim':         max(0, claim['total_estimate'] - claim['deductible']),
            'adjuster_name':     claim['adjuster_name'],
            'adjuster_email':    claim['adjuster_email'],
            'status':            claim['status'],
            'generated':         datetime.datetime.now().isoformat(),
            'carrier_format':    carrier,
            'rooms': [
                {
                    'name':     rd['room']['name'],
                    'subtotal': rd['room']['subtotal'],
                    'items': [
                        {'description': i['description'], 'quantity': i['quantity'],
                         'unit': i['unit'], 'unit_cost': i['unit_cost'], 'total': i['total']}
                        for i in rd['line_items']
                    ]
                } for rd in room_data
            ]
        }
        zf.writestr(f'{cn}/05_Claim_Summary_{cn}.json', json.dumps(summary, indent=2))

        # 6. README with carrier-specific instructions
        carrier_instructions = {
            'generic':      'Upload to your carrier\'s adjuster portal. Include all files.',
            'wright':       'Upload to Wright Flood adjuster portal at wrightflood.com/claims\n'
                            'Required: Proof of Loss, ESX estimate, all photos.\n'
                            'Submit within 60 days of date of loss.',
            'nfip_direct':  'Submit to NFIP Direct via the FEMA adjuster portal.\n'
                            'Email: FEMA-NFIPFROMailbox@fema.dhs.gov\n'
                            'Required: Signed Proof of Loss, Building Worksheet, photos, ESX.',
            'allstate':     'Upload via Allstate Business Insurance adjuster portal.\n'
                            'Required: ESX estimate, Proof of Loss, photos.',
            'statefarm':    'Submit via State Farm Claims portal or email to your assigned examiner.\n'
                            'Required: ESX estimate, signed Proof of Loss, all damage photos.',
            'assurant':     'Submit via Assurant adjuster portal at assurant.com/claims\n'
                            'Required: ESX estimate, Proof of Loss, Building Worksheet, photos.',
            'nationwide':   'Submit via Nationwide adjuster portal.\n'
                            'Required: Signed Proof of Loss, ESX estimate, photos.',
            'xactanalysis': 'Upload your ESX file directly to XactAnalysis at xactanalysis.com\n'
                            'File: 03_Estimate_{cn}.esx\n'
                            'Attach remaining documents as supporting files in XactAnalysis.',
        }
        readme = f'''FLOODCLAIM PRO — SUBMISSION PACKAGE
{'=' * 60}
Claim:    {cn}
Client:   {claim['client_name']}
Property: {claim['property_address']}
Carrier:  {carrier.upper()}
Generated: {datetime.datetime.now().strftime('%B %d, %Y %I:%M %p')}

FILES IN THIS PACKAGE
{'-' * 40}
01_Proof_of_Loss_{cn}.txt         — Signed Proof of Loss (print + sign)
02_Building_Worksheet_{cn}.txt    — NFIP Building Property Worksheet
03_Estimate_{cn}.esx              — Xactimate-compatible estimate
04_Photo_Manifest_{cn}.txt        — Photo index with AI descriptions
05_Claim_Summary_{cn}.json        — Machine-readable claim data
Photos/                           — All damage photos organized by room

SUBMISSION INSTRUCTIONS
{'-' * 40}
{carrier_instructions.get(carrier, carrier_instructions['generic'])}

IMPORTANT DEADLINES
{'-' * 40}
• File Proof of Loss within 60 days of date of loss ({claim['flood_date']})
• Deadline: {(datetime.datetime.strptime(claim['flood_date'], '%Y-%m-%d') + datetime.timedelta(days=60)).strftime('%B %d, %Y') if claim['flood_date'] else 'Check policy'}
• Keep copies of all submitted documents
• Note your claim number: {cn}

Generated by FloodClaim Pro — Professional Flood Damage Assessment
'''
        zf.writestr(f'{cn}/README_{carrier.upper()}.txt', readme)

        # 7. Photos (organized by room folder)
        if include_photos:
            for rd in room_data:
                room_name = rd['room']['name'].replace('/', '-').replace(' ', '_')
                for photo in rd['room_photos']:
                    path = os.path.join(UPLOAD_DIR, photo['filename'])
                    if os.path.exists(path):
                        zf.write(path, f'{cn}/Photos/{room_name}/{photo["filename"]}')
            for photo in unassigned:
                path = os.path.join(UPLOAD_DIR, photo['filename'])
                if os.path.exists(path):
                    zf.write(path, f'{cn}/Photos/General/{photo["filename"]}')

    buf.seek(0)
    _log_activity(claim_id, f'Submission package downloaded (carrier: {carrier})')
    resp = make_response(buf.read())
    resp.headers['Content-Type']        = 'application/zip'
    resp.headers['Content-Disposition'] = f'attachment; filename="{cn}-{carrier}-submission.zip"'
    return resp


@app.route('/sales')
def sales_page():
    """Hidden sales/pitch page — no login required, no nav link.
    Remove this route when Billy buys."""
    return render_template('sales.html')

@app.route('/health')
def health():
    return jsonify({'status': 'ok'})

# ── Phase 3: Standardized /api/status ───────────────────────────────────
@app.route('/api/status', methods=['GET'])
def api_status():
    """Liberty-Emporium network: standardized status endpoint."""
    from datetime import datetime, timezone
    uptime = int(_uptime_time.time() - _APP_START_TIME)
    def _fmt(s):
        if s < 60:   return f"{s}s"
        if s < 3600: return f"{s//60}m {s%60}s"
        return f"{s//3600}h {(s%3600)//60}m"
    try:
        db     = get_db()
        claims = db.execute('SELECT COUNT(*) FROM claims').fetchone()[0]
        open_c = db.execute("SELECT COUNT(*) FROM claims WHERE status NOT IN ('closed','paid')").fetchone()[0]
        photos = db.execute('SELECT COUNT(*) FROM photos').fetchone()[0]
        stats  = {'total_claims': claims, 'open_claims': open_c, 'total_photos': photos}
    except Exception as e:
        stats = {'error': str(e)}
    return jsonify({
        'app':            APP_NAME,
        'version':        APP_VERSION,
        'healthy':        True,
        'uptime_seconds': uptime,
        'uptime_human':   _fmt(uptime),
        'stats':          stats,
        'network':        'liberty-emporium',
        'ts':             datetime.now(timezone.utc).isoformat(),
    })

# ── Phase 3: Cross-app — Pet Vet AI photo analysis ──────────────────────────
def ai_describe_photo_via_network(image_path):
    """Phase 3: Ask Pet Vet AI to analyze a damage photo via the app network.
    Falls back to local OpenRouter analysis if network call fails.
    """
    try:
        with open(image_path, 'rb') as f:
            img_b64 = base64.b64encode(f.read()).decode()
        ext  = image_path.rsplit('.', 1)[-1].lower()
        mime = f'image/{ext}' if ext != 'jpg' else 'image/jpeg'

        result = _call_app('Pet Vet AI', '/api/analyze-damage',
                           data={'image_b64': img_b64, 'mime_type': mime,
                                 'context': 'flood damage'})
        if result and result.get('success'):
            analysis = result.get('analysis', {})
            if isinstance(analysis, dict):
                return analysis.get('description') or analysis.get('diagnosis', '')
            return str(analysis)
    except Exception:
        pass
    # Fallback to local
    return ai_describe_photo(image_path)

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
