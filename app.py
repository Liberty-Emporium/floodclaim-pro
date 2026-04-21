import os, sqlite3, secrets, hashlib, json, datetime, pathlib, base64, io
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

app.secret_key = _SECRET_KEY

# ── Session config ────────────────────────────────────────────────────────────
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
app.config['SESSION_COOKIE_HTTPONLY']    = True
app.config['SESSION_COOKIE_SAMESITE']   = 'Lax'
# Keep Secure=False — Railway's edge terminates TLS; the cookie travels over
# plain HTTP between the edge and the app container, so Secure would silently
# drop it. Railway enforces HTTPS at the edge already.
app.config['SESSION_COOKIE_SECURE']     = False

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
    return hashlib.sha256(pw.encode()).hexdigest()

def check_pw(pw, hashed):
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
                user_id         INTEGER REFERENCES users(id),
                stripe_customer TEXT,
                stripe_sub_id   TEXT,
                plan            TEXT DEFAULT 'basic',
                status          TEXT DEFAULT 'active',
                created_at      TEXT DEFAULT CURRENT_TIMESTAMP
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

def set_setting(key, value):
    db = sqlite3.connect(DB_PATH)
    db.execute(
        'INSERT INTO settings (key, value) VALUES (?,?) '
        'ON CONFLICT(key) DO UPDATE SET value=excluded.value',
        (key, value))
    db.commit()
    db.close()

# ── Willie API token ─────────────────────────────────────────────────────────────────
def get_willie_token():
    """Get or auto-generate the Willie API token."""
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


# ── AI Adjuster Estimate (UI) ───────────────────────────────────────────────────
@app.route('/claims/<int:claim_id>/ai-estimate', methods=['POST'])
def ai_estimate(claim_id):
    """Generate a full AI adjuster estimate — analyzes photos + line items.
    Accepts session login OR Willie API token for cross-origin requests."""
    # Allow Willie token auth as fallback for cross-origin requests
    if not session.get('user_id'):
        if not willie_auth():
            return jsonify({'ok': False, 'error': 'Session expired — please refresh the page and log in again.'}), 401
    db = get_db()
    claim = db.execute('SELECT * FROM claims WHERE id=?', (claim_id,)).fetchone()
    if not claim:
        return jsonify({'ok': False, 'error': 'Claim not found'}), 404

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
    photos = db.execute('SELECT * FROM photos WHERE claim_id=? ORDER BY id', (claim_id,)).fetchall()
    photo_analyses = []
    for photo in photos[:8]:
        photo_path = os.path.join(UPLOAD_DIR, photo['filename'])
        desc = photo.get('ai_description', '')
        if not desc and os.path.exists(photo_path):
            desc = ai_describe_photo(photo_path)
            if desc:
                db.execute('UPDATE photos SET ai_description=? WHERE id=?', (desc, photo['id']))
                db.commit()
        if desc:
            label = photo.get('caption') or photo['filename']
            photo_analyses.append(f"  [{label}]: {desc}")
    photo_section = '\n'.join(photo_analyses) if photo_analyses else '  No photos uploaded yet.'

    prompt = f"""You are a licensed public adjuster and flood damage estimator with 20 years of experience.
Analyze this flood damage claim and produce a complete, professional estimate like you would submit to an insurance company.

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
What specific damage is visible in each photo? (water lines, mold, structural, flooring, drywall, etc.)

2. 📊 COMPLETE LINE-ITEM ESTIMATE
List every repair needed:
| Item | Qty | Unit | Unit Cost | Total |
Mark existing items ✅ and new recommended items ➕

3. 💰 ESTIMATE SUMMARY
- Subtotal per room
- Grand Total
- 10% contingency
- Recommended claim amount

4. ⚠️ ADJUSTER NOTES
Documentation gaps, red flags, items insurance may dispute, and what to photograph next.

Use current market rates for {claim.get('property_address', 'North Carolina')}. Be thorough and professional."""

    estimate = call_openrouter([{'role': 'user', 'content': prompt}], model, key)
    return jsonify({
        'ok': True,
        'claim_number': claim['claim_number'],
        'client': claim['client_name'],
        'current_total': float(claim['total_estimate']),
        'photos_analyzed': len(photo_analyses),
        'estimate': estimate
    })


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
        room_data.append({'room': room, 'items': items, 'photos': photos})
    unassigned_photos = db.execute('SELECT * FROM photos WHERE claim_id=? AND room_id IS NULL', (claim_id,)).fetchall()
    recalc_claim(claim_id)
    claim = db.execute('''SELECT c.*, u.name as adjuster_name, u.email as adjuster_email
        FROM claims c LEFT JOIN users u ON c.adjuster_id=u.id WHERE c.id=?''', (claim_id,)).fetchone()
    return render_template('report.html', claim=claim, room_data=room_data,
                           unassigned_photos=unassigned_photos, pdf_mode=True, auto_print=True,
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
        room_data.append({'room': room, 'items': items, 'photos': photos})
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
@app.route('/billing')
@login_required
def billing():
    plans = [
        {'id': 'basic',  'name': 'Basic',  'price': '$49/mo',  'features': ['25 claims/mo', 'PDF export', 'Willie AI', 'Client portal']},
        {'id': 'pro',    'name': 'Pro',    'price': '$99/mo',  'features': ['100 claims/mo', 'Everything in Basic', 'Xactimate export', 'Priority support']},
        {'id': 'agency', 'name': 'Agency', 'price': '$249/mo', 'features': ['Unlimited claims', 'Everything in Pro', 'Multi-adjuster team', 'White-label reports']},
    ]
    return render_template('billing.html', plans=plans, sub=None)


@app.route('/billing/checkout', methods=['POST'])
@login_required
def billing_checkout():
    flash('Stripe integration coming soon — add STRIPE_SECRET_KEY in Settings to activate.', 'info')
    return redirect(url_for('billing'))

def call_openrouter(messages, model, key):
    """Call OpenRouter chat completions API. Returns response text or error string."""
    try:
        r = _req.post(
            'https://openrouter.ai/api/v1/chat/completions',
            headers={'Authorization': f'Bearer {key}', 'Content-Type': 'application/json'},
            json={'model': model, 'messages': messages, 'max_tokens': 1500},
            timeout=60
        )
        data = r.json()
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
        return f'AI analysis failed: {str(e)}'

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        pw    = request.form.get('password', '')
        db    = get_db()
        user  = db.execute('SELECT * FROM users WHERE email=?', (email,)).fetchone()
        if not user or not check_pw(pw, user['password']):
            flash('Invalid email or password.', 'error')
            return render_template('login.html')
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
    if session['role'] == 'admin':
        claims = db.execute('''SELECT c.*, u.name as adjuster_name
            FROM claims c LEFT JOIN users u ON c.adjuster_id=u.id
            ORDER BY c.created_at DESC''').fetchall()
    else:
        claims = db.execute('''SELECT c.*, u.name as adjuster_name
            FROM claims c LEFT JOIN users u ON c.adjuster_id=u.id
            WHERE c.adjuster_id=? ORDER BY c.created_at DESC''',
            (session['user_id'],)).fetchall()
    stats = {
        'total':       len(claims),
        'new':         sum(1 for c in claims if c['status'] == 'New'),
        'in_progress': sum(1 for c in claims if c['status'] == 'In Progress'),
        'submitted':   sum(1 for c in claims if c['status'] == 'Submitted'),
        'closed':      sum(1 for c in claims if c['status'] == 'Closed'),
        'pipeline':    sum(c['total_estimate'] for c in claims if c['status'] != 'Closed'),
    }
    adjusters = db.execute('SELECT * FROM users ORDER BY name').fetchall() \
                if session['role'] == 'admin' else []
    return render_template('dashboard.html', claims=claims, stats=stats, adjusters=adjusters)

@app.route('/claims/new', methods=['GET', 'POST'])
@login_required
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
            room_data.append({'room': room, 'items': items, 'photos': photos})
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
        return render_template('claim_detail.html', claim=claim,
                               room_data=room_data, unassigned_photos=unassigned_photos)
    except Exception as _claim_err:
        import traceback as _tb
        print(f'[claim_detail ERROR] claim_id={claim_id}: {_claim_err}\n{_tb.format_exc()}')
        flash(f'Error loading claim — check server logs for details: {_claim_err}', 'error')
        return redirect(url_for('dashboard'))

@app.route('/claims/<int:claim_id>/status', methods=['POST'])
@login_required
def update_status(claim_id):
    db = get_db()
    status = request.form.get('status')
    claim = db.execute('SELECT * FROM claims WHERE id=?', (claim_id,)).fetchone()
    db.execute('UPDATE claims SET status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?',
               (status, claim_id))
    db.commit()
    if claim:
        notify_client_status_change(claim, status)
    return redirect(url_for('claim_detail', claim_id=claim_id))

@app.route('/claims/<int:claim_id>/room/add', methods=['POST'])
@login_required
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

@app.route('/rooms/<int:room_id>/item/add', methods=['POST'])
@login_required
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
        room_data.append({'room': room, 'items': items, 'photos': photos})
    unassigned_photos = db.execute(
        'SELECT * FROM photos WHERE claim_id=? AND room_id IS NULL', (claim_id,)).fetchall()
    recalc_claim(claim_id)
    claim = db.execute('''SELECT c.*, u.name as adjuster_name, u.email as adjuster_email
        FROM claims c LEFT JOIN users u ON c.adjuster_id=u.id WHERE c.id=?''',
        (claim_id,)).fetchone()
    return render_template('report.html', claim=claim, room_data=room_data,
                           unassigned_photos=unassigned_photos,
                           generated=datetime.datetime.now().strftime('%B %d, %Y %I:%M %p'))

# ── Admin: Settings ───────────────────────────────────────────────────────────

@app.route('/admin/settings', methods=['GET', 'POST'])
@login_required
@admin_required
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
                    'twilio_account_sid', 'twilio_auth_token', 'twilio_from_number']:
            val = request.form.get(key, '').strip()
            if val:
                set_setting(key, val)
        flash('Settings saved!', 'success')
        return redirect(url_for('settings'))
    current_key = get_setting('openrouter_api_key')
    masked_key  = ''
    if current_key:
        if len(current_key) > 12:
            masked_key = current_key[:8] + '•' * (len(current_key) - 12) + current_key[-4:]
        else:
            masked_key = '••••••••'
    env_key_set    = bool(OPENROUTER_KEY)
    current_model  = get_setting('ai_model', 'openai/gpt-4o-mini')
    return render_template('settings.html',
                           masked_key=masked_key,
                           key_is_set=bool(current_key),
                           env_key_set=env_key_set,
                           current_model=current_model)

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

# ── Willie Chat ────────────────────────────────────────────────────────────────

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
    """Proxy to the Willie AI widget endpoint and save to history."""
    data       = request.get_json(silent=True) or {}
    message    = data.get('message', '').strip()
    history    = data.get('history', [])
    conv_id    = data.get('conversation_id')
    session_id = data.get('session_id', '')
    if not message:
        return jsonify({'error': 'message required'}), 400

    WILLIE_AGENT_ID = get_setting('willie_agent_id', 'F5J8yYT6a6GrppjviN6p8w')
    WIDGET_BASE     = 'https://ai-agent-widget-production.up.railway.app'

    try:
        payload = json.dumps({'message': message, 'history': history[-10:],
                              'session_id': session_id or f'willie-{session["user_id"]}'}).encode()
        req = _req.post(f'{WIDGET_BASE}/chat/{WILLIE_AGENT_ID}',
                        headers={'Content-Type': 'application/json'},
                        data=payload, timeout=30)
        result  = req.json()
        reply   = result.get('reply', 'Willie is unavailable right now.')
    except Exception as e:
        reply = f'Willie is unavailable right now. ({str(e)[:60]})'

    # Save both messages to history if conv_id provided
    if conv_id:
        db = get_db()
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

# ── Willie External API ──────────────────────────────────────────────────────────────
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
            room_data.append({'room': dict(r), 'items': [dict(i) for i in items]})
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
    photos = db.execute('SELECT * FROM photos WHERE claim_id=? ORDER BY id', (claim_id,)).fetchall()
    photo_analyses = []
    for photo in photos[:8]:  # limit to 8 photos to avoid token overflow
        photo_path = os.path.join(UPLOAD_DIR, photo['filename'])
        if os.path.exists(photo_path):
            if photo.get('ai_description'):
                photo_analyses.append(f"Photo ({photo['caption'] or photo['filename']}): {photo['ai_description']}")
            else:
                analysis = ai_describe_photo(photo_path)
                if analysis:
                    db.execute('UPDATE photos SET ai_description=? WHERE id=?', (analysis, photo['id']))
                    db.commit()
                    photo_analyses.append(f"Photo ({photo['caption'] or photo['filename']}): {analysis}")

    photo_section = '\n'.join(photo_analyses) if photo_analyses else 'No photos uploaded yet.'
    room_section  = '\n'.join(room_summary) if room_summary else 'No rooms documented yet.'

    prompt = f"""You are a licensed public adjuster and flood damage estimator with 20 years of experience.
Analyze this flood damage claim and produce a complete professional estimate like you would submit to an insurance company.

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

1. **PHOTO FINDINGS** — What damage did you observe in each photo? Be specific (water staining, mold, structural damage, flooring damage, etc.)

2. **COMPLETE LINE-ITEM ESTIMATE** — List every repair item needed with:
   - Description
   - Quantity + Unit (sq ft, ln ft, ea, hr)
   - Unit Cost
   - Line Total
   Mark items already documented with ✅, missing items with ➕

3. **ESTIMATE SUMMARY**
   - Subtotal by room
   - Grand Total
   - Suggested contingency (10-15%)
   - Final recommended claim amount

4. **ADJUSTER NOTES** — Any red flags, documentation gaps, or items the insurance company will likely scrutinize.

Use current market rates for the {claim.get('property_address', 'southeastern US')} area. Be thorough — this goes to the insurance company."""

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
        room_data.append({'room': dict(r), 'items': [dict(i) for i in items]})
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
    rooms = db.execute('SELECT id, room_name, notes FROM rooms WHERE claim_id=? ORDER BY id', (claim_id,)).fetchall()
    items = db.execute('SELECT id, room_id, description, quantity, unit, unit_cost, total_cost FROM line_items WHERE claim_id=? ORDER BY id', (claim_id,)).fetchall()
    rooms_out = []
    for r in rooms:
        room_items = [dict(i) for i in items if i['room_id'] == r['id']]
        rooms_out.append({'id': r['id'], 'room_name': r['room_name'], 'notes': r['notes'], 'line_items': room_items})
    return jsonify({'ok': True, 'claim_id': claim_id, 'rooms': rooms_out})


@app.route('/willie/api/claims/<int:claim_id>/rooms/<int:room_id>', methods=['DELETE'])
def willie_delete_room(claim_id, room_id):
    if not willie_auth(): return jsonify({'error': 'unauthorized'}), 401
    db = get_db()
    room = db.execute('SELECT id, room_name FROM rooms WHERE id=? AND claim_id=?', (room_id, claim_id)).fetchone()
    if not room: return jsonify({'error': 'Room not found'}), 404
    db.execute('DELETE FROM rooms WHERE id=?', (room_id,))
    db.commit()
    return jsonify({'ok': True, 'message': f'Room "{room["room_name"]}" and all its line items deleted.'})


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
    allowed = {'openrouter_api_key', 'openrouter_model'}
    updated = []
    for key, value in data.items():
        if key in allowed:
            db.execute('INSERT INTO settings (key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', (key, value))
            updated.append(key)
    db.commit()
    return jsonify({'ok': True, 'updated': updated})


@app.route('/health')
def health():
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
