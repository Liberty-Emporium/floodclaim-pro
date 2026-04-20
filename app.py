import os, sqlite3, secrets, hashlib, json, datetime, pathlib, base64
from datetime import timedelta
from functools import wraps
from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, jsonify, g, send_from_directory)
from werkzeug.utils import secure_filename
import requests as _req

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
app.config['SESSION_COOKIE_SECURE']   = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

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
            client_email    TEXT DEFAULT '',
            property_address TEXT NOT NULL,
            flood_date      TEXT NOT NULL,
            insurance_company TEXT DEFAULT '',
            policy_number   TEXT DEFAULT '',
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
    ''')
    # Seed admin
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

# ── Auth ──────────────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session:
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
        rt = db.execute('SELECT COALESCE(SUM(total),0) as s FROM line_items WHERE room_id=?', (room['id'],)).fetchone()['s']
        db.execute('UPDATE rooms SET subtotal=? WHERE id=?', (rt, room['id']))
        total += rt
    db.execute('UPDATE claims SET total_estimate=?, updated_at=CURRENT_TIMESTAMP WHERE id=?', (total, claim_id))
    db.commit()

def get_setting(key, default=''):
    """Read a setting from DB, fall back to default."""
    try:
        db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        row = db.execute('SELECT value FROM settings WHERE key=?', (key,)).fetchone()
        db.close()
        return row['value'] if row else default
    except Exception:
        return default

def set_setting(key, value):
    """Upsert a setting into DB."""
    db = sqlite3.connect(DB_PATH)
    db.execute('INSERT INTO settings (key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
               (key, value))
    db.commit()
    db.close()

def ai_describe_photo(image_path):
    key = get_setting('openrouter_api_key') or OPENROUTER_KEY
    if not key:
        # Try KYS
        # (already tried DB + env above)
        try:
            kys_token = os.environ.get('KYS_API_TOKEN', '')
            kys_url   = os.environ.get('KYS_URL', 'https://ai-api-tracker-production.up.railway.app')
            if kys_token:
                r = _req.post(f'{kys_url}/api/fetch-key',
                              headers={'Authorization': f'Bearer {kys_token}', 'Content-Type': 'application/json'},
                              json={'key': 'openrouter'}, timeout=5)
                d = r.json()
                if d.get('ok'): key = d.get('value', '')
        except Exception:
            pass
    if not key:
        return 'AI description unavailable — add OPENROUTER_API_KEY to Railway.'
    try:
        with open(image_path, 'rb') as f:
            img_b64 = base64.b64encode(f.read()).decode()
        ext = image_path.rsplit('.', 1)[-1].lower()
        mime = f'image/{ext}' if ext != 'jpg' else 'image/jpeg'
        r = _req.post('https://openrouter.ai/api/v1/chat/completions',
            headers={'Authorization': f'Bearer {key}', 'Content-Type': 'application/json'},
            json={
                'model': 'openai/gpt-4o-mini',
                'messages': [{
                    'role': 'user',
                    'content': [
                        {'type': 'text', 'text': 'You are a flood damage assessor. Describe the flood damage visible in this photo in 2-3 sentences. Be specific about what is damaged, the severity, and likely repair needs. Be professional and concise.'},
                        {'type': 'image_url', 'image_url': {'url': f'data:{mime};base64,{img_b64}'}}
                    ]
                }],
                'max_tokens': 200
            }, timeout=30)
        return r.json()['choices'][0]['message']['content']
    except Exception as e:
        return f'AI description failed: {str(e)}'

# ── Routes ────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
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
            WHERE c.adjuster_id=? ORDER BY c.created_at DESC''', (session['user_id'],)).fetchall()
    stats = {
        'total': len(claims),
        'new': sum(1 for c in claims if c['status'] == 'New'),
        'in_progress': sum(1 for c in claims if c['status'] == 'In Progress'),
        'submitted': sum(1 for c in claims if c['status'] == 'Submitted'),
        'closed': sum(1 for c in claims if c['status'] == 'Closed'),
        'pipeline': sum(c['total_estimate'] for c in claims if c['status'] not in ('Closed',)),
    }
    adjusters = []
    if session['role'] == 'admin':
        adjusters = db.execute('SELECT * FROM users ORDER BY name').fetchall()
    return render_template('dashboard.html', claims=claims, stats=stats, adjusters=adjusters)

@app.route('/claims/new', methods=['GET', 'POST'])
@login_required
def new_claim():
    db = get_db()
    if request.method == 'POST':
        claim_num = gen_claim_number()
        adjuster_id = request.form.get('adjuster_id') or session['user_id']
        db.execute('''INSERT INTO claims
            (claim_number, adjuster_id, client_name, client_phone, client_email,
             property_address, flood_date, insurance_company, policy_number, notes)
            VALUES (?,?,?,?,?,?,?,?,?,?)''',
            (claim_num,
             adjuster_id,
             request.form.get('client_name',''),
             request.form.get('client_phone',''),
             request.form.get('client_email',''),
             request.form.get('property_address',''),
             request.form.get('flood_date',''),
             request.form.get('insurance_company',''),
             request.form.get('policy_number',''),
             request.form.get('notes','')))
        db.commit()
        claim = db.execute('SELECT * FROM claims WHERE claim_number=?', (claim_num,)).fetchone()
        flash(f'Claim {claim_num} created!', 'success')
        return redirect(url_for('claim_detail', claim_id=claim['id']))
    adjusters = db.execute('SELECT * FROM users ORDER BY name').fetchall() if session['role'] == 'admin' else []
    return render_template('new_claim.html', adjusters=adjusters)

@app.route('/claims/<int:claim_id>')
@login_required
def claim_detail(claim_id):
    db = get_db()
    claim = db.execute('''SELECT c.*, u.name as adjuster_name
        FROM claims c LEFT JOIN users u ON c.adjuster_id=u.id WHERE c.id=?''', (claim_id,)).fetchone()
    if not claim: flash('Claim not found.', 'error'); return redirect(url_for('dashboard'))
    rooms = db.execute('SELECT * FROM rooms WHERE claim_id=? ORDER BY id', (claim_id,)).fetchall()
    room_data = []
    for room in rooms:
        items = db.execute('SELECT * FROM line_items WHERE room_id=? ORDER BY id', (room['id'],)).fetchall()
        photos = db.execute('SELECT * FROM photos WHERE room_id=? ORDER BY id', (room['id'],)).fetchall()
        room_data.append({'room': room, 'items': items, 'photos': photos})
    unassigned_photos = db.execute('SELECT * FROM photos WHERE claim_id=? AND room_id IS NULL ORDER BY id', (claim_id,)).fetchall()
    recalc_claim(claim_id)
    claim = db.execute('''SELECT c.*, u.name as adjuster_name
        FROM claims c LEFT JOIN users u ON c.adjuster_id=u.id WHERE c.id=?''', (claim_id,)).fetchone()
    return render_template('claim_detail.html', claim=claim, room_data=room_data, unassigned_photos=unassigned_photos)

@app.route('/claims/<int:claim_id>/status', methods=['POST'])
@login_required
def update_status(claim_id):
    status = request.form.get('status')
    get_db().execute('UPDATE claims SET status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?', (status, claim_id))
    get_db().commit()
    return redirect(url_for('claim_detail', claim_id=claim_id))

@app.route('/claims/<int:claim_id>/room/add', methods=['POST'])
@login_required
def add_room(claim_id):
    name = request.form.get('room_name', '').strip()
    if name:
        get_db().execute('INSERT INTO rooms (claim_id, name) VALUES (?,?)', (claim_id, name))
        get_db().commit()
    return redirect(url_for('claim_detail', claim_id=claim_id))

@app.route('/rooms/<int:room_id>/item/add', methods=['POST'])
@login_required
def add_item(room_id):
    db = get_db()
    room = db.execute('SELECT * FROM rooms WHERE id=?', (room_id,)).fetchone()
    desc      = request.form.get('description','')
    qty       = float(request.form.get('quantity', 1) or 1)
    unit      = request.form.get('unit','ea')
    unit_cost = float(request.form.get('unit_cost', 0) or 0)
    total     = qty * unit_cost
    db.execute('INSERT INTO line_items (room_id, description, quantity, unit, unit_cost, total) VALUES (?,?,?,?,?,?)',
               (room_id, desc, qty, unit, unit_cost, total))
    db.commit()
    recalc_claim(room['claim_id'])
    return redirect(url_for('claim_detail', claim_id=room['claim_id']))

@app.route('/items/<int:item_id>/delete', methods=['POST'])
@login_required
def delete_item(item_id):
    db = get_db()
    item = db.execute('SELECT r.claim_id FROM line_items li JOIN rooms r ON li.room_id=r.id WHERE li.id=?', (item_id,)).fetchone()
    db.execute('DELETE FROM line_items WHERE id=?', (item_id,))
    db.commit()
    if item: recalc_claim(item['claim_id'])
    return jsonify({'ok': True})

@app.route('/claims/<int:claim_id>/photo/upload', methods=['POST'])
@login_required
def upload_photo(claim_id):
    db = get_db()
    file    = request.files.get('photo')
    room_id = request.form.get('room_id') or None
    caption = request.form.get('caption', '')
    if not file or not allowed_file(file.filename):
        flash('Invalid file type.', 'error')
        return redirect(url_for('claim_detail', claim_id=claim_id))
    ext      = file.filename.rsplit('.', 1)[1].lower()
    filename = f'{secrets.token_hex(12)}.{ext}'
    save_path = os.path.join(UPLOAD_DIR, filename)
    file.save(save_path)
    # AI describe
    ai_desc = ai_describe_photo(save_path)
    db.execute('INSERT INTO photos (claim_id, room_id, filename, caption, ai_description) VALUES (?,?,?,?,?)',
               (claim_id, room_id, filename, caption, ai_desc))
    db.commit()
    flash('Photo uploaded and AI analysis complete!', 'success')
    return redirect(url_for('claim_detail', claim_id=claim_id))

@app.route('/uploads/<filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(UPLOAD_DIR, filename)

@app.route('/claims/<int:claim_id>/report')
@login_required
def report(claim_id):
    db = get_db()
    claim = db.execute('''SELECT c.*, u.name as adjuster_name, u.email as adjuster_email
        FROM claims c LEFT JOIN users u ON c.adjuster_id=u.id WHERE c.id=?''', (claim_id,)).fetchone()
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
    return render_template('report.html', claim=claim, room_data=room_data, unassigned_photos=unassigned_photos,
                           generated=datetime.datetime.now().strftime('%B %d, %Y %I:%M %p'))

# ── Admin: Settings ──────────────────────────────────────────────────────────

@app.route('/admin/settings', methods=['GET', 'POST'])
@login_required
@admin_required
def settings():
    saved = False
    if request.method == 'POST':
        openrouter_key = request.form.get('openrouter_api_key', '').strip()
        if openrouter_key:
            set_setting('openrouter_api_key', openrouter_key)
        elif request.form.get('clear_openrouter'):
            set_setting('openrouter_api_key', '')
        flash('Settings saved!', 'success')
        return redirect(url_for('settings'))
    current_key = get_setting('openrouter_api_key')
    # Mask key for display
    masked_key = ''
    if current_key:
        masked_key = current_key[:8] + '•' * (len(current_key) - 12) + current_key[-4:] if len(current_key) > 12 else '••••••••'
    env_key_set = bool(OPENROUTER_KEY)
    return render_template('settings.html',
                           masked_key=masked_key,
                           key_is_set=bool(current_key),
                           env_key_set=env_key_set)

# ── Admin: Team Management ────────────────────────────────────────────────────
@app.route('/admin/team')
@login_required
@admin_required
def team():
    users = get_db().execute('SELECT u.*, (SELECT COUNT(*) FROM claims WHERE adjuster_id=u.id) as claim_count FROM users u ORDER BY u.name').fetchall()
    return render_template('team.html', users=users)

@app.route('/admin/team/add', methods=['POST'])
@login_required
@admin_required
def add_team_member():
    db = get_db()
    email = request.form.get('email','').strip().lower()
    name  = request.form.get('name','').strip()
    pw    = request.form.get('password','').strip()
    role  = request.form.get('role','adjuster')
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
    get_db().execute('DELETE FROM users WHERE id=?', (user_id,))
    get_db().commit()
    flash('Team member removed.', 'success')
    return redirect(url_for('team'))

@app.route('/health')
def health():
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
