import os, sqlite3, secrets, hashlib, json, datetime, pathlib, base64
from datetime import timedelta
from functools import wraps
from flask import (Flask, render_template, request, redirect, url_for,
                   session, flash, jsonify, g, send_from_directory)
from werkzeug.utils import secure_filename
import requests as _req

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
        _SECRET_KEY = secrets.token_hex(32)   # last resort

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
        db.execute('''INSERT INTO claims
            (claim_number, adjuster_id, client_name, client_phone, client_email,
             property_address, flood_date, insurance_company, policy_number, notes)
            VALUES (?,?,?,?,?,?,?,?,?,?)''',
            (claim_num,
             adjuster_id,
             request.form.get('client_name', ''),
             request.form.get('client_phone', ''),
             request.form.get('client_email', ''),
             request.form.get('property_address', ''),
             request.form.get('flood_date', ''),
             request.form.get('insurance_company', ''),
             request.form.get('policy_number', ''),
             request.form.get('notes', '')))
        db.commit()
        claim = db.execute('SELECT * FROM claims WHERE claim_number=?', (claim_num,)).fetchone()
        flash(f'Claim {claim_num} created!', 'success')
        return redirect(url_for('claim_detail', claim_id=claim['id']))
    adjusters = db.execute('SELECT * FROM users ORDER BY name').fetchall() \
                if session['role'] == 'admin' else []
    return render_template('new_claim.html', adjusters=adjusters)

@app.route('/claims/<int:claim_id>')
@login_required
def claim_detail(claim_id):
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

@app.route('/claims/<int:claim_id>/status', methods=['POST'])
@login_required
def update_status(claim_id):
    db = get_db()
    status = request.form.get('status')
    db.execute('UPDATE claims SET status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?',
               (status, claim_id))
    db.commit()
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
    db.execute('UPDATE claims SET status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?', (status, claim_id))
    db.commit()
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

@app.route('/health')
def health():
    return jsonify({'status': 'ok'})

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
