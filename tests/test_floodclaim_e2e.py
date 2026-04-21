"""
FloodClaim Pro — Playwright E2E + Advanced Test Suite
Catches what pure requests-based tests miss:
  - Real browser JS errors
  - Form submission feedback (flash messages, DOM updates)
  - AI Estimate modal rendering
  - Room add/delete full UI flow
  - Schema drift detection
  - sqlite3.Row .get() anti-pattern
  - Jinja2 key/method name collisions

Run: pytest tests/test_floodclaim_e2e.py -v --tb=short
Requires: pip install playwright pytest-playwright && playwright install chromium
"""
import pytest
import requests
import sqlite3
import os
import re
import ast
import time

from playwright.sync_api import Page, expect, sync_playwright

BASE_URL       = os.environ.get('FLOODCLAIM_URL',   'https://billy-floods.up.railway.app')
ADMIN_EMAIL    = os.environ.get('ADMIN_EMAIL',       'admin@floodclaimpro.com')
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD',    'admin1234')
APP_PY         = os.path.join(os.path.dirname(__file__), '..', 'app.py')
TEMPLATES_DIR  = os.path.join(os.path.dirname(__file__), '..', 'templates')


# ── Shared fixtures ───────────────────────────────────────────────────────────

@pytest.fixture(scope='module')
def api_session():
    """Authenticated requests.Session for API-level checks."""
    s = requests.Session()
    r = s.post(f'{BASE_URL}/login',
               data={'email': ADMIN_EMAIL, 'password': ADMIN_PASSWORD},
               allow_redirects=True, timeout=15)
    assert '/dashboard' in r.url or 'dashboard' in r.text.lower()
    return s

@pytest.fixture(scope='module')
def test_claim(api_session):
    """Create a disposable test claim, yield its ID, then delete it."""
    import secrets as _s
    r = api_session.post(f'{BASE_URL}/claims/new', data={
        'client_name':       f'E2E-Test-{_s.token_hex(3)}',
        'property_address':  '999 E2E Test Ln, Liberty, NC 27298',
        'flood_date':        '2026-04-01',
        'claim_number':      f'E2E-{_s.token_hex(4)}',
        'insurance_company': 'E2E Insurance',
        'flood_source':      'Test Rain',
        'water_category':    '1',
        'water_class':       '2',
        'water_depth_in':    '4',
    }, allow_redirects=True, timeout=15)
    assert r.status_code == 200
    m = re.search(r'/claims/(\d+)', r.url)
    assert m, f'Could not parse claim ID from {r.url}'
    claim_id = int(m.group(1))
    yield claim_id
    try:
        api_session.post(f'{BASE_URL}/claims/{claim_id}/delete', timeout=10)
    except Exception:
        pass

@pytest.fixture(scope='module')
def browser_ctx():
    """Headless Chromium context, logged in as admin."""
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=True)
        ctx     = browser.new_context(viewport={'width': 1280, 'height': 900})
        page    = ctx.new_page()
        # Log in
        page.goto(f'{BASE_URL}/login')
        page.fill('input[name="email"]',    ADMIN_EMAIL)
        page.fill('input[name="password"]', ADMIN_PASSWORD)
        page.click('button[type="submit"]')
        page.wait_for_url(re.compile(r'.*/dashboard.*'), timeout=15000)
        yield ctx
        browser.close()

@pytest.fixture()
def page(browser_ctx):
    p = browser_ctx.new_page()
    yield p
    p.close()


# ══════════════════════════════════════════════════════════════════════════════
# STATIC CODE ANALYSIS  (catches bugs before they ever reach production)
# ══════════════════════════════════════════════════════════════════════════════
class TestStaticAnalysis:

    def test_no_sqlite_row_get_calls(self):
        """
        sqlite3.Row objects don't have .get() — only dicts do.
        Any row.get('col', default) will crash with AttributeError in Python 3.13.
        We must convert to dict() before calling .get().
        """
        with open(APP_PY) as f:
            source = f.read()
        tree  = ast.parse(source)
        hits  = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func = node.func
                if isinstance(func, ast.Attribute) and func.attr == 'get':
                    # Check if it looks like row.get(...)
                    obj = func.value
                    if isinstance(obj, ast.Name):
                        name = obj.id.lower()
                        # flag variables that sound like DB rows
                        if any(k in name for k in ('claim', 'photo', 'room', 'item',
                                                     'user', 'row', 'result', 'record')):
                            hits.append(f'Line {node.lineno}: {obj.id}.get(...)')
        # Now verify each hit is preceded by dict() conversion in context
        lines = source.splitlines()
        unprotected = []
        for hit in hits:
            lineno = int(re.search(r'Line (\d+)', hit).group(1)) - 1
            varname = re.search(r': (\w+)\.get', hit).group(1)
            # Look back up to 10 lines for dict(varname) or varname = dict(
            context = '\n'.join(lines[max(0, lineno-15):lineno])
            if f'dict({varname})' not in context and f'{varname} = dict(' not in context:
                unprotected.append(hit)
        assert not unprotected, (
            'sqlite3.Row .get() calls found without dict() conversion:\n'
            + '\n'.join(unprotected)
            + '\nFix: add `varname = dict(varname)` right after .fetchone()'
        )

    def test_no_jinja2_reserved_key_names(self):
        """
        Passing dicts with keys 'items', 'values', 'keys', 'update' to Jinja2
        templates causes the template to resolve to the Python dict method
        instead of the value. Detect room_data dicts with forbidden key names.
        """
        with open(APP_PY) as f:
            source = f.read()
        forbidden = ['items', 'values', 'keys', 'update', 'get', 'pop']
        hits = []
        for m in re.finditer(r"room_data\.append\(\{([^}]+)\}\)", source):
            keys_str = m.group(1)
            for key in re.findall(r"'(\w+)'", keys_str):
                if key in forbidden:
                    hits.append(f'room_data.append({{"{key}": ...}}) — "{key}" is a Python dict method name')
        assert not hits, (
            'Jinja2 key/method name collision in room_data dicts:\n'
            + '\n'.join(hits)
            + '\nRename to e.g. "line_items", "room_photos" to avoid dict method shadowing'
        )

    def test_no_hardcoded_tokens_in_any_file(self):
        """Scan all templates and app.py for any hardcoded bearer tokens."""
        suspicious_patterns = [
            r'Bearer [A-Za-z0-9+/=_\-]{30,}',   # hardcoded bearer token
            r'ghp_[A-Za-z0-9]{36}',              # GitHub PAT
            r'glpat-[A-Za-z0-9_\-]{20,}',        # GitLab PAT
        ]
        files_to_check = [APP_PY]
        for fname in os.listdir(TEMPLATES_DIR):
            if fname.endswith('.html'):
                files_to_check.append(os.path.join(TEMPLATES_DIR, fname))
        hits = []
        for fpath in files_to_check:
            with open(fpath) as f:
                content = f.read()
            for pattern in suspicious_patterns:
                for m in re.finditer(pattern, content):
                    hits.append(f'{os.path.basename(fpath)}: {m.group(0)[:40]}...')
        assert not hits, 'Hardcoded tokens found:\n' + '\n'.join(hits)

    def test_all_routes_have_login_required(self):
        """Every POST route that modifies data must have @login_required or willie_auth()."""
        with open(APP_PY) as f:
            source = f.read()
        # Find all POST routes that are NOT willie API routes
        route_blocks = re.findall(
            r"(@app\.route\('[^']+',\s*methods=\[[^\]]*'POST'[^\]]*\]\)\n(?:@\w+\n)*def \w+)",
            source
        )
        # Routes that intentionally don't use @login_required
        # (they use willie_auth, session manually, or are public by design)
        allowed_without_decorator = {
            'login',           # public — it IS the auth endpoint
            'ai_estimate',     # uses session check + willie_auth fallback manually
            'update_claim_estimate',  # uses session + willie_auth manually
            'sign_claim',      # client-facing portal endpoint
        }
        unprotected = []
        for block in route_blocks:
            if '/willie/' in block:
                continue  # willie routes use willie_auth() — skip
            if '@login_required' not in block:
                fn_match = re.search(r'def (\w+)', block)
                fn_name  = fn_match.group(1) if fn_match else '?'
                if fn_name not in allowed_without_decorator:
                    unprotected.append(fn_name)
        assert not unprotected, (
            'POST routes missing @login_required:\n' + '\n'.join(unprotected)
        )

    def test_schema_defines_all_expected_columns(self):
        """Every column used in the code must be defined in CREATE TABLE statements."""
        with open(APP_PY) as f:
            source = f.read()
        required_photo_cols  = ['id', 'claim_id', 'room_id', 'filename', 'caption', 'ai_description']
        required_room_cols   = ['id', 'claim_id', 'name', 'subtotal']
        required_claims_cols = ['id', 'claim_number', 'client_name', 'total_estimate',
                                 'flood_source', 'water_category', 'flood_zone']

        for col in required_photo_cols:
            assert col in source, f'Missing column "{col}" in photos schema or migrations'
        for col in required_room_cols:
            assert col in source, f'Missing column "{col}" in rooms schema'
        for col in required_claims_cols:
            assert col in source, f'Missing column "{col}" in claims schema'

    def test_migrate_functions_cover_all_tables(self):
        """A migration function must exist for every table that gets ALTER TABLE changes."""
        with open(APP_PY) as f:
            source = f.read()
        tables_altered = re.findall(r'ALTER TABLE (\w+)', source)
        for table in set(tables_altered):
            assert f'migrate_{table}' in source or f'migrate_new' in source, \
                f'ALTER TABLE {table} has no corresponding migrate_{table}() function'


# ══════════════════════════════════════════════════════════════════════════════
# SCHEMA DRIFT DETECTION  (compares live DB schema vs code expectations)
# ══════════════════════════════════════════════════════════════════════════════
class TestSchemaDrift:
    """
    Connects to the local DB and checks that every column the code
    references actually exists. Catches the 'column not found' 500s
    before they hit production.
    """
    DB_PATH = '/data/floodclaim.db'

    def _get_columns(self, table):
        db   = sqlite3.connect(self.DB_PATH)
        cols = [r[1] for r in db.execute(f'PRAGMA table_info({table})').fetchall()]
        db.close()
        return cols

    def test_photos_has_all_required_columns(self):
        required = ['id', 'claim_id', 'room_id', 'filename', 'caption', 'ai_description', 'created_at']
        actual   = self._get_columns('photos')
        missing  = [c for c in required if c not in actual]
        assert not missing, f'photos table missing columns: {missing}\nActual: {actual}'

    def test_rooms_has_all_required_columns(self):
        required = ['id', 'claim_id', 'name', 'subtotal', 'created_at']
        actual   = self._get_columns('rooms')
        missing  = [c for c in required if c not in actual]
        assert not missing, f'rooms table missing columns: {missing}\nActual: {actual}'

    def test_claims_has_all_required_columns(self):
        required = [
            'id', 'claim_number', 'adjuster_id', 'client_name', 'property_address',
            'flood_date', 'flood_source', 'water_category', 'water_class', 'water_depth_in',
            'insurance_company', 'total_estimate', 'status', 'flood_zone', 'created_at', 'updated_at'
        ]
        actual  = self._get_columns('claims')
        missing = [c for c in required if c not in actual]
        assert not missing, f'claims table missing columns: {missing}\nActual: {actual}'

    def test_no_orphaned_rooms(self):
        """Every room must reference a valid claim_id."""
        db = sqlite3.connect(self.DB_PATH)
        orphans = db.execute(
            'SELECT r.id FROM rooms r LEFT JOIN claims c ON r.claim_id=c.id WHERE c.id IS NULL'
        ).fetchall()
        db.close()
        assert not orphans, f'Orphaned rooms found (no parent claim): {[r[0] for r in orphans]}'

    def test_no_orphaned_line_items(self):
        """Every line item must reference a valid room_id."""
        db = sqlite3.connect(self.DB_PATH)
        orphans = db.execute(
            'SELECT li.id FROM line_items li LEFT JOIN rooms r ON li.room_id=r.id WHERE r.id IS NULL'
        ).fetchall()
        db.close()
        assert not orphans, f'Orphaned line_items (no parent room): {[r[0] for r in orphans]}'

    def test_settings_table_exists(self):
        db   = sqlite3.connect(self.DB_PATH)
        tbls = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]
        db.close()
        assert 'settings' in tbls, 'settings table missing from DB'


# ══════════════════════════════════════════════════════════════════════════════
# PLAYWRIGHT E2E — Real browser tests
# ══════════════════════════════════════════════════════════════════════════════
class TestE2ELogin:
    """Uses fresh unauthenticated browser context — does NOT use the shared logged-in fixture."""

    @pytest.fixture()
    def fresh_page(self):
        """Unauthenticated page for login flow tests."""
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            ctx     = browser.new_context(viewport={'width': 1280, 'height': 900})
            page    = ctx.new_page()
            yield page
            browser.close()

    def test_login_page_renders(self, fresh_page: Page):
        fresh_page.goto(f'{BASE_URL}/login')
        expect(fresh_page.locator('input[name="email"]')).to_be_visible()
        expect(fresh_page.locator('input[name="password"]')).to_be_visible()
        expect(fresh_page.locator('button[type="submit"]')).to_be_visible()

    def test_bad_login_shows_error(self, fresh_page: Page):
        fresh_page.goto(f'{BASE_URL}/login')
        fresh_page.fill('input[name="email"]', 'wrong@wrong.com')
        fresh_page.fill('input[name="password"]', 'wrongpassword')
        fresh_page.click('button[type="submit"]')
        fresh_page.wait_for_load_state('networkidle')
        assert '/login' in fresh_page.url or '/dashboard' not in fresh_page.url
        content = fresh_page.content()
        assert 'invalid' in content.lower() or 'incorrect' in content.lower() \
               or 'wrong' in content.lower() or fresh_page.url.endswith('/login'), \
               'Bad login did not show error message'

    def test_good_login_reaches_dashboard(self, fresh_page: Page):
        fresh_page.goto(f'{BASE_URL}/login')
        fresh_page.fill('input[name="email"]', ADMIN_EMAIL)
        fresh_page.fill('input[name="password"]', ADMIN_PASSWORD)
        fresh_page.click('button[type="submit"]')
        fresh_page.wait_for_url(re.compile(r'.*/dashboard.*'), timeout=15000)
        expect(fresh_page.locator('body')).to_be_visible()
        assert 'dashboard' in fresh_page.url.lower()


class TestE2EDashboard:

    def test_dashboard_loads_with_claims(self, page: Page):
        """page fixture is already authenticated via browser_ctx."""
        page.goto(f'{BASE_URL}/dashboard', wait_until='networkidle')
        expect(page.locator('body')).to_be_visible()
        content = page.content()
        assert 'claim' in content.lower() or 'dashboard' in content.lower()

    def test_no_js_errors_on_dashboard(self, page: Page):
        errors = []
        page.on('pageerror', lambda e: errors.append(str(e)))
        page.goto(f'{BASE_URL}/dashboard', wait_until='networkidle')
        assert not errors, f'JS errors on dashboard:\n' + '\n'.join(errors)


class TestE2EClaimDetail:

    def _login_and_goto_claim(self, page: Page, claim_id: int):
        """page is already authenticated via browser_ctx fixture."""
        page.goto(f'{BASE_URL}/claims/{claim_id}', wait_until='networkidle')

    def test_claim_detail_no_js_errors(self, page: Page, test_claim: int):
        errors = []
        page.on('pageerror', lambda e: errors.append(str(e)))
        self._login_and_goto_claim(page, test_claim)
        assert f'/claims/{test_claim}' in page.url, f'Did not reach claim, URL={page.url}'
        assert not errors, 'JS errors on claim detail:\n' + '\n'.join(errors)

    def test_add_room_via_browser(self, page: Page, test_claim: int):
        """Fill in room name and submit — room should appear on page."""
        errors = []
        page.on('pageerror', lambda e: errors.append(str(e)))
        self._login_and_goto_claim(page, test_claim)
        page.fill('input[name="room_name"]', 'Master Bedroom')
        page.click('button[type="submit"]:has-text("Add Room")')
        page.wait_for_load_state('networkidle')
        assert not errors, f'JS errors after Add Room: {errors}'
        expect(page.get_by_text('Master Bedroom')).to_be_visible()

    def test_delete_room_via_browser(self, page: Page, test_claim: int):
        """Add a room then delete it — room should disappear."""
        errors = []
        page.on('pageerror', lambda e: errors.append(str(e)))
        self._login_and_goto_claim(page, test_claim)
        # Add a room we'll delete
        page.fill('input[name="room_name"]', 'Room To Delete')
        page.click('button[type="submit"]:has-text("Add Room")')
        page.wait_for_load_state('networkidle')
        expect(page.get_by_text('Room To Delete')).to_be_visible()
        # Click Remove on that room — handle the confirm dialog
        page.on('dialog', lambda d: d.accept())
        page.get_by_role('button', name=re.compile('Remove', re.I)).first.click()
        page.wait_for_load_state('networkidle')
        assert not errors, f'JS errors after Delete Room: {errors}'
        assert 'Room To Delete' not in page.content(), 'Room still visible after delete'

    def test_ai_estimate_button_visible(self, page: Page, test_claim: int):
        """AI Estimate button must be present and visible."""
        self._login_and_goto_claim(page, test_claim)
        btn = page.get_by_role('button', name=re.compile('AI Estimate', re.I))
        expect(btn).to_be_visible()

    def test_ai_estimate_opens_modal(self, page: Page, test_claim: int):
        """Clicking AI Estimate must open the modal (not crash with JS error)."""
        errors = []
        page.on('pageerror', lambda e: errors.append(str(e)))
        self._login_and_goto_claim(page, test_claim)
        page.click('button:has-text("AI Estimate")')
        # Modal should appear
        modal = page.locator('#estimateModal')
        expect(modal).to_be_visible(timeout=5000)
        assert not errors, f'JS errors when opening AI Estimate modal: {errors}'

    def test_ai_estimate_returns_result_or_config_error(self, page: Page, test_claim: int):
        """
        AI Estimate must either:
        a) Return an actual estimate (OpenRouter key configured), OR
        b) Show a config error ('API key not configured') — never a parse crash.
        A JS parse error ('Unexpected token') or empty modal = FAIL.
        """
        errors = []
        page.on('pageerror', lambda e: errors.append(str(e)))
        self._login_and_goto_claim(page, test_claim)
        page.click('button:has-text("AI Estimate")')
        modal = page.locator('#estimateModal')
        expect(modal).to_be_visible(timeout=5000)
        # Wait up to 60s for the loading state to resolve
        page.wait_for_function(
            """() => {
                const el = document.getElementById('estimateContent');
                if (!el) return false;
                const text = el.innerText || '';
                return text.length > 10 && !text.includes('Analyzing photos');
            }""",
            timeout=60000
        )
        content_text = page.locator('#estimateContent').inner_text()
        # Must NOT be a JS crash
        assert 'Unexpected token' not in content_text, \
            f'AI Estimate got JS parse error: {content_text[:200]}'
        assert 'SyntaxError' not in content_text, \
            f'AI Estimate got SyntaxError: {content_text[:200]}'
        # Must be either real content OR a config message — not empty
        assert len(content_text.strip()) > 10, \
            f'AI Estimate modal is empty or too short: "{content_text}"'
        assert not errors, f'JS errors during AI Estimate: {errors}'

    def test_add_line_item_via_browser(self, page: Page, test_claim: int):
        """Add a room then add a line item — item must appear in the table."""
        errors = []
        page.on('pageerror', lambda e: errors.append(str(e)))
        self._login_and_goto_claim(page, test_claim)
        # Make sure we have a room
        rooms_visible = page.locator('.room-block').count()
        if rooms_visible == 0:
            page.fill('input[name="room_name"]', 'Test Room')
            page.click('button[type="submit"]:has-text("Add Room")')
            page.wait_for_load_state('networkidle')
        # Fill line item form in the first room
        page.locator('input[name="description"]').first.fill('Water damage repair')
        page.locator('input[name="quantity"]').first.fill('5')
        page.locator('input[name="unit_cost"]').first.fill('75.00')
        page.locator('button[type="submit"]:has-text("Add")').first.click()
        page.wait_for_load_state('networkidle')
        assert not errors, f'JS errors after Add Item: {errors}'
        assert 'Water damage repair' in page.content(), \
            'Line item not visible after adding'


# ══════════════════════════════════════════════════════════════════════════════
# API REGRESSION  (things that broke tonight — must never break again)
# ══════════════════════════════════════════════════════════════════════════════
class TestAPIRegression:

    def test_all_claims_return_200(self, api_session):
        """Every claim page must return 200 — no 500s ever."""
        r = api_session.get(f'{BASE_URL}/dashboard', timeout=10)
        claim_ids = list(set(re.findall(r'/claims/(\d+)', r.text)))[:20]
        failures  = []
        for cid in claim_ids:
            cr = api_session.get(f'{BASE_URL}/claims/{cid}', timeout=15)
            if cr.status_code != 200:
                failures.append(f'Claim {cid}: HTTP {cr.status_code}')
        assert not failures, 'Claims returning errors:\n' + '\n'.join(failures)

    def test_add_room_returns_200(self, api_session, test_claim):
        r = api_session.post(
            f'{BASE_URL}/claims/{test_claim}/room/add',
            data={'room_name': 'Regression Test Room'},
            allow_redirects=True, timeout=15
        )
        assert r.status_code == 200, f'Add Room: HTTP {r.status_code}'
        assert 'Regression Test Room' in r.text

    def test_delete_room_works(self, api_session, test_claim):
        """Add a room then delete it via API."""
        # Add
        r = api_session.post(
            f'{BASE_URL}/claims/{test_claim}/room/add',
            data={'room_name': 'Room For Deletion'},
            allow_redirects=True, timeout=15
        )
        assert r.status_code == 200
        room_id_match = re.search(r'/rooms/(\d+)/delete', r.text)
        assert room_id_match, 'Could not find delete room form in page'
        room_id = int(room_id_match.group(1))
        # Delete
        dr = api_session.post(
            f'{BASE_URL}/rooms/{room_id}/delete',
            allow_redirects=True, timeout=15
        )
        assert dr.status_code == 200, f'Delete Room: HTTP {dr.status_code}'
        assert 'Room For Deletion' not in dr.text

    def test_ai_estimate_json_response(self, api_session, test_claim):
        """AI estimate must return valid JSON — never HTML."""
        r = api_session.post(
            f'{BASE_URL}/claims/{test_claim}/ai-estimate',
            headers={'Content-Type': 'application/json'},
            timeout=60
        )
        assert r.status_code in (200, 400), f'Unexpected status: {r.status_code}'
        try:
            data = r.json()
        except Exception:
            pytest.fail(f'AI estimate returned non-JSON. Status={r.status_code}, body: {r.text[:300]}')
        assert 'ok' in data

    def test_update_estimate_json_response(self, api_session, test_claim):
        r = api_session.post(
            f'{BASE_URL}/claims/{test_claim}/update-estimate',
            json={'total_estimate': 9999.00}, timeout=15
        )
        try:
            data = r.json()
        except Exception:
            pytest.fail(f'update-estimate returned non-JSON: {r.text[:200]}')
        assert 'ok' in data

    def test_unauthenticated_api_returns_json_401(self):
        """Unauthenticated AI estimate must return JSON 401, not HTML redirect."""
        r = requests.post(
            f'{BASE_URL}/claims/1/ai-estimate',
            headers={'Content-Type': 'application/json'},
            timeout=10
        )
        assert r.status_code == 401
        data = r.json()
        assert data.get('ok') is False
        assert 'error' in data

    def test_settings_page_accessible(self, api_session):
        r = api_session.get(f'{BASE_URL}/admin/settings', timeout=10)
        assert r.status_code == 200
        assert 'openrouter' in r.text.lower() or 'api' in r.text.lower()

    def test_health_endpoint(self):
        r = requests.get(f'{BASE_URL}/health', timeout=10)
        assert r.status_code == 200
        assert r.json().get('status') == 'ok'


# ══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════════
def pytest_terminal_summary(terminalreporter, exitstatus, config):
    passed = len(terminalreporter.stats.get('passed', []))
    failed = len(terminalreporter.stats.get('failed', []))
    errors = len(terminalreporter.stats.get('error',  []))
    total  = passed + failed + errors
    print(f'\n{"="*60}')
    print(f'🤖 FLOODCLAIM PRO — FULL E2E + STATIC ANALYSIS SUITE')
    print(f'{"="*60}')
    print(f'✅ Passed:  {passed}/{total}')
    if failed: print(f'❌ Failed:  {failed}/{total}')
    if errors:  print(f'💥 Errors:  {errors}/{total}')
    print(f'{"="*60}\n')
