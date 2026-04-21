"""
FloodClaim Pro — Integration Test Suite
Run: pytest tests/test_floodclaim.py -v
Catches: auth failures, 500s, DB migration gaps, Add Room, AI Estimate, photo handling
"""
import pytest
import requests
import sqlite3
import os
import tempfile
import sys

# ── Config ────────────────────────────────────────────────────────────────────
BASE_URL      = os.environ.get('FLOODCLAIM_URL', 'https://billy-floods.up.railway.app')
ADMIN_EMAIL   = os.environ.get('ADMIN_EMAIL',    'admin@floodclaimpro.com')
ADMIN_PASSWORD= os.environ.get('ADMIN_PASSWORD', 'admin1234')

# ── Session fixture (authenticated) ──────────────────────────────────────────
@pytest.fixture(scope='module')
def session():
    """Return a requests.Session logged in as admin."""
    s = requests.Session()
    r = s.post(f'{BASE_URL}/login',
               data={'email': ADMIN_EMAIL, 'password': ADMIN_PASSWORD},
               allow_redirects=True, timeout=15)
    assert r.status_code == 200, f'Login failed: HTTP {r.status_code}'
    assert '/dashboard' in r.url or 'dashboard' in r.text.lower(), \
        f'Login did not reach dashboard. URL={r.url}'
    return s

@pytest.fixture(scope='module')
def test_claim_id(session):
    """Create a fresh test claim and return its ID. Deleted after module."""
    r = session.post(f'{BASE_URL}/claims/new', data={
        'client_name':       'Echo Test Client',
        'property_address':  '123 Test St, Liberty, NC 27298',
        'flood_date':        '2026-04-01',
        'claim_number':      'ECHO-TEST-001',
        'insurance_company': 'Test Insurance Co',
        'flood_source':      'Heavy Rain',
        'water_category':    '1',
        'water_class':       '2',
        'water_depth_in':    '6',
    }, allow_redirects=True, timeout=15)
    assert r.status_code == 200, f'Create claim failed: HTTP {r.status_code}'
    # Extract claim ID from URL (redirects to /claims/<id>)
    import re
    m = re.search(r'/claims/(\d+)', r.url)
    assert m, f'Could not find claim ID in URL: {r.url}'
    claim_id = int(m.group(1))
    yield claim_id
    # Cleanup — delete the test claim
    try:
        session.post(f'{BASE_URL}/claims/{claim_id}/delete', timeout=10)
    except Exception:
        pass  # Best effort


# ══════════════════════════════════════════════════════════════════════════════
# 1. HEALTH & AVAILABILITY
# ══════════════════════════════════════════════════════════════════════════════
class TestHealth:

    def test_health_endpoint(self):
        """GET /health must return {"status":"ok"}."""
        r = requests.get(f'{BASE_URL}/health', timeout=10)
        assert r.status_code == 200, f'Health check failed: {r.status_code}'
        data = r.json()
        assert data.get('status') == 'ok', f'Health status: {data}'

    def test_login_page_loads(self):
        """Login page must return 200."""
        r = requests.get(f'{BASE_URL}/login', timeout=10)
        assert r.status_code == 200

    def test_unauthenticated_dashboard_redirects(self):
        """Dashboard without session must redirect to login, not 500."""
        r = requests.get(f'{BASE_URL}/dashboard', allow_redirects=False, timeout=10)
        assert r.status_code in (301, 302), \
            f'Expected redirect, got {r.status_code}'
        assert 'login' in r.headers.get('location', '').lower()

    def test_unauthenticated_claim_redirects_not_500(self):
        """Unauthenticated /claims/1 must redirect, not 500."""
        r = requests.get(f'{BASE_URL}/claims/1', allow_redirects=False, timeout=10)
        assert r.status_code in (301, 302), \
            f'Expected redirect, got {r.status_code}'


# ══════════════════════════════════════════════════════════════════════════════
# 2. AUTHENTICATION
# ══════════════════════════════════════════════════════════════════════════════
class TestAuth:

    def test_login_success(self, session):
        """Logged-in session can reach dashboard."""
        r = session.get(f'{BASE_URL}/dashboard', timeout=10)
        assert r.status_code == 200, f'Dashboard returned {r.status_code}'
        assert 'claim' in r.text.lower() or 'dashboard' in r.text.lower()

    def test_bad_credentials_rejected(self):
        """Wrong password must not log in."""
        s = requests.Session()
        r = s.post(f'{BASE_URL}/login',
                   data={'email': ADMIN_EMAIL, 'password': 'WRONG_PASSWORD'},
                   allow_redirects=True, timeout=10)
        assert '/dashboard' not in r.url, 'Bad credentials reached dashboard!'

    def test_api_endpoints_return_json_on_auth_failure(self):
        """AI estimate endpoint must return JSON 401, not HTML redirect."""
        r = requests.post(f'{BASE_URL}/claims/1/ai-estimate',
                          headers={'Content-Type': 'application/json'},
                          timeout=10)
        assert r.status_code == 401, \
            f'Expected 401, got {r.status_code}'
        data = r.json()
        assert 'error' in data, 'Auth failure response missing error field'
        assert data.get('ok') is False


# ══════════════════════════════════════════════════════════════════════════════
# 3. CLAIM DETAIL — NO 500s
# ══════════════════════════════════════════════════════════════════════════════
class TestClaimDetail:

    def test_claim_detail_loads(self, session, test_claim_id):
        """Claim detail page must return 200, not 500."""
        r = session.get(f'{BASE_URL}/claims/{test_claim_id}', timeout=15)
        assert r.status_code == 200, \
            f'Claim detail returned {r.status_code} — possible 500 / DB migration issue'
        assert 'Echo Test Client' in r.text

    def test_all_existing_claims_load(self, session):
        """Every claim that exists must return 200, not 500."""
        r = session.get(f'{BASE_URL}/dashboard', timeout=10)
        assert r.status_code == 200
        import re
        claim_ids = re.findall(r'/claims/(\d+)', r.text)
        claim_ids = list(set(claim_ids))[:10]  # test up to 10 claims
        failures = []
        for cid in claim_ids:
            cr = session.get(f'{BASE_URL}/claims/{cid}', timeout=15)
            if cr.status_code != 200:
                failures.append(f'Claim {cid}: HTTP {cr.status_code}')
        assert not failures, 'Some claims returned errors:\n' + '\n'.join(failures)


# ══════════════════════════════════════════════════════════════════════════════
# 4. ADD ROOM
# ══════════════════════════════════════════════════════════════════════════════
class TestAddRoom:

    def test_add_room_succeeds(self, session, test_claim_id):
        """POST /claims/<id>/room/add must create a room and redirect back."""
        r = session.post(
            f'{BASE_URL}/claims/{test_claim_id}/room/add',
            data={'room_name': 'Living Room'},
            allow_redirects=True, timeout=15
        )
        assert r.status_code == 200, f'Add Room returned {r.status_code}'
        assert 'Living Room' in r.text, \
            'Room name not visible after adding — room may not have been saved'

    def test_add_multiple_rooms(self, session, test_claim_id):
        """Multiple rooms can be added to one claim."""
        for room in ['Kitchen', 'Master Bedroom', 'Bathroom']:
            r = session.post(
                f'{BASE_URL}/claims/{test_claim_id}/room/add',
                data={'room_name': room},
                allow_redirects=True, timeout=15
            )
            assert r.status_code == 200, f'Add room "{room}" returned {r.status_code}'
            assert room in r.text, f'Room "{room}" not visible after adding'

    def test_empty_room_name_ignored(self, session, test_claim_id):
        """Submitting empty room name must not crash."""
        r = session.post(
            f'{BASE_URL}/claims/{test_claim_id}/room/add',
            data={'room_name': ''},
            allow_redirects=True, timeout=15
        )
        assert r.status_code == 200, f'Empty room name caused {r.status_code}'

    def test_claim_detail_loads_after_room_added(self, session, test_claim_id):
        """Claim detail must still return 200 after rooms exist (no 500)."""
        r = session.get(f'{BASE_URL}/claims/{test_claim_id}', timeout=15)
        assert r.status_code == 200, \
            f'Claim detail returned {r.status_code} after adding rooms'


# ══════════════════════════════════════════════════════════════════════════════
# 5. ADD LINE ITEMS
# ══════════════════════════════════════════════════════════════════════════════
class TestAddItems:

    @pytest.fixture(scope='class')
    def room_id(self, session, test_claim_id):
        """Add a room and return its ID."""
        import re
        r = session.post(
            f'{BASE_URL}/claims/{test_claim_id}/room/add',
            data={'room_name': 'Test Room for Items'},
            allow_redirects=True, timeout=15
        )
        assert r.status_code == 200
        # Find the room ID from the form action in the response
        m = re.search(r'/rooms/(\d+)/item/add', r.text)
        assert m, 'Could not find room ID in response after adding room'
        return int(m.group(1))

    def test_add_line_item(self, session, test_claim_id, room_id):
        """POST /rooms/<id>/item/add must create a line item."""
        r = session.post(
            f'{BASE_URL}/rooms/{room_id}/item/add',
            data={
                'description': 'Drywall repair',
                'quantity':    '2',
                'unit':        'sq ft',
                'unit_cost':   '4.50',
            },
            allow_redirects=True, timeout=15
        )
        assert r.status_code == 200, f'Add item returned {r.status_code}'
        assert 'Drywall repair' in r.text, 'Line item not visible after adding'

    def test_total_updates_after_item(self, session, test_claim_id, room_id):
        """Total estimate must be > 0 after adding a line item."""
        r = session.get(f'{BASE_URL}/claims/{test_claim_id}', timeout=15)
        assert r.status_code == 200
        import re
        # Look for any dollar amount > $0.00
        totals = re.findall(r'\$([\d,]+\.\d{2})', r.text)
        nonzero = [t for t in totals if float(t.replace(',', '')) > 0]
        assert nonzero, 'No non-zero dollar amounts found after adding line item'


# ══════════════════════════════════════════════════════════════════════════════
# 6. AI ESTIMATE ENDPOINT
# ══════════════════════════════════════════════════════════════════════════════
class TestAIEstimate:

    def test_ai_estimate_returns_json_when_authed(self, session, test_claim_id):
        """AI estimate must return JSON (not HTML) for logged-in user."""
        r = session.post(
            f'{BASE_URL}/claims/{test_claim_id}/ai-estimate',
            headers={'Content-Type': 'application/json'},
            timeout=60
        )
        assert r.status_code in (200, 400, 500), \
            f'Unexpected status: {r.status_code}'
        # Must be valid JSON — not an HTML redirect page
        try:
            data = r.json()
        except Exception:
            pytest.fail(
                f'AI estimate returned non-JSON (HTML redirect?). '
                f'Status={r.status_code}, body starts: {r.text[:200]}'
            )
        assert 'ok' in data, f'Response missing "ok" field: {data}'

    def test_ai_estimate_no_hardcoded_token(self):
        """The template must NOT contain the old hardcoded willie token."""
        template_path = os.path.join(
            os.path.dirname(__file__), '..', 'templates', 'claim_detail.html'
        )
        with open(template_path) as f:
            content = f.read()
        assert 'S7LroZDvJSqzJZ304leqwQcxToJXRwF597gszWWarq4' not in content, \
            'Hardcoded willie token still present in claim_detail.html!'

    def test_update_estimate_returns_json_when_authed(self, session, test_claim_id):
        """update-estimate must return JSON for logged-in user."""
        r = session.post(
            f'{BASE_URL}/claims/{test_claim_id}/update-estimate',
            json={'total_estimate': 1234.56},
            timeout=15
        )
        try:
            data = r.json()
        except Exception:
            pytest.fail(f'update-estimate returned non-JSON: {r.text[:200]}')
        assert 'ok' in data


# ══════════════════════════════════════════════════════════════════════════════
# 7. DB SCHEMA / MIGRATION
# ══════════════════════════════════════════════════════════════════════════════
class TestDBMigration:
    """These tests run against the LOCAL app.py to verify migration logic."""

    def test_photos_table_has_room_id(self):
        """photos table must have room_id column in schema definition."""
        app_path = os.path.join(os.path.dirname(__file__), '..', 'app.py')
        with open(app_path) as f:
            content = f.read()
        assert 'room_id' in content, 'room_id missing from app.py schema'

    def test_photos_table_has_ai_description(self):
        """photos table must have ai_description column."""
        app_path = os.path.join(os.path.dirname(__file__), '..', 'app.py')
        with open(app_path) as f:
            content = f.read()
        assert 'ai_description' in content

    def test_migrate_photos_columns_exists(self):
        """migrate_photos_columns() function must exist in app.py."""
        app_path = os.path.join(os.path.dirname(__file__), '..', 'app.py')
        with open(app_path) as f:
            content = f.read()
        assert 'migrate_photos_columns' in content, \
            'migrate_photos_columns() missing — photos table migration not present!'

    def test_secret_key_not_random_on_every_boot(self):
        """SECRET_KEY fallback must NOT be pure random (causes session resets)."""
        app_path = os.path.join(os.path.dirname(__file__), '..', 'app.py')
        with open(app_path) as f:
            content = f.read()
        # Should use RAILWAY_SERVICE_ID or file-based key, not raw token_hex as sole fallback
        # Check that our stable hash fallback is present
        assert 'RAILWAY_SERVICE_ID' in content or '/data/.secret_key' in content, \
            'SECRET_KEY has no stable fallback — sessions will reset on every redeploy!'

    def test_login_required_flashes_on_session_expiry(self):
        """login_required decorator must flash a message on session expiry."""
        app_path = os.path.join(os.path.dirname(__file__), '..', 'app.py')
        with open(app_path) as f:
            content = f.read()
        assert 'session expired' in content.lower() or 'Session expired' in content, \
            'login_required does not flash session-expired message'

    def test_no_hardcoded_tokens_in_templates(self):
        """No hardcoded API tokens should exist in any template."""
        templates_dir = os.path.join(os.path.dirname(__file__), '..', 'templates')
        bad_tokens = [
            'S7LroZDvJSqzJZ304leqwQcxToJXRwF597gszWWarq4',
        ]
        for filename in os.listdir(templates_dir):
            if not filename.endswith('.html'):
                continue
            with open(os.path.join(templates_dir, filename)) as f:
                content = f.read()
            for token in bad_tokens:
                assert token not in content, \
                    f'Hardcoded token found in {filename}!'


# ══════════════════════════════════════════════════════════════════════════════
# 8. SETTINGS PAGE
# ══════════════════════════════════════════════════════════════════════════════
class TestSettings:

    def test_settings_page_loads(self, session):
        """Settings page must return 200."""
        r = session.get(f'{BASE_URL}/admin/settings', timeout=10)
        assert r.status_code == 200, f'Settings returned {r.status_code}'

    def test_settings_has_api_key_field(self, session):
        """Settings must have OpenRouter API key field."""
        r = session.get(f'{BASE_URL}/admin/settings', timeout=10)
        assert 'openrouter' in r.text.lower() or 'api' in r.text.lower()


# ══════════════════════════════════════════════════════════════════════════════
# SUMMARY
# ══════════════════════════════════════════════════════════════════════════════
def pytest_terminal_summary(terminalreporter, exitstatus, config):
    passed = len(terminalreporter.stats.get('passed', []))
    failed = len(terminalreporter.stats.get('failed', []))
    errors = len(terminalreporter.stats.get('error', []))
    total  = passed + failed + errors
    print(f'\n{"="*55}')
    print(f'🤖 FLOODCLAIM PRO TEST SUITE')
    print(f'{"="*55}')
    print(f'✅ Passed:  {passed}/{total}')
    if failed: print(f'❌ Failed:  {failed}/{total}')
    if errors:  print(f'💥 Errors:  {errors}/{total}')
    print(f'{"="*55}\n')
