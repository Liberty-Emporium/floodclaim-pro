#!/usr/bin/env python3
"""
willie_test.py — Full automated test suite for FloodClaim Pro Willie API
Tests every route, catches schema bugs, and reports a pass/fail summary.

Usage:
    python3 willie_test.py
    python3 willie_test.py --url https://billy-floods.up.railway.app
    python3 willie_test.py --url http://localhost:5000 --token YOUR_TOKEN

Exit code: 0 = all passed, 1 = failures found
"""

import sys, os, json, argparse, time
import urllib.request, urllib.error

# ── Config ────────────────────────────────────────────────────────────────────
DEFAULT_URL   = 'https://billy-floods.up.railway.app'
DEFAULT_TOKEN = os.environ.get('WILLIE_TOKEN', 'S7LroZDvJSqzJZ304leqwQcxToJXRwF597gszWWarq4')

PASS = '\033[92m✅\033[0m'
FAIL = '\033[91m❌\033[0m'
WARN = '\033[93m⚠️ \033[0m'
INFO = '\033[94mℹ️ \033[0m'

results = []
_test_claim_id   = None
_test_room_id    = None
_test_item_id    = None
_test_team_id    = None

# ── HTTP helper ───────────────────────────────────────────────────────────────
def req(method, path, token, base_url, body=None, params=None):
    url = base_url.rstrip('/') + path
    if params:
        url += '?' + '&'.join(f'{k}={urllib.parse.quote(str(v))}' for k,v in params.items())
    data = json.dumps(body).encode() if body else None
    headers = {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json',
    }
    r = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(r, timeout=30) as resp:
            raw = resp.read().decode()
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, {'error': raw[:200]}
    except Exception as ex:
        return 0, {'error': str(ex)}

import urllib.parse

# ── Test runner ───────────────────────────────────────────────────────────────
def test(name, status, data, expect_ok=True, expect_status=200, check_keys=None):
    ok    = data.get('ok', True) if expect_ok else True
    valid = (status == expect_status or (expect_status == 200 and status in (200, 201))) and ok
    if check_keys:
        for k in check_keys:
            if k not in data:
                valid = False
                print(f'  {FAIL} Missing key: {k}')
    icon  = PASS if valid else FAIL
    msg   = f'{icon} [{status}] {name}'
    if not valid:
        err = data.get('error') or data.get('message') or str(data)[:120]
        msg += f'\n       → {err}'
    print(msg)
    results.append((name, valid, status, data))
    return valid, data

# ── Test suite ────────────────────────────────────────────────────────────────
def run(base_url, token):
    global _test_claim_id, _test_room_id, _test_item_id, _test_team_id

    print(f'\n🧪 FloodClaim Pro — Willie API Test Suite')
    print(f'   URL:   {base_url}')
    print(f'   Token: {token[:12]}...')
    print('─' * 60)

    # ── 1. Health check ───────────────────────────────────────────────────────
    print('\n📡 CONNECTIVITY')
    s, d = req('GET', '/health', token, base_url)
    test('GET /health', s, d, check_keys=['status'])

    # ── 2. Dashboard ──────────────────────────────────────────────────────────
    print('\n📊 DASHBOARD')
    s, d = req('GET', '/willie/api/dashboard', token, base_url)
    ok, _ = test('GET /willie/api/dashboard', s, d, check_keys=['stats', 'recent_claims'])
    if ok:
        stats = d.get('stats', {})
        print(f'   {INFO} Total claims: {stats.get("total")} | Pipeline: ${stats.get("pipeline_value", 0):,.2f}')

    # ── 3. List claims ────────────────────────────────────────────────────────
    print('\n📋 CLAIMS — LIST & LOOKUP')
    s, d = req('GET', '/willie/api/claims', token, base_url)
    ok, _ = test('GET /willie/api/claims', s, d, check_keys=['claims', 'count'])
    existing_claims = d.get('claims', [])
    if existing_claims:
        print(f'   {INFO} Found {len(existing_claims)} existing claims')

    # ── 4. Create test claim ──────────────────────────────────────────────────
    print('\n🆕 CLAIMS — CREATE')
    s, d = req('POST', '/willie/api/claims', token, base_url, body={
        'client_name':       'Willie Test Client',
        'property_address':  '123 Test Ave, Myrtle Beach SC 29577',
        'flood_date':        '2026-04-21',
        'insurance_company': 'Test Insurance Co',
        'water_category':    '3',
        'water_class':       '2',
    })
    ok, _ = test('POST /willie/api/claims (create)', s, d, check_keys=['claim_id', 'claim_number'])
    if ok:
        _test_claim_id = d['claim_id']
        print(f'   {INFO} Created claim ID={_test_claim_id} | {d.get("claim_number")}')

    # ── 5. Get claim by ID ────────────────────────────────────────────────────
    if _test_claim_id:
        s, d = req('GET', f'/willie/api/claims/{_test_claim_id}', token, base_url)
        test(f'GET /willie/api/claims/{_test_claim_id}', s, d, check_keys=['claim', 'rooms'])

    # ── 6. Lookup by claim number ─────────────────────────────────────────────
    if existing_claims:
        cn = existing_claims[0]['claim_number']
        s, d = req('GET', '/willie/api/claims/lookup', token, base_url, params={'claim_number': cn})
        test(f'GET /willie/api/claims/lookup?claim_number={cn}', s, d, check_keys=['claim'])

    # Lookup by client name
    s, d = req('GET', '/willie/api/claims/lookup', token, base_url, params={'client_name': 'Willie Test'})
    test('GET /willie/api/claims/lookup?client_name=Willie+Test', s, d, check_keys=['claims'])

    # ── 7. Update status ──────────────────────────────────────────────────────
    print('\n🔄 CLAIMS — STATUS UPDATE')
    if _test_claim_id:
        for status_val in ['In Progress', 'Submitted', 'New']:
            s, d = req('POST', f'/willie/api/claims/{_test_claim_id}/status', token, base_url,
                       body={'status': status_val})
            test(f'POST status → "{status_val}"', s, d)

        # Bad status value
        s, d = req('POST', f'/willie/api/claims/{_test_claim_id}/status', token, base_url,
                   body={'status': 'InvalidStatus'})
        test('POST status → invalid (expect 400)', s, d, expect_ok=False, expect_status=400)

    # ── 8. Rooms ──────────────────────────────────────────────────────────────
    print('\n🏠 ROOMS')
    if _test_claim_id:
        s, d = req('POST', f'/willie/api/claims/{_test_claim_id}/rooms', token, base_url,
                   body={'room_name': 'Living Room'})
        ok, _ = test('POST /rooms (add Living Room)', s, d, check_keys=['room_id'])
        if ok:
            _test_room_id = d['room_id']

        # Add a second room
        s, d = req('POST', f'/willie/api/claims/{_test_claim_id}/rooms', token, base_url,
                   body={'room_name': 'Kitchen'})
        test('POST /rooms (add Kitchen)', s, d, check_keys=['room_id'])
        kitchen_id = d.get('room_id')

        # List rooms
        s, d = req('GET', f'/willie/api/claims/{_test_claim_id}/rooms', token, base_url)
        ok, _ = test('GET /rooms (list)', s, d, check_keys=['rooms', 'count'])
        if ok:
            print(f'   {INFO} {d["count"]} rooms found')

        # Missing room_name
        s, d = req('POST', f'/willie/api/claims/{_test_claim_id}/rooms', token, base_url, body={})
        test('POST /rooms (missing name → 400)', s, d, expect_ok=False, expect_status=400)

    # ── 9. Line items ─────────────────────────────────────────────────────────
    print('\n📝 LINE ITEMS')
    if _test_claim_id and _test_room_id:
        test_items = [
            {'description': 'Tear out wet drywall Cat 3', 'quantity': 200, 'unit': 'sf', 'unit_cost': 1.79},
            {'description': 'LVP flooring installed',     'quantity': 180, 'unit': 'sf', 'unit_cost': 5.50},
            {'description': 'Water extraction',           'quantity': 200, 'unit': 'sf', 'unit_cost': 1.25},
        ]
        for item in test_items:
            s, d = req('POST', f'/willie/api/claims/{_test_claim_id}/rooms/{_test_room_id}/items',
                       token, base_url, body=item)
            ok2, _ = test(f'POST /items "{item["description"][:30]}"', s, d)
            if ok2 and not _test_item_id:
                _test_item_id = d.get('item_id') or _get_item_id(base_url, token, _test_claim_id, _test_room_id)

        # Missing description
        s, d = req('POST', f'/willie/api/claims/{_test_claim_id}/rooms/{_test_room_id}/items',
                   token, base_url, body={'quantity': 1, 'unit_cost': 100})
        test('POST /items (missing description → 400)', s, d, expect_ok=False, expect_status=400)

    # ── 10. Report ────────────────────────────────────────────────────────────
    print('\n📄 REPORT')
    if _test_claim_id:
        s, d = req('GET', f'/willie/api/claims/{_test_claim_id}/report', token, base_url)
        ok, _ = test('GET /report', s, d, check_keys=['report'])
        if ok:
            report = d['report']
            rooms_in_report = report.get('rooms', [])
            print(f'   {INFO} Report: {report.get("client_name")} | {len(rooms_in_report)} rooms | ${report.get("total_estimate", 0):.2f}')
            # Verify line items are in report
            total_items = sum(len(r.get('line_items', [])) for r in rooms_in_report)
            if total_items > 0:
                print(f'   {PASS} Report contains {total_items} line items')
            else:
                print(f'   {WARN} Report has no line items (recalc may be needed)')

    # ── 11. Team ──────────────────────────────────────────────────────────────
    print('\n👥 TEAM')
    s, d = req('GET', '/willie/api/team', token, base_url)
    ok, _ = test('GET /willie/api/team', s, d, check_keys=['team'])
    if ok:
        print(f'   {INFO} {len(d["team"])} team members')

    # Add test member
    s, d = req('POST', '/willie/api/team', token, base_url, body={
        'name':     'Willie Test User',
        'email':    f'willietest_{int(time.time())}@test.com',
        'password': 'TestPass123!',
        'role':     'adjuster',
    })
    ok, _ = test('POST /team (add member)', s, d)
    if ok:
        _test_team_id = d.get('user_id') or d.get('id')

    # Duplicate email
    dup_email = f'dup_{int(time.time())}@test.com'
    req('POST', '/willie/api/team', token, base_url, body={'name':'Dup','email':dup_email,'password':'x','role':'adjuster'})
    s, d = req('POST', '/willie/api/team', token, base_url, body={'name':'Dup2','email':dup_email,'password':'x','role':'adjuster'})
    test('POST /team (duplicate email → 409)', s, d, expect_ok=False, expect_status=409)

    # ── 12. Settings ──────────────────────────────────────────────────────────
    print('\n⚙️  SETTINGS')
    s, d = req('GET', '/willie/api/settings', token, base_url)
    test('GET /willie/api/settings', s, d, check_keys=['settings'])

    # ── 13. Error cases — 404s ─────────────────────────────────────────────────
    print('\n🚫 ERROR HANDLING — 404s')
    s, d = req('GET', '/willie/api/claims/999999', token, base_url)
    test('GET claim 999999 (→ 404)', s, d, expect_ok=False, expect_status=404)

    s, d = req('GET', '/willie/api/claims/999999/rooms', token, base_url)
    test('GET rooms for non-existent claim (→ 404)', s, d, expect_ok=False, expect_status=404)

    # Bad token
    s, d = req('GET', '/willie/api/dashboard', 'BADTOKEN', base_url)
    test('GET /dashboard (bad token → 401)', s, d, expect_ok=False, expect_status=401)

    # ── 14. Cleanup — delete line item ────────────────────────────────────────
    print('\n🧹 CLEANUP')
    if _test_item_id:
        s, d = req('DELETE', f'/willie/api/line-items/{_test_item_id}', token, base_url)
        test(f'DELETE line item {_test_item_id}', s, d)

    # Delete test room (Kitchen)
    if _test_claim_id and 'kitchen_id' in dir() and kitchen_id:
        s, d = req('DELETE', f'/willie/api/claims/{_test_claim_id}/rooms/{kitchen_id}', token, base_url)
        test(f'DELETE room (Kitchen)', s, d)

    # Delete test team member
    if _test_team_id:
        s, d = req('DELETE', f'/willie/api/team/{_test_team_id}', token, base_url)
        test(f'DELETE team member {_test_team_id}', s, d)

    # Delete test claim
    if _test_claim_id:
        s, d = req('DELETE', f'/willie/api/claims/{_test_claim_id}', token, base_url)
        test(f'DELETE test claim {_test_claim_id}', s, d)
        # Verify gone
        s2, d2 = req('GET', f'/willie/api/claims/{_test_claim_id}', token, base_url)
        test(f'Verify claim deleted (→ 404)', s2, d2, expect_ok=False, expect_status=404)

    # ── Summary ───────────────────────────────────────────────────────────────
    passed = sum(1 for _, ok, _, _ in results if ok)
    failed = sum(1 for _, ok, _, _ in results if not ok)
    total  = len(results)

    print('\n' + '═' * 60)
    print(f'  RESULTS: {passed}/{total} passed  |  {failed} failed')
    print('═' * 60)

    if failed:
        print('\nFailed tests:')
        for name, ok, status, data in results:
            if not ok:
                err = data.get('error') or data.get('message') or str(data)[:100]
                print(f'  {FAIL} [{status}] {name}')
                print(f'         → {err}')

    print()
    return failed == 0


def _get_item_id(base_url, token, claim_id, room_id):
    """Fetch the first line item id for a room (for delete testing)."""
    s, d = req('GET', f'/willie/api/claims/{claim_id}/rooms', token, base_url)
    if d.get('ok'):
        for r in d.get('rooms', []):
            if r['id'] == room_id:
                items = r.get('line_items', [])
                if items:
                    return items[0]['id']
    return None


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='FloodClaim Pro Willie API test suite')
    parser.add_argument('--url',   default=DEFAULT_URL,   help='Base URL of the app')
    parser.add_argument('--token', default=DEFAULT_TOKEN, help='Willie API token')
    args = parser.parse_args()

    success = run(args.url, args.token)
    sys.exit(0 if success else 1)
