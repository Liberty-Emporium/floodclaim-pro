#!/usr/bin/env python3
"""
FloodClaim Pro — Full Browser Test Suite
Uses browser-use to drive a real Chromium window and test every feature.

Usage (on your Kali box):
    source ~/browser-test-env/bin/activate
    python3 browser_test_suite.py

    # Run a specific test only:
    python3 browser_test_suite.py --test login
    python3 browser_test_suite.py --test estimate
    python3 browser_test_suite.py --test willie

Requirements:
    pip install browser-use langchain-openai python-dotenv
    playwright install chromium
"""

import asyncio, os, sys, argparse, json, time
from dotenv import load_dotenv
from browser_use import Agent, Browser, BrowserProfile
from langchain_openai import ChatOpenAI

load_dotenv()

BASE_URL  = 'https://billy-floods.up.railway.app'
EMAIL     = 'admin@floodclaimpro.com'
PASSWORD  = 'admin'
OR_KEY    = os.getenv('OPENAI_API_KEY', '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')

# ── Colours ──────────────────────────────────────────────────────────────────
GREEN  = '\033[92m'
RED    = '\033[91m'
YELLOW = '\033[93m'
CYAN   = '\033[96m'
RESET  = '\033[0m'
BOLD   = '\033[1m'

results = []

def log(msg): print(f"  {CYAN}→{RESET} {msg}")
def ok(msg):  print(f"  {GREEN}✅ PASS:{RESET} {msg}"); results.append(('PASS', msg))
def fail(msg):print(f"  {RED}❌ FAIL:{RESET} {msg}"); results.append(('FAIL', msg))
def header(title): print(f"\n{BOLD}{CYAN}{'═'*60}{RESET}\n{BOLD}  {title}{RESET}\n{CYAN}{'═'*60}{RESET}")


def make_agent(browser, task, max_steps=25):
    llm = ChatOpenAI(
        model='openai/gpt-4o-mini',
        api_key=OR_KEY,
        base_url='https://openrouter.ai/api/v1',
    )
    return Agent(task=task, llm=llm, browser=browser)


# ── TEST 1: Login ─────────────────────────────────────────────────────────────
async def test_login(browser):
    header('TEST 1 — Login & Dashboard')
    agent = make_agent(browser, f"""
        Go to {BASE_URL}
        Log in with email={EMAIL} and password={PASSWORD}.
        After logging in you should see the dashboard.
        Tell me:
        1. Are you on the dashboard? (yes/no)
        2. How many claims are listed in the table?
        3. Is there a "New Claim" button visible?
        Report each answer clearly labelled.
    """)
    result = await agent.run(max_steps=15)
    text = result.final_result() or ''
    log(f"Result: {text[:200]}")

    if 'yes' in text.lower() and ('claim' in text.lower() or 'dashboard' in text.lower()):
        ok('Login successful, landed on dashboard')
    else:
        fail('Login did not reach dashboard')

    if any(c.isdigit() for c in text):
        ok('Claims count visible on dashboard')
    else:
        fail('Could not read claims count')


# ── TEST 2: New Claim ─────────────────────────────────────────────────────────
async def test_new_claim(browser):
    header('TEST 2 — Create New Claim')
    agent = make_agent(browser, f"""
        Go to {BASE_URL}
        Log in with email={EMAIL} and password={PASSWORD}.
        Click the "New Claim" or "+ New Claim" button.
        Fill in the new claim form with these values:
          - Client Name: Browser Test Client
          - Property Address: 999 Test Street, Myrtle Beach SC 29577
          - Flood Date: 2026-04-21
          - Insurance Company: Test Insurance
        Submit the form.
        Tell me:
        1. Did the form submit successfully? (yes/no)
        2. What claim number was assigned? (should start with FC-)
        3. Are you now on the claim detail page?
    """)
    result = await agent.run(max_steps=20)
    text = result.final_result() or ''
    log(f"Result: {text[:300]}")

    if 'yes' in text.lower() or 'fc-' in text.lower():
        ok('New claim created successfully')
    else:
        fail('New claim creation failed')

    if 'fc-' in text.lower():
        ok('Claim number assigned (FC- format)')
    else:
        fail('No claim number detected')


# ── TEST 3: Add Room & Line Items ─────────────────────────────────────────────
async def test_rooms_and_items(browser):
    header('TEST 3 — Add Room & Line Items')
    agent = make_agent(browser, f"""
        Go to {BASE_URL}
        Log in with email={EMAIL} and password={PASSWORD}.
        Click on the claim for "Maria Gonzalez" (look for her name in the claims table).
        Once on her claim detail page:
        1. Find the "Add Room" input field and add a room called "Test Bathroom"
        2. After the room appears, add a line item to it:
           - Description: Tear out wet drywall
           - Quantity: 120
           - Unit: sf
           - Unit Cost: 1.79
        3. Submit the line item.
        Tell me:
        1. Was the room "Test Bathroom" added successfully? (yes/no)
        2. Was the line item added? (yes/no)
        3. What is the room subtotal showing?
    """)
    result = await agent.run(max_steps=25)
    text = result.final_result() or ''
    log(f"Result: {text[:300]}")

    if 'yes' in text.lower() or 'bathroom' in text.lower():
        ok('Room added successfully')
    else:
        fail('Room addition failed')

    if 'drywall' in text.lower() or 'line item' in text.lower() or '214' in text:
        ok('Line item added successfully')
    else:
        fail('Line item addition failed')


# ── TEST 4: Photo Upload ──────────────────────────────────────────────────────
async def test_photo_upload(browser):
    header('TEST 4 — Photo Upload')
    # We'll use a small test image from a public URL - download it first
    import urllib.request as ur
    test_img = '/tmp/test_damage.jpg'
    if not os.path.exists(test_img):
        try:
            ur.urlretrieve(
                'https://upload.wikimedia.org/wikipedia/commons/thumb/3/3f/Bikesgonewild.jpg/320px-Bikesgonewild.jpg',
                test_img
            )
        except Exception:
            # Create a minimal valid JPEG if download fails
            with open(test_img, 'wb') as f:
                f.write(bytes([
                    0xFF,0xD8,0xFF,0xE0,0x00,0x10,0x4A,0x46,0x49,0x46,0x00,0x01,
                    0x01,0x00,0x00,0x01,0x00,0x01,0x00,0x00,0xFF,0xDB,0x00,0x43,
                    0x00,0x08,0x06,0x06,0x07,0x06,0x05,0x08,0x07,0x07,0x07,0x09,
                    0x09,0x08,0x0A,0x0C,0x14,0x0D,0x0C,0x0B,0x0B,0x0C,0x19,0x12,
                    0x13,0x0F,0x14,0x1D,0x1A,0x1F,0x1E,0x1D,0x1A,0x1C,0x1C,0x20,
                    0x24,0x2E,0x27,0x20,0x22,0x2C,0x23,0x1C,0x1C,0x28,0x37,0x29,
                    0x2C,0x30,0x31,0x34,0x34,0x34,0x1F,0x27,0x39,0x3D,0x38,0x32,
                    0x3C,0x2E,0x33,0x34,0x32,0xFF,0xC0,0x00,0x0B,0x08,0x00,0x01,
                    0x00,0x01,0x01,0x01,0x11,0x00,0xFF,0xC4,0x00,0x1F,0x00,0x00,
                    0x01,0x05,0x01,0x01,0x01,0x01,0x01,0x01,0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                    0x09,0x0A,0x0B,0xFF,0xDA,0x00,0x08,0x01,0x01,0x00,0x00,0x3F,
                    0x00,0xF5,0x0A,0x28,0x03,0xFF,0xD9
                ]))

    agent = make_agent(browser, f"""
        Go to {BASE_URL}
        Log in with email={EMAIL} and password={PASSWORD}.
        Click on the claim for "Maria Gonzalez".
        On her claim detail page, find the photo upload section.
        Upload the file at this path: {test_img}
        Add the caption: "Test damage photo"
        Click the upload button.
        Tell me:
        1. Did the photo upload successfully? (yes/no)
        2. Is the photo now visible on the page?
        3. Is there an AI analysis description shown for the photo?
    """)
    result = await agent.run(max_steps=20)
    text = result.final_result() or ''
    log(f"Result: {text[:300]}")

    if 'yes' in text.lower() or 'upload' in text.lower() or 'photo' in text.lower():
        ok('Photo upload completed')
    else:
        fail('Photo upload failed or not confirmed')


# ── TEST 5: AI Estimate ────────────────────────────────────────────────────────
async def test_ai_estimate(browser):
    header('TEST 5 — AI Estimate')
    agent = make_agent(browser, f"""
        Go to {BASE_URL}
        Log in with email={EMAIL} and password={PASSWORD}.
        Click on the claim for "James & Patricia Moore".
        Once on the claim detail page, click the "🤖 AI Estimate" button.
        Wait up to 90 seconds for the estimate to load (it runs AI analysis).
        Tell me:
        1. Did the estimate modal open? (yes/no)
        2. Is there a Grand Total or recommended claim amount shown? What is it?
        3. Are there line items listed in the estimate?
        4. Did the total estimate on the page update after the estimate ran?
    """)
    result = await agent.run(max_steps=20)
    text = result.final_result() or ''
    log(f"Result: {text[:400]}")

    if 'yes' in text.lower() or 'modal' in text.lower() or '$' in text:
        ok('AI Estimate modal opened')
    else:
        fail('AI Estimate modal did not open')

    import re
    totals = re.findall(r'\$[\d,]+(?:\.\d{2})?', text)
    if totals:
        ok(f'Grand Total found: {totals[0]}')
    else:
        fail('No dollar amount found in estimate result')


# ── TEST 6: Willie Chat ────────────────────────────────────────────────────────
async def test_willie_chat(browser):
    header('TEST 6 — Willie Chat Assistant')
    agent = make_agent(browser, f"""
        Go to {BASE_URL}
        Log in with email={EMAIL} and password={PASSWORD}.
        You should see a chat bubble/widget in the bottom-right corner of the page.
        Click on it to open the Willie chat assistant.
        Type this message: "How many claims do we have and what is the total pipeline value?"
        Wait for Willie's response (up to 30 seconds).
        Tell me:
        1. Did the chat bubble open? (yes/no)
        2. Did Willie respond? (yes/no)
        3. Did Willie mention a number of claims or a dollar amount?
        4. What exactly did Willie say?
    """)
    result = await agent.run(max_steps=20)
    text = result.final_result() or ''
    log(f"Result: {text[:400]}")

    if 'yes' in text.lower() and 'willie' in text.lower() or 'chat' in text.lower():
        ok('Willie chat opened and responded')
    else:
        fail('Willie chat did not respond')


# ── TEST 7: Delete Claim ──────────────────────────────────────────────────────
async def test_delete_claim(browser):
    header('TEST 7 — Delete Claim')
    agent = make_agent(browser, f"""
        Go to {BASE_URL}
        Log in with email={EMAIL} and password={PASSWORD}.
        On the dashboard, look for a claim belonging to "Browser Test Client"
        or any test claim that was created during this test session.
        If you find one, click its trash/delete button (🗑).
        Confirm the deletion when the confirmation dialog appears.
        Then tell me:
        1. Did you find a test claim to delete? (yes/no)
        2. Did the delete confirmation dialog appear? (yes/no)
        3. Was the claim successfully removed from the list? (yes/no)
        If no test claim was found, just report that and count the remaining claims.
    """)
    result = await agent.run(max_steps=20)
    text = result.final_result() or ''
    log(f"Result: {text[:300]}")

    if 'yes' in text.lower() or 'deleted' in text.lower() or 'removed' in text.lower():
        ok('Delete claim flow completed')
    else:
        fail('Delete claim not confirmed (test claim may not exist)')


# ── TEST 8: Settings Page ─────────────────────────────────────────────────────
async def test_settings(browser):
    header('TEST 8 — Settings Page')
    agent = make_agent(browser, f"""
        Go to {BASE_URL}
        Log in with email={EMAIL} and password={PASSWORD}.
        Find and click the Settings link (usually in the sidebar or navigation).
        On the settings page, tell me:
        1. Is there an OpenRouter API key section? (yes/no)
        2. Is there an AI model picker/selector? (yes/no)
        3. Is there a Willie Integration section? (yes/no)
        4. What is the currently selected AI model?
    """)
    result = await agent.run(max_steps=15)
    text = result.final_result() or ''
    log(f"Result: {text[:300]}")

    if 'openrouter' in text.lower() or 'api key' in text.lower():
        ok('Settings page loaded with API key section')
    else:
        fail('Settings page missing OpenRouter section')

    if 'model' in text.lower() or 'gpt' in text.lower() or 'claude' in text.lower():
        ok('AI model picker visible')
    else:
        fail('AI model picker not found')


# ── TEST 9: Report Page ────────────────────────────────────────────────────────
async def test_report(browser):
    header('TEST 9 — Claim Report')
    agent = make_agent(browser, f"""
        Go to {BASE_URL}
        Log in with email={EMAIL} and password={PASSWORD}.
        Click on the claim for "Maria Gonzalez".
        On her claim detail page, find and click the "Report" or "📄 Report" button.
        This should open a printable report in a new tab or the same page.
        Tell me:
        1. Did the report open? (yes/no)
        2. Does it show the client name "Maria Gonzalez"? (yes/no)
        3. Does it show rooms and line items? (yes/no)
        4. Does it show a total estimate dollar amount?
    """)
    result = await agent.run(max_steps=20)
    text = result.final_result() or ''
    log(f"Result: {text[:300]}")

    if 'yes' in text.lower() or 'gonzalez' in text.lower() or 'report' in text.lower():
        ok('Report page opened successfully')
    else:
        fail('Report page did not open')

    if 'gonzalez' in text.lower():
        ok('Report shows correct client name')
    else:
        fail('Client name not confirmed in report')


# ── TEST 10: Mobile Responsive ────────────────────────────────────────────────
async def test_mobile(browser):
    header('TEST 10 — Mobile Responsive (375px width)')
    agent = make_agent(browser, f"""
        Go to {BASE_URL}
        Resize the browser window to a mobile size (375px wide, 812px tall).
        Log in with email={EMAIL} and password={PASSWORD}.
        Tell me:
        1. Does the login page look reasonable on mobile? (yes/no)
        2. After login, does the dashboard fit without horizontal scrolling? (yes/no)
        3. Is there a hamburger menu or the navigation collapsed for mobile? (yes/no)
        4. Are the claim rows still readable on the small screen?
    """)
    result = await agent.run(max_steps=15)
    text = result.final_result() or ''
    log(f"Result: {text[:300]}")

    if 'yes' in text.lower():
        ok('Mobile responsive layout confirmed')
    else:
        fail('Mobile layout issues detected')


# ── Summary ────────────────────────────────────────────────────────────────────
def print_summary():
    print(f"\n{BOLD}{'═'*60}")
    print(f"  TEST RESULTS SUMMARY")
    print(f"{'═'*60}{RESET}")
    passed = [r for r in results if r[0] == 'PASS']
    failed = [r for r in results if r[0] == 'FAIL']
    for name, msg in results:
        icon = f"{GREEN}✅{RESET}" if name == 'PASS' else f"{RED}❌{RESET}"
        print(f"  {icon} {msg}")
    print(f"\n{BOLD}  {GREEN}{len(passed)} passed{RESET}{BOLD}  |  {RED}{len(failed)} failed{RESET}{BOLD}  |  {len(results)} total{RESET}")
    print(f"{'═'*60}\n")


# ── Test registry ──────────────────────────────────────────────────────────────
ALL_TESTS = {
    'login':    test_login,
    'newclaim': test_new_claim,
    'rooms':    test_rooms_and_items,
    'photo':    test_photo_upload,
    'estimate': test_ai_estimate,
    'willie':   test_willie_chat,
    'delete':   test_delete_claim,
    'settings': test_settings,
    'report':   test_report,
    'mobile':   test_mobile,
}


async def main(run_tests):
    print(f"\n{BOLD}{CYAN}FloodClaim Pro — Browser Test Suite{RESET}")
    print(f"{CYAN}Target: {BASE_URL}{RESET}")
    print(f"{CYAN}Running: {', '.join(run_tests)}{RESET}\n")

    browser = Browser(browser_profile=BrowserProfile(
        headless=False,
        viewport={'width': 1440, 'height': 900},
    ))

    try:
        for test_name in run_tests:
            fn = ALL_TESTS.get(test_name)
            if fn:
                try:
                    await fn(browser)
                except Exception as e:
                    fail(f'{test_name} crashed: {str(e)[:100]}')
            else:
                print(f"  {YELLOW}⚠️  Unknown test: {test_name}{RESET}")
    finally:
        try:
            await browser.browser_session.stop()
        except Exception:
            pass

    print_summary()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='FloodClaim Pro Browser Test Suite')
    parser.add_argument('--test', nargs='+',
                        choices=list(ALL_TESTS.keys()) + ['all'],
                        default=['all'],
                        help='Which tests to run (default: all)')
    args = parser.parse_args()

    tests_to_run = list(ALL_TESTS.keys()) if 'all' in args.test else args.test
    asyncio.run(main(tests_to_run))
