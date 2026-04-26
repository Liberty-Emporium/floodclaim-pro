"""
echo_reporter.py — Liberty-Emporium App Network Reporter
Drop this file into any app and call install_reporter(app, app_name).
It silently sends health pings and error reports to EcDash.
No configuration needed beyond two env vars:
  ECDASH_REPORTER_URL  = https://jay-portfolio-production.up.railway.app
  ECDASH_REPORTER_TOKEN = (shared secret — get from Jay)
"""

import os
import json
import time
import threading
import traceback
import urllib.request
import urllib.error
from datetime import datetime, timezone

# ── Config from env ───────────────────────────────────────────────────────────
ECDASH_URL   = os.environ.get('ECDASH_REPORTER_URL',   'https://jay-portfolio-production.up.railway.app')
REPORT_TOKEN = os.environ.get('ECDASH_REPORTER_TOKEN', '')
PING_INTERVAL = int(os.environ.get('ECDASH_PING_INTERVAL', '300'))  # seconds, default 5 min

def _post(endpoint, payload):
    """Fire-and-forget POST to EcDash. Never raises."""
    if not REPORT_TOKEN:
        return
    try:
        data = json.dumps(payload).encode('utf-8')
        req  = urllib.request.Request(
            ECDASH_URL.rstrip('/') + endpoint,
            data=data,
            headers={
                'Content-Type':          'application/json',
                'X-Reporter-Token':      REPORT_TOKEN,
            },
            method='POST'
        )
        with urllib.request.urlopen(req, timeout=4):
            pass
    except Exception:
        pass  # Never crash the app — reporting is best-effort


def report_error(app_name, error, route=None, user_id=None, extra=None):
    """Call this anywhere you catch an exception to report it to EcDash."""
    _post('/api/monitor/error', {
        'app':       app_name,
        'error':     str(error),
        'traceback': traceback.format_exc(),
        'route':     route,
        'user_id':   str(user_id) if user_id else None,
        'extra':     extra or {},
        'ts':        datetime.now(timezone.utc).isoformat(),
    })


def report_health(app_name, status='ok', details=None):
    """Send a health ping to EcDash."""
    _post('/api/monitor/health', {
        'app':     app_name,
        'status':  status,
        'details': details or {},
        'ts':      datetime.now(timezone.utc).isoformat(),
    })


def install_reporter(flask_app, app_name):
    """
    Call once at app startup:
        from echo_reporter import install_reporter
        install_reporter(app, 'Contractor Pro AI')

    This does 3 things:
    1. Registers a Flask error handler that reports all 500s to EcDash
    2. Registers an after_request hook that tracks slow requests (>3s)
    3. Starts a background thread that sends a health ping every PING_INTERVAL seconds
    """

    # 1. Catch all unhandled exceptions
    @flask_app.errorhandler(Exception)
    def _handle_exception(e):
        from flask import request as freq, jsonify
        report_error(
            app_name,
            error=e,
            route=freq.path,
            extra={'method': freq.method, 'args': dict(freq.args)}
        )
        # Re-raise so Flask still returns a 500 to the user
        raise e

    # 2. Track slow requests
    @flask_app.before_request
    def _before():
        from flask import g
        g._req_start = time.time()

    @flask_app.after_request
    def _after(response):
        from flask import g, request as freq
        try:
            elapsed = time.time() - g._req_start
            if elapsed > 3.0:
                _post('/api/monitor/slow', {
                    'app':     app_name,
                    'route':   freq.path,
                    'elapsed': round(elapsed, 2),
                    'status':  response.status_code,
                    'ts':      datetime.now(timezone.utc).isoformat(),
                })
        except Exception:
            pass
        return response

    # 3. Background health ping thread
    def _ping_loop():
        time.sleep(10)  # wait for app to fully start
        while True:
            try:
                report_health(app_name, status='ok')
            except Exception:
                pass
            time.sleep(PING_INTERVAL)

    t = threading.Thread(target=_ping_loop, daemon=True)
    t.start()

    return flask_app
