"""
ecdash_client.py — Liberty-Emporium App Network Client  v1.0
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Drop this single file into any Liberty-Emporium app.
It provides two capabilities:

  PHASE 2 — Pull own secrets from EcDash vault at startup:
    from ecdash_client import get_secret, get_secrets
    STRIPE_KEY = get_secret("Stripe Secret Key")
    keys = get_secrets(["Stripe Secret Key", "OpenRouter API Key"])

  PHASE 3 — Call other Liberty-Emporium apps:
    from ecdash_client import call_app, get_app_url
    result = call_app("Pet Vet AI", "/api/analyze-damage", {"image_b64": "..."})
    url    = get_app_url("FloodClaim Pro")

Config (set as Railway env vars):
  ECDASH_APP_TOKEN  — your app's unique token (set by activate-phase2.py)
  ECDASH_URL        — https://jay-portfolio-production.up.railway.app
  ECDASH_APP_NAME   — your app's name (e.g. "FloodClaim Pro")

All calls are fire-and-forget safe — errors are logged, never raised.
"""

import os
import json
import time
import logging
import hashlib
import urllib.request
import urllib.error
from functools import lru_cache
from typing import Any, Dict, List, Optional

logger = logging.getLogger("ecdash_client")

# ── Config ────────────────────────────────────────────────────────────────────
ECDASH_URL       = os.environ.get("ECDASH_URL",        "https://jay-portfolio-production.up.railway.app")
ECDASH_APP_TOKEN = os.environ.get("ECDASH_APP_TOKEN",  "")
ECDASH_APP_NAME  = os.environ.get("ECDASH_APP_NAME",   "")
_REQUEST_TIMEOUT = int(os.environ.get("ECDASH_TIMEOUT", "8"))

# In-memory secret cache — avoids repeated vault calls during a request
_secret_cache: Dict[str, Any]   = {}
_secret_cache_ts: Dict[str, float] = {}
_SECRET_TTL = 300  # seconds — re-fetch secrets every 5 min

# App URL cache
_url_cache: Dict[str, str] = {}
_url_cache_ts: float = 0
_URL_TTL = 600  # 10 min


def _http(method: str, url: str, data: Optional[dict] = None,
          headers: Optional[dict] = None, timeout: int = _REQUEST_TIMEOUT) -> Optional[dict]:
    """Low-level HTTP helper. Returns parsed JSON or None on error."""
    try:
        body = json.dumps(data).encode() if data else None
        hdrs = {"Content-Type": "application/json", **(headers or {})}
        req  = urllib.request.Request(url, data=body, headers=hdrs, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        logger.warning(f"ecdash_client: HTTP {e.code} → {url}")
    except Exception as e:
        logger.debug(f"ecdash_client: {method} {url} failed: {e}")
    return None


def _vault_headers() -> dict:
    return {"Authorization": f"Bearer {ECDASH_APP_TOKEN}"}


# ── Phase 2: Secret pulling ───────────────────────────────────────────────────

def get_secret(label: str, fallback: str = "") -> str:
    """
    Pull a single secret from EcDash vault by label.
    Falls back to env var with the same name (spaces→underscores, uppercase).
    Caches results for _SECRET_TTL seconds.

    Example:
        STRIPE_KEY = get_secret("Stripe Secret Key")
    """
    now = time.time()
    if label in _secret_cache and now - _secret_cache_ts.get(label, 0) < _SECRET_TTL:
        return _secret_cache[label]

    if not ECDASH_APP_TOKEN or not ECDASH_APP_NAME:
        # Fall back to env var: "Stripe Secret Key" → STRIPE_SECRET_KEY
        env_key = label.upper().replace(" ", "_").replace("-", "_")
        return os.environ.get(env_key, fallback)

    result = _http("POST",
        f"{ECDASH_URL}/api/vault/app-keys",
        data={"app": ECDASH_APP_NAME, "token": ECDASH_APP_TOKEN, "labels": [label]},
    )
    if result and label in result:
        val = result[label]
        _secret_cache[label] = val
        _secret_cache_ts[label] = now
        return val

    # Env var fallback
    env_key = label.upper().replace(" ", "_").replace("-", "_")
    return os.environ.get(env_key, fallback)


def get_secrets(labels: List[str]) -> Dict[str, str]:
    """
    Pull multiple secrets in one vault call.
    Returns dict of {label: value}. Missing keys get empty string.

    Example:
        keys = get_secrets(["Stripe Secret Key", "Stripe Publishable Key"])
        stripe.api_key = keys["Stripe Secret Key"]
    """
    if not labels:
        return {}

    now   = time.time()
    fresh = {l: _secret_cache[l] for l in labels
             if l in _secret_cache and now - _secret_cache_ts.get(l, 0) < _SECRET_TTL}
    stale = [l for l in labels if l not in fresh]

    if stale and ECDASH_APP_TOKEN and ECDASH_APP_NAME:
        result = _http("POST",
            f"{ECDASH_URL}/api/vault/app-keys",
            data={"app": ECDASH_APP_NAME, "token": ECDASH_APP_TOKEN, "labels": stale},
        ) or {}
        for label, val in result.items():
            _secret_cache[label] = val
            _secret_cache_ts[label] = now
            fresh[label] = val

    # Fill remaining from env vars
    for l in labels:
        if l not in fresh:
            env_key = l.upper().replace(" ", "_").replace("-", "_")
            fresh[l] = os.environ.get(env_key, "")

    return fresh


def invalidate_secret_cache():
    """Force re-fetch on next get_secret() call."""
    _secret_cache.clear()
    _secret_cache_ts.clear()


# ── Phase 3: Cross-app calls ──────────────────────────────────────────────────

def _refresh_app_urls() -> Dict[str, str]:
    """Fetch all app URLs from EcDash vault (App URLs category). Cached."""
    global _url_cache, _url_cache_ts
    now = time.time()
    if _url_cache and now - _url_cache_ts < _URL_TTL:
        return _url_cache

    if not ECDASH_APP_TOKEN:
        return _url_cache

    result = _http("GET", f"{ECDASH_URL}/api/vault",
                   headers=_vault_headers())
    if not result or not isinstance(result, list):
        return _url_cache

    urls = {}
    for item in result:
        if item.get("category") == "App URLs":
            label = item.get("label", "")
            # Reveal the URL value
            detail = _http("GET", f"{ECDASH_URL}/api/vault/{item['id']}",
                           headers=_vault_headers())
            if detail and detail.get("secret"):
                urls[label] = detail["secret"].rstrip("/")

    if urls:
        _url_cache = urls
        _url_cache_ts = now
        logger.debug(f"ecdash_client: loaded {len(urls)} app URLs from vault")

    return _url_cache


# Human-friendly name → vault label mapping
_APP_NAME_MAP = {
    # Canonical names
    "FloodClaim Pro":        "FloodClaim Pro",
    "AI Agent Widget":       "AI Agent Widget",
    "Sweet Spot Cakes":      "Sweet Spot Custom Cakes",
    "Pet Vet AI":            "Pet Vet AI",
    "Contractor Pro AI":     "Contractor Pro AI",
    "Drop Shipping":         "Drop Shipping (Alexander AI)",
    "Consignment":           "Consignment Solutions",
    "Liberty Inventory":     "Liberty Inventory",
    "GymForge":              "GymForge",
    "Liberty Oil":           "Liberty Oil & Propane Website",
    "EcDash":                "EcDash (Portfolio Dashboard)",
    # Short aliases
    "floodclaim":            "FloodClaim Pro",
    "widget":                "AI Agent Widget",
    "cakes":                 "Sweet Spot Custom Cakes",
    "petvet":                "Pet Vet AI",
    "contractor":            "Contractor Pro AI",
    "dropship":              "Drop Shipping (Alexander AI)",
    "consignment":           "Consignment Solutions",
    "inventory":             "Liberty Inventory",
    "gymforge":              "GymForge",
    "liberty-oil":           "Liberty Oil & Propane Website",
    "ecdash":                "EcDash (Portfolio Dashboard)",
}


def get_app_url(app_name: str) -> Optional[str]:
    """
    Look up a Liberty-Emporium app's live URL from EcDash vault.
    Accepts canonical names or short aliases (see _APP_NAME_MAP).

    Example:
        url = get_app_url("Pet Vet AI")
        # → "https://pet-vet-ai-production.up.railway.app"
    """
    vault_label = _APP_NAME_MAP.get(app_name, app_name)
    urls = _refresh_app_urls()
    return urls.get(vault_label)


def call_app(app_name: str, path: str, data: Optional[dict] = None,
             method: str = "POST", timeout: int = _REQUEST_TIMEOUT,
             app_token: Optional[str] = None) -> Optional[dict]:
    """
    Call another Liberty-Emporium app's API endpoint.

    The target app's URL is looked up from EcDash vault automatically.
    Auth header uses this app's ECDASH_APP_TOKEN so the target knows
    who's calling (inter-app auth).

    Args:
        app_name:  "Pet Vet AI", "FloodClaim Pro", etc. (or short alias)
        path:      "/api/status", "/api/analyze-damage", etc.
        data:      JSON body for POST/PUT requests
        method:    HTTP method (default POST)
        timeout:   seconds (default 8)
        app_token: override auth token (optional)

    Returns:
        Parsed JSON response dict, or None on error.

    Example:
        result = call_app("Pet Vet AI", "/api/analyze-damage",
                          {"image_b64": b64_string, "context": "flood damage"})
    """
    base_url = get_app_url(app_name)
    if not base_url:
        logger.warning(f"ecdash_client: unknown app '{app_name}' — cannot call {path}")
        return None

    url     = base_url + path
    token   = app_token or ECDASH_APP_TOKEN
    headers = {}
    if token:
        headers["X-App-Token"]     = token
        headers["X-App-Name"]      = ECDASH_APP_NAME
        headers["X-Liberty-Auth"]  = token  # canonical header

    return _http(method, url, data=data if method in ("POST","PUT","PATCH") else None,
                 headers=headers, timeout=timeout)


def get_app_status(app_name: str) -> Optional[dict]:
    """
    Get standardized status from another app's /api/status endpoint.

    Returns dict with keys: app, version, uptime_seconds, stats, healthy
    Returns None if app unreachable.
    """
    return call_app(app_name, "/api/status", method="GET")


# ── Startup helper ────────────────────────────────────────────────────────────

def log_startup(app_name: Optional[str] = None):
    """
    Log which Phase 2/3 capabilities are active.
    Call once at app startup for visibility.
    """
    name = app_name or ECDASH_APP_NAME or "unknown"
    if ECDASH_APP_TOKEN:
        logger.info(f"ecdash_client: '{name}' connected to EcDash network ✓ "
                    f"(vault + inter-app calls enabled)")
    else:
        logger.warning(f"ecdash_client: '{name}' — ECDASH_APP_TOKEN not set, "
                       f"falling back to env vars")


def init_app(flask_app=None, app_name: Optional[str] = None):
    """
    Optional Flask integration. Call once at startup:
        from ecdash_client import init_app
        init_app(app, "FloodClaim Pro")

    Sets ECDASH_APP_NAME if provided, logs startup status, pre-warms URL cache.
    """
    global ECDASH_APP_NAME
    if app_name:
        ECDASH_APP_NAME = app_name
        os.environ["ECDASH_APP_NAME"] = app_name

    log_startup(ECDASH_APP_NAME)

    # Pre-warm the URL cache in a background thread so first call_app() is fast
    import threading
    def _prewarm():
        try:
            _refresh_app_urls()
        except Exception:
            pass
    threading.Thread(target=_prewarm, daemon=True).start()

    return flask_app  # pass-through for chaining
