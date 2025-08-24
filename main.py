# main.py
import os
import time
import hmac
import hashlib
from urllib.parse import urlencode, urlparse, parse_qsl, urlunparse
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import RedirectResponse
from dotenv import load_dotenv

# .env aynı klasördeyse local/dev için yükle
load_dotenv(dotenv_path=Path(__file__).parent / ".env", override=True)

app = FastAPI(title="KPIQ Dashboard Backend", version="0.4.0")

# -------------- helpers --------------
def sign(payload: str, secret: str) -> str:
    """Return HMAC-SHA256 (hex) of payload using `secret`."""
    return hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()


def is_plan_enabled(plan: str) -> bool:
    """
    Check if the plan is enabled via the env var ENABLED_PLANS.
    Example: ENABLED_PLANS=starter or ENABLED_PLANS=starter,premium
    """
    enabled = os.getenv("ENABLED_PLANS", "").replace(" ", "").split(",")
    enabled = [p for p in enabled if p]
    return plan in enabled


def with_qs(url: str, extra: dict) -> str:
    """Merge current query string with `extra` and return new URL."""
    if not url:
        return url
    u = urlparse(url)
    q = dict(parse_qsl(u.query))
    q.update(extra)
    return urlunparse((u.scheme, u.netloc, u.path, u.params, urlencode(q), u.fragment))


# -------------- health --------------
@app.get("/health")
def health():
    return {"status": "ok"}


# -------------- SSO entry (Shopify -> backend) --------------
@app.get("/sso/login")
def sso_login(
    email: str = Query(..., description="Shopify customer e-mail"),
    shop: str = Query(..., description="Shopify shop domain (permanent_domain)"),
    plan: str = Query(..., regex="^(starter|premium)$", description="starter | premium"),
):
    """
    Shopify -> (this service) -> KPIQ Dashboard SSO handoff.
    We generate a signed query and redirect the user to /auth/sso for verification.
    """
    secret = os.getenv("KPIQ_SSO_SECRET")
    if not secret:
        raise HTTPException(status_code=500, detail="KPIQ_SSO_SECRET is not set")

    # Optional: only allow certain plans (e.g. starter)
    if not is_plan_enabled(plan):
        raise HTTPException(status_code=400, detail=f"Plan '{plan}' not enabled")

    # Where /auth/sso lives (currently the same backend, later could be dashboard app)
    dashboard_base = os.getenv(
        "KPIQ_DASHBOARD_DOMAIN",
        "https://kpiq-dasboard-backend.onrender.com",  # sensible default: this service
    )

    ts = int(time.time())
    payload = f"{email}|{shop}|{plan}|{ts}"
    sig = sign(payload, secret)

    qs = urlencode({"email": email, "shop": shop, "plan": plan, "ts": ts, "sig": sig})
    return RedirectResponse(f"{dashboard_base}/auth/sso?{qs}")


# -------------- SSO verification (backend) --------------
@app.get("/auth/sso")
def auth_sso(
    email: str,
    shop: str,
    plan: str,
    ts: int,
    sig: str,
):
    """
    Verify SSO parameters on the backend.
    If valid, redirect the customer directly to the plan's report URL.
    """
    secret = os.getenv("KPIQ_SSO_SECRET")
    if not secret:
        raise HTTPException(status_code=500, detail="KPIQ_SSO_SECRET is not set")

    # Timestamp check (e.g., 10 minutes tolerance)
    now = int(time.time())
    try:
        ts_int = int(ts)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid timestamp")

    if abs(now - ts_int) > 600:
        raise HTTPException(status_code=400, detail="Link expired")

    # Plan check
    if not is_plan_enabled(plan):
        raise HTTPException(status_code=400, detail=f"Plan '{plan}' not enabled")

    # Signature verification
    payload = f"{email}|{shop}|{plan}|{ts_int}"
    expected_sig = sign(payload, secret)
    if not hmac.compare_digest(expected_sig, sig):
        raise HTTPException(status_code=400, detail="Invalid signature")

    # ---------- SUCCESS: send user to the correct report ----------
    # URLs come from env; if missing, fall back to the Shopify dashboard.
    starter_url = os.getenv("KPIQ_STARTER_REPORT_URL", "").strip()
    premium_url = os.getenv("KPIQ_PREMIUM_REPORT_URL", "").strip()
    dashboard_fallback = os.getenv("KPIQ_SHOPIFY_DASHBOARD_URL", "/").strip()

    plan_target = {
        "starter": starter_url or dashboard_fallback,
        "premium": premium_url or dashboard_fallback,
    }.get(plan, dashboard_fallback)

    # If your report app expects the signed params, keep them; otherwise drop `with_qs`.
    target = with_qs(
        plan_target,
        {"email": email, "shop": shop, "plan": plan, "ts": ts_int, "sig": expected_sig},
    )

    # 303 = See Other (forces GET on the target)
    return RedirectResponse(url=target, status_code=303)
