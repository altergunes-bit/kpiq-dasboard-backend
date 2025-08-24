# main.py
import os
import time
import hmac
import hashlib
from urllib.parse import urlencode
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import RedirectResponse  # HTMLResponse no longer needed
from dotenv import load_dotenv

# Load .env from the same folder as this file (for local/dev)
load_dotenv(dotenv_path=Path(__file__).parent / ".env", override=True)

app = FastAPI(title="KPIQ Dashboard Backend", version="0.3.0")

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
    dashboard_base = os.getenv("KPIQ_DASHBOARD_DOMAIN", "https://dashboard.kpiq.info")

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
    Verify SSO parameters on the backend. If valid, redirect the customer
    straight back to the Shopify Dashboard page (no interstitial page).
    """
    secret = os.getenv("KPIQ_SSO_SECRET")
    if not secret:
        raise HTTPException(status_code=500, detail="KPIQ_SSO_SECRET is not set")

    # Timestamp check (e.g., 10 minutes tolerance)
    now = int(time.time())
    if abs(now - int(ts)) > 600:
        raise HTTPException(status_code=400, detail="Link expired")

    # Plan check
    if not is_plan_enabled(plan):
        raise HTTPException(status_code=400, detail=f"Plan '{plan}' not enabled")

    # Signature verification
    payload = f"{email}|{shop}|{plan}|{ts}"
    expected_sig = sign(payload, secret)
    if not hmac.compare_digest(expected_sig, sig):
        raise HTTPException(status_code=400, detail="Invalid signature")

    # Success -> redirect to Shopify dashboard URL (e.g. https://kpiq.info/pages/dashboard)
    # 303 'See Other' ensures the client performs a GET to the target.
    dashboard_url = os.getenv("KPIQ_SHOPIFY_DASHBOARD_URL", "/")
    return RedirectResponse(url=dashboard_url, status_code=303)
