# main.py
import os
import time
import hmac
import hashlib
from urllib.parse import urlencode
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import RedirectResponse, HTMLResponse
from dotenv import load_dotenv

# .env yükle
load_dotenv(dotenv_path=Path(__file__).parent / ".env", override=True)

app = FastAPI(title="KPIQ Dashboard Backend", version="0.2.0")

# -------------- yardımcılar --------------
def sign(payload: str, secret: str) -> str:
    """HMAC-SHA256 (hex)"""
    return hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()

def is_plan_enabled(plan: str) -> bool:
    enabled = os.getenv("ENABLED_PLANS", "").replace(" ", "").split(",")
    enabled = [p for p in enabled if p]
    return plan in enabled

# -------------- health --------------
@app.get("/health")
def health():
    return {"status": "ok"}

# -------------- SSO giriş (Shopify -> backend) --------------
@app.get("/sso/login")
def sso_login(
    email: str = Query(..., description="Shopify customer e-mail"),
    shop: str = Query(..., description="Shopify shop domain (permanent_domain)"),
    plan: str = Query(..., regex="^(starter|premium)$", description="starter | premium"),
):
    """
    Shopify → (bu servis) → KPIQ dashboard SSO yönlendirmesi.
    """
    secret = os.getenv("KPIQ_SSO_SECRET")
    if not secret:
        raise HTTPException(status_code=500, detail="KPIQ_SSO_SECRET is not set")

    # İsteğe bağlı: plan filtreleme (şu an sadece starter)
    if not is_plan_enabled(plan):
        raise HTTPException(status_code=400, detail=f"Plan '{plan}' not enabled")

    dashboard_base = os.getenv("KPIQ_DASHBOARD_DOMAIN", "https://dashboard.kpiq.info")

    ts = int(time.time())
    payload = f"{email}|{shop}|{plan}|{ts}"
    sig = sign(payload, secret)

    qs = urlencode({"email": email, "shop": shop, "plan": plan, "ts": ts, "sig": sig})
    # Test sırasında /auth/sso backend’imizde (ngrok) çalışıyor. Gerçekte dashboard.kpiq.info’da olacak.
    return RedirectResponse(f"{dashboard_base}/auth/sso?{qs}")

# -------------- SSO doğrulama (backend) --------------
@app.get("/auth/sso")
def auth_sso(
    email: str,
    shop: str,
    plan: str,
    ts: int,
    sig: str,
):
    """
    Backend üzerinde SSO parametrelerini doğrular.
    Başarılıysa Shopify dashboard sayfasına yönlendirir veya kısa bir 'SSO OK' HTML döner (demo).
    """
    secret = os.getenv("KPIQ_SSO_SECRET")
    if not secret:
        raise HTTPException(status_code=500, detail="KPIQ_SSO_SECRET is not set")

    # Timestamp kontrolü (örn. 10 dk)
    now = int(time.time())
    if abs(now - int(ts)) > 600:
        raise HTTPException(status_code=400, detail="Link expired")

    # Plan kontrolü
    if not is_plan_enabled(plan):
        raise HTTPException(status_code=400, detail=f"Plan '{plan}' not enabled")

    # İmza doğrulama
    payload = f"{email}|{shop}|{plan}|{ts}"
    expected_sig = sign(payload, secret)
    if not hmac.compare_digest(expected_sig, sig):
        raise HTTPException(status_code=400, detail="Invalid signature")

    # --- DEMO 1: Basit HTML yanıtı ---
    html = f"""
    <html>
    <head><title>SSO OK</title></head>
    <body style="font-family:system-ui; max-width:680px; margin:40px auto;">
      <h2>SSO doğrulandı 🎉</h2>
      <p><b>Email:</b> {email}<br/>
         <b>Shop:</b> {shop}<br/>
         <b>Plan:</b> {plan}</p>
      <p>Artık bu kullanıcı için dashboarda güvenle yönlendirebilirsiniz.</p>
      <p><a href="{os.getenv('KPIQ_SHOPIFY_DASHBOARD_URL', '/')}">Shopify Dashboard sayfasına dön</a></p>
    </body>
    </html>
    """
    return HTMLResponse(content=html, status_code=200)

    # --- DEMO 2: Direkt redirect isterseniz (üstteki HTML yerine) ---
    # return RedirectResponse(os.getenv("KPIQ_SHOPIFY_DASHBOARD_URL", "/"))
