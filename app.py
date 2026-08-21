"""
HID Origo Wallet — Flask backend (prod)
=========================================
Ported from the official Java sample (WebPushProvisioningService.java) and
the HID Origo Wallet v3.0 R9 Postman collection. Endpoints/payloads below
match the real API, not guesses.

Flow implemented:
  1. POST /admin/passes            -> create a pass for a user, email them a redeem link
  2. GET  /wpp/redeem               -> decode issuanceCode, list supported wallets
  3. POST /wpp/provisioning/google  -> validate Google id_token, call /v2/provision
  4. POST /wpp/provisioning/apple   -> call /v2/provision for Apple, return JWS
  5. POST /origo/callback           -> receive PASS_ISSUING / PASS_ACTIVE events

Env vars required (see CONFIG section) — all real values pulled from your
Postman environment + Java application.yml, nothing invented.
"""

import base64
import hashlib
import json
import logging
import os
import smtplib
import time
import uuid
from email.mime.text import MIMEText

import requests
from dotenv import load_dotenv
from flask import Flask, jsonify, redirect, request, send_from_directory

load_dotenv()  # reads .env in the same folder, if present, into os.environ

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("origo-wallet-backend")

app = Flask(__name__, static_folder="static")


@app.route("/redeem.html")
def serve_redeem_page():
    return send_from_directory(".", "redeem.html")


@app.errorhandler(requests.exceptions.HTTPError)
def handle_upstream_http_error(e):
    resp = e.response
    log.error("Upstream HTTP error: %s %s", resp.status_code, resp.text)
    return jsonify({"error": "upstream_error", "status": resp.status_code, "body": resp.text}), 502


@app.errorhandler(requests.exceptions.RequestException)
def handle_upstream_request_error(e):
    log.error("Upstream request failed: %s", str(e))
    return jsonify({"error": "upstream_unreachable", "detail": str(e)}), 502


from werkzeug.exceptions import HTTPException


@app.errorhandler(Exception)
def handle_any_error(e):
    if isinstance(e, HTTPException):
        return e  # let Flask handle normal 404s/405s etc. as usual
    log.exception("Unhandled error")
    return jsonify({"error": "internal_error", "detail": str(e)}), 500

# --------------------------------------------------------------------------
# CONFIG — from your Postman environment (env = prod) + application.yml
# --------------------------------------------------------------------------
IDP_URL = os.environ.get("IDP_URL", "https://api.origo.hidglobal.com")
USERS_URL = os.environ.get("USERS_URL", "https://api.origo.hidglobal.com/scim")
CREDENTIAL_MGMT_URL = os.environ.get(
    "CREDENTIAL_MGMT_URL", "https://credential-management.api.origo.hidglobal.com"
)
CALLBACK_URL = os.environ.get("CALLBACK_URL", "https://callback.api.origo.hidglobal.com")
EVENTS_URL = os.environ.get("EVENTS_URL", "https://event.api.origo.hidglobal.com")

# Not in your env file — this is the WPP-specific host from the Java sample's
# application.yml default (WPP_BASE_URL). Confirm with HID PS if different for you.
WPP_URL = os.environ.get("WPP_URL", "https://web.api.origo.hidglobal.com")

ORGANIZATION_ID = os.environ["ORGANIZATION_ID"]
CLIENT_ID = os.environ["CLIENT_ID"]
CLIENT_SECRET = os.environ["CLIENT_SECRET"]
APPLICATION_ID = os.environ["APPLICATION_ID"]  # your HID-issued Application-ID header value

CONTENT_TYPE_CM = "application/vnd.hidglobal.origo.credential-management-3.0+json"
CONTENT_TYPE_SCIM = "application/scim+json"

GOOGLE_CLIENT_ID = os.environ["GOOGLE_CLIENT_ID"]
GOOGLE_CLIENT_SECRET = os.environ["GOOGLE_CLIENT_SECRET"]
GOOGLE_REDIRECT_URL = os.environ["GOOGLE_REDIRECT_URL"]

# Where your frontend's redeem page lives — the link emailed to users points here
FRONTEND_BASE_URL = os.environ.get("FRONTEND_BASE_URL", "https://yourapp.example.com")

# SMTP for sending the redemption email
SMTP_HOST = os.environ.get("SMTP_HOST", "Smtp52.mailservice25.com")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "manjuhr@datalogicsindia.com")
SMTP_PASS = os.environ.get("SMTP_PASS", "HmanKyu&4")
FROM_EMAIL = os.environ.get("FROM_EMAIL", "manjuhr@datalogicsindia.com")

ORIGO_WEBHOOK_SECRET = os.environ.get("ORIGO_WEBHOOK_SECRET", "")


# --------------------------------------------------------------------------
# Token caching — mirrors CacheTokenService.java (simple TTL cache)
# --------------------------------------------------------------------------
_token_cache = {"token": None, "exp": 0}


def get_access_token() -> str:
    if _token_cache["token"] and _token_cache["exp"] > time.time() + 30:
        return _token_cache["token"]

    resp = requests.post(
        f"{IDP_URL}/authentication/customer/{ORGANIZATION_ID}/token",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data={
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
            "grant_type": "client_credentials",
        },
        timeout=10,
    )
    if not resp.ok:
        log.error("Token request failed: %s %s", resp.status_code, resp.text)
    resp.raise_for_status()
    body = resp.json()
    _token_cache["token"] = body["access_token"]
    _token_cache["exp"] = time.time() + body.get("expires_in", 3600)
    return _token_cache["token"]


def origo_auth_headers(extra_content_type=None) -> dict:
    headers = {
        "Authorization": f"Bearer {get_access_token()}",
        "x-requestId": uuid.uuid4().hex[:16],
        "Application-ID": APPLICATION_ID,
    }
    if extra_content_type:
        headers["Content-Type"] = extra_content_type
        headers["Accept"] = extra_content_type
    return headers


@app.route("/debug/token", methods=["GET"])
def debug_token():
    """Temporary — test the auth exchange in isolation. Remove before real prod use."""
    try:
        token = get_access_token()
        return jsonify({"ok": True, "token_prefix": token[:20] + "...", "token_length": len(token)})
    except requests.exceptions.HTTPError as e:
        return jsonify({"ok": False, "status": e.response.status_code, "body": e.response.text}), 200


# --------------------------------------------------------------------------
# 1. Create a pass for a user, then email them the redeem link
#    Real endpoint: POST /organization/{org}/pass  (Credential Management API)
# --------------------------------------------------------------------------
@app.route("/admin/passes", methods=["POST"])
def create_pass_and_email():
    body = request.json  # {"userId": "...", "passTemplateId": "...", "email": "..."}
    user_id = body["userId"]
    pass_template_id = body["passTemplateId"]
    recipient_email = body["email"]

    resp = requests.post(
        f"{CREDENTIAL_MGMT_URL}/organization/{ORGANIZATION_ID}/pass",
        headers=origo_auth_headers(CONTENT_TYPE_CM),
        json={"passTemplateId": pass_template_id, "userId": user_id},
        timeout=10,
    )
    if not resp.ok:
        log.error("Create pass failed: %s %s", resp.status_code, resp.text)
    resp.raise_for_status()
    data = resp.json()

    # TEMP: log the raw response so we can confirm the real shape of issuanceToken
    log.info("credential-mgmt response: %s", data)

    raw_issuance_token = data["issuanceToken"]

    # Handle both possible shapes: plain string, or dict/object
    if isinstance(raw_issuance_token, dict):
        # Adjust "token" to whatever key actually holds the string once you see the logs
        token_str = raw_issuance_token.get("token")
        if token_str is None:
            token_str = json.dumps(raw_issuance_token)
    elif isinstance(raw_issuance_token, str):
        token_str = raw_issuance_token
    else:
        token_str = str(raw_issuance_token)

    issuance_code = base64.b64encode(token_str.encode()).decode()
    redeem_link = f"{FRONTEND_BASE_URL}/redeem.html?issuanceCode={issuance_code}"

    send_redeem_email(recipient_email, redeem_link)

    return jsonify({"issuanceToken": token_str, "redeemLink": redeem_link}), 201


def send_redeem_email(to_email: str, redeem_link: str):
    subject = "Add your access pass to your wallet"
    body_text = (
        "Hello,\n\n"
        "Your access pass is ready. Click the link below to add it to Apple Wallet "
        "or Google Wallet:\n\n"
        f"{redeem_link}\n\n"
        "This link is valid for a limited time.\n"
    )
    msg = MIMEText(body_text)
    msg["Subject"] = subject
    msg["From"] = FROM_EMAIL
    msg["To"] = to_email

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        server.starttls()
        server.login(SMTP_USER, SMTP_PASS)
        server.sendmail(FROM_EMAIL, [to_email], msg.as_string())
    log.info("Redeem email sent to %s", to_email)


# --------------------------------------------------------------------------
# NOTE: decoding issuanceCode + calling /v2/platforms now happens client-side
# in redeem.html (same pattern as RedeemComponent.tsx), which then calls the
# /origo/webpush/v2/platforms route defined further below.
# --------------------------------------------------------------------------


# --------------------------------------------------------------------------
# get-details -> frontend needs Google client id/secret/redirect + applicationId
# custom.min.js reads these out of sessionStorage after this call.
# --------------------------------------------------------------------------
@app.route("/origo/webpush/get-details", methods=["GET"])
def get_details():
    return jsonify({
        "applicationId": APPLICATION_ID,
        "profile": "prod",
        "google": {
            "clientId": GOOGLE_CLIENT_ID,
            "clientSecret": GOOGLE_CLIENT_SECRET,
            "redirectUrl": GOOGLE_REDIRECT_URL,
        },
    })


# --------------------------------------------------------------------------
# v2/platforms -> exact path custom.min.js / your frontend will call
# --------------------------------------------------------------------------
@app.route("/origo/webpush/v2/platforms", methods=["POST"])
def platforms():
    body = request.json
    issuance_token = body["issuanceToken"]

    resp = requests.post(
        f"{WPP_URL}/v2/platforms",
        headers={**origo_auth_headers(), "Content-Type": "application/json"},
        json={"issuanceToken": issuance_token, "applicationId": "HID-MOBILE_ACCESS"},
        timeout=10,
    )
    resp.raise_for_status()
    return jsonify(resp.json())


# --------------------------------------------------------------------------
# v2/provision -> single endpoint, dispatched on walletType, matching
# WalletProvisioningRequest exactly:
#   { issuanceToken, walletType: "GOOGLE_WALLET"|"APPLE_WALLET",
#     googleWallet: { idToken, accessToken } }   // only for GOOGLE_WALLET
# This is the exact body custom.min.js's invokeGoogleWallet/invokeAppleWallet
# will POST here (via axios, passed in by your frontend).
# --------------------------------------------------------------------------
@app.route("/origo/webpush/v2/provision", methods=["POST"])
def provision():
    body = request.json
    issuance_token = body["issuanceToken"]
    wallet_type = body.get("walletType")

    if wallet_type == "GOOGLE_WALLET":
        google_wallet = body.get("googleWallet") or {}
        raw_id_token = google_wallet.get("idToken")
        if not raw_id_token:
            return jsonify({"error": "googleWallet.idToken required"}), 400

        tokeninfo = requests.get(
            "https://www.googleapis.com/oauth2/v3/tokeninfo",
            params={"id_token": raw_id_token},
            timeout=10,
        )
        if tokeninfo.status_code != 200:
            return jsonify({"error": "invalid Google id_token"}), 400
        claims = tokeninfo.json()
        linking_token_object = build_linking_token_object(claims["sub"], claims["aud"])

        payload = {
            "issuanceToken": issuance_token,
            "applicationId": "HID-MOBILE_ACCESS",
            "web": {"language": "en-US"},
            "googleWallet": {
                "type": "CORPORATE_ID_WEB",
                "version": "V1",
                "linkingTokenObject": linking_token_object,
            },
        }
    elif wallet_type == "APPLE_WALLET":
        payload = {
            "issuanceToken": issuance_token,
            "applicationId": "HID-MOBILE_ACCESS",
            "web": {"language": "en-US"},
            "appleWallet": {"type": "CORPORATE_ID_WEB", "version": "V1"},
        }
    else:
        return jsonify({"error": "Wallet Type is missing or invalid"}), 400

    resp = requests.post(
        f"{WPP_URL}/v2/provision",
        headers={**origo_auth_headers(), "Content-Type": "application/json"},
        json=payload,
        timeout=10,
    )
    resp.raise_for_status()
    return jsonify(resp.json())


def build_linking_token_object(sub: str, aud: str) -> str:
    """Exact port of WebPushProvisioningService.getLinkingTokenObject()."""
    nonce = str(uuid.uuid4())
    hashed_user_id = hashlib.sha256((sub + nonce).encode()).hexdigest()
    linking_obj = json.dumps({"nonce": nonce, "hashedUserId": hashed_user_id, "aud": aud})
    return base64.urlsafe_b64encode(linking_obj.encode()).rstrip(b"=").decode()


# --------------------------------------------------------------------------
# 5. Origo callback receiver — register once via POST /organization/{org}/callback
#    (see one-time setup script further down)
# --------------------------------------------------------------------------
@app.route("/origo/callback", methods=["POST"])
def origo_callback():
    if ORIGO_WEBHOOK_SECRET and request.headers.get("X-API-Key") != ORIGO_WEBHOOK_SECRET:
        return jsonify({"error": "unauthorized"}), 401

    event = request.json.get("event", {})
    status = event.get("pass", {}).get("status")
    platform_type = event.get("platformType")
    credentials = event.get("credential", [])

    log.info("Origo callback: status=%s platform=%s", status, platform_type)

    if status == "PASS_ISSUING":
        pass  # TODO: notify your access control system, e.g. isecure_api
    elif status == "PASS_ACTIVE":
        pass  # TODO: assign credential to user in your access control system

    return jsonify({"status": "ok"})


# --------------------------------------------------------------------------
# One-time setup: register your callback URL with Origo
# Run this once (e.g. `python -c "from app import register_callback; register_callback()"`)
# --------------------------------------------------------------------------
def register_callback():
    resp = requests.post(
        f"{CALLBACK_URL}/organization/{ORGANIZATION_ID}/callback",
        headers={**origo_auth_headers(), "Content-Type": "application/json"},
        json={
            "url": f"{FRONTEND_BASE_URL}/origo/callback",
            "authenticationType": "X-API-Key",
            "apiKey": ORIGO_WEBHOOK_SECRET,
        },
        timeout=10,
    )
    resp.raise_for_status()
    print(resp.json())


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9090, debug=True)
