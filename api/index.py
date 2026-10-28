#!/usr/bin/env python3
"""
AgriStack Token API — Vercel serverless (14 states)
- No threads, no background refresh
- In-memory cache (warm containers only)
- Single state per request
"""

import os, json, time, base64, re, uuid, logging
from io import BytesIO
from urllib.parse import unquote
import requests
from bs4 import BeautifulSoup
from PIL import Image
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from flask import Flask, jsonify

logging.basicConfig(level=logging.INFO)
log = logging.getLogger("agristack")

# Lazy load OCR only when needed (Vercel cold start speed)
_ocr = None
def get_ocr():
    global _ocr
    if _ocr is None:
        try:
            import ddddocr
            _ocr = ddddocr.DdddOcr(show_ad=False)
        except Exception as e:
            log.error("ddddocr init failed: %s", e)
            _ocr = False
    return _ocr

RSA_PUB_KEY = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC9BLl8HcSzbdYg5S50RfMznsJf
zzefjAUuYkWS9vViuzs4vw59bbEsIu4bjAlyyTusg8luuXPA9SvO4zYgj1rxe42f
i+tISEuwIcL0f0I+PgmbIBPOhSnTVYmXFmtbZxXgSfLYyzq0WGNZDLJ0s5V1cE6e
EFTb/F6ZCp79sd+/UQIDAQAB
-----END PUBLIC KEY-----"""

def _cred(state):
    return {
        "id": os.environ.get(f"CSC_ID_{state}", ""),
        "password": os.environ.get(f"CSC_PW_{state}", ""),
    }

WORKING_CREDS = {
    "AS": _cred("AS"), "BR": _cred("BR"), "CG": _cred("CG"),
    "GJ": _cred("GJ"), "MH": _cred("MH"), "MP": _cred("MP"),
    "OD": _cred("OD"), "PB": _cred("PB"), "RJ": _cred("RJ"),
    "TN": _cred("TN"), "TR": _cred("TR"), "UK": _cred("UK"),
    "UP": _cred("UP"), "WB": _cred("WB"),
}

WORKING_STATE_CONFIG = {
    "AS": {"full": "asfr", "sub": "as"},
    "BR": {"full": "bhfr", "sub": "bh"},
    "CG": {"full": "cgfr", "sub": "cg"},
    "GJ": {"full": "gjfr", "sub": "gj"},
    "MH": {"full": "mhfr", "sub": "mh"},
    "MP": {"full": "mpfr", "sub": "mp"},
    "OD": {"full": "odfr", "sub": "od"},
    "PB": {"full": "pbfr", "sub": "pb"},
    "RJ": {"full": "rjfr", "sub": "rj"},
    "TN": {"full": "tnfr", "sub": "tn"},
    "TR": {"full": "trfr", "sub": "tr"},
    "UK": {"full": "ukfr", "sub": "uk"},
    "UP": {"full": "upfr", "sub": "up"},
    "WB": {"full": "wbfr", "sub": "wb"},
}
ALL_STATES = sorted(WORKING_CREDS.keys())

# In-memory cache (per-container)
_cache = {}

def cache_set(state, user_token, auth_token, dpop_pem, expires_in):
    _cache[state] = {
        "user_token": user_token, "auth_token": auth_token,
        "dpop_private_key": dpop_pem,
        "expires_at": time.time() + expires_in,
        "fetched_at": time.time(),
    }

def cache_get(state, buffer_sec=30):
    d = _cache.get(state)
    if not d: return None
    if time.time() >= d["expires_at"] - buffer_sec: return None
    return dict(d)

def gen_dpop_key():
    return ec.generate_private_key(ec.SECP256R1(), default_backend())

def key_to_pem(key):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

def gen_dpop_proof(key, method, url):
    pub = key.public_key().public_numbers()
    x = base64.urlsafe_b64encode(pub.x.to_bytes(32, 'big')).rstrip(b'=').decode()
    y = base64.urlsafe_b64encode(pub.y.to_bytes(32, 'big')).rstrip(b'=').decode()
    h = {"typ": "dpop+jwt", "alg": "ES256",
         "jwk": {"kty": "EC", "crv": "P-256", "x": x, "y": y}}
    p = {"jti": str(uuid.uuid4()), "htm": method.upper(),
         "htu": url, "iat": int(time.time())}
    hb = base64.urlsafe_b64encode(json.dumps(h).encode()).rstrip(b'=').decode()
    pb = base64.urlsafe_b64encode(json.dumps(p).encode()).rstrip(b'=').decode()
    sig = key.sign(f"{hb}.{pb}".encode(), ec.ECDSA(hashes.SHA256()))
    return f"{hb}.{pb}." + base64.urlsafe_b64encode(sig).rstrip(b'=').decode()

def enc_pass(rvar, user, password):
    bu = base64.b64encode(user.encode()).decode()
    bp = base64.b64encode(password.encode()).decode()
    bc = base64.b64encode(f"{rvar}@{bu}@{bp}".encode()).decode()
    key = serialization.load_pem_public_key(RSA_PUB_KEY.encode(), backend=default_backend())
    return base64.b64encode(key.encrypt(bc.encode(), padding.PKCS1v15())).decode()

def solve_captcha(b64_str):
    ocr = get_ocr()
    if not ocr:
        raise RuntimeError("OCR unavailable")
    if "base64," in b64_str:
        b64_str = b64_str.split("base64,")[1]
    b64_str = b64_str.strip().strip('"').strip("'").split('?')[0]
    raw = base64.b64decode(b64_str)
    return ocr.classification(Image.open(BytesIO(raw)).convert("RGB"))

def login_state(state_code):
    cred = WORKING_CREDS[state_code]
    cfg = WORKING_STATE_CONFIG[state_code]
    if not cred["id"] or not cred["password"]:
        log.error("[%s] missing credentials in env", state_code)
        return None

    base_url = f"https://{cfg['full']}.agristack.gov.in"
    sub = cfg['sub']

    try:
        s = requests.Session()
        s.headers.update({"User-Agent": "Mozilla/5.0 (Linux; Android 15; 2312FRAFDI) AppleWebKit/537.36 Chrome/149 Mobile Safari/537.36"})
        key = gen_dpop_key()
        dpop_pem = key_to_pem(key)

        url1 = f"{base_url}/farmer-registry-api-{sub}/agristack/v1/api/csc/auth/url"
        r = s.get(url1, headers={"dpop": gen_dpop_proof(key, "GET", url1),
                                  "accept": "application/json",
                                  "referer": f"{base_url}/farmer-registry-{sub}/"}, timeout=8)
        if r.status_code != 200: return None
        auth_url = r.json()["data"]
        m = re.search(r'state=([^&]+)', auth_url)
        if not m: return None
        state_val = m.group(1)

        r = s.get(auth_url, headers={"accept": "text/html"}, timeout=8)
        html = r.text or ""
        soup = BeautifulSoup(html, "lxml")

        csrf = None
        for c in s.cookies:
            if c.name == "csrf_cookie_name":
                csrf = c.value; break
        if not csrf:
            inp = soup.find("input", {"name": "csrf_test_name"})
            if inp: csrf = inp.get("value")
        if not csrf:
            for inp in soup.find_all("input", {"type": "hidden"}):
                nm = (inp.get("name") or "").lower()
                if "csrf" in nm or "token" in nm:
                    csrf = inp.get("value"); break

        rvar_m = re.search(r'var rvar = "(\d+)"', html)
        rvar = rvar_m.group(1) if rvar_m else "771129"

        cap = None
        ci = soup.find("div", {"id": "captchaimgs"})
        if ci:
            img = ci.find("img")
            if img and img.get("src"): cap = img["src"]
        if not cap:
            mm = re.search(r'data:image/(jpeg|png);base64,([A-Za-z0-9+/=]+)', html)
            if mm: cap = f"data:image/{mm.group(1)};base64,{mm.group(2)}"
        if not cap:
            for img in soup.find_all("img"):
                src = img.get("src") or ""
                if "captcha" in src.lower(): cap = src; break

        if not csrf or not cap: return None

        captcha = solve_captcha(cap)
        ep = enc_pass(rvar, cred["id"], cred["password"])

        r = s.post(auth_url, data={
            "csrf_test_name": csrf, "csclogin": cred["id"],
            "password": ep, "captcha": captcha, "login": "Log In"
        }, headers={"content-type": "application/x-www-form-urlencoded",
                    "origin": "https://connect.csc.gov.in",
                    "referer": auth_url}, allow_redirects=False, timeout=8)

        if r.status_code not in (302, 303): return None

        loc = r.headers.get("Location", "")
        code = None
        cm = re.search(r'[?&]code=([^&]+)', loc)
        if cm: code = cm.group(1)
        else:
            frag = loc.split('#', 1)[1] if '#' in loc else loc
            um = re.search(r'url=([^&]+)', frag)
            if um:
                cm2 = re.search(r'code=([^&]+)', unquote(um.group(1)))
                if cm2: code = cm2.group(1)
        if not code: return None

        url4 = f"{base_url}/farmer-registry-api-{sub}/agristack/v1/api/csc/fr/login?code={code}&state={state_val}"
        r = s.get(url4, headers={"referer": "https://connect.csc.gov.in/"}, allow_redirects=False, timeout=8)

        bearer = None
        if r.status_code in (301, 302, 303):
            tm = re.search(r'token=([^&]+)', r.headers.get("Location", ""))
            if tm: bearer = tm.group(1)
        if not bearer:
            r2 = s.get(url4, headers={"referer": "https://connect.csc.gov.in/"}, allow_redirects=True, timeout=8)
            if r2.url:
                tm = re.search(r'token=([^&]+)', r2.url)
                if tm: bearer = tm.group(1)
        if not bearer: return None

        url5 = f"{base_url}/farmer-registry-api-{sub}/agristack/v1/api/authenticate/user/token"
        r = s.post(url5, json={"token": bearer}, headers={
            "authorization": f"Bearer {bearer}",
            "dpop": gen_dpop_proof(key, "POST", url5),
            "content-type": "application/json",
            "origin": base_url,
            "referer": f"{base_url}/farmer-registry-{sub}/"
        }, timeout=8)

        try: j = r.json()
        except: return None
        if j.get("status") != "success": return None

        ud = j["data"]
        return {
            "ok": True, "csc_id": cred["id"],
            "user_token": ud["userToken"],
            "auth_token": ud.get("loginLogoutActivityLog", {}).get("authToken") or ud["userToken"],
            "user_id": ud.get("userId"),
            "expires_in": ud.get("tokenExpiresIn", 900),
            "dpop_private_key": dpop_pem,
        }
    except Exception as e:
        log.error("[%s] login error: %s", state_code, e)
        return None

def refresh_state(state_code):
    res = login_state(state_code)
    if res and res.get("ok"):
        cache_set(state_code, res["user_token"], res["auth_token"],
                  res["dpop_private_key"], res["expires_in"])
        log.info("[%s] cached csc=%s user=%s", state_code, res["csc_id"], res.get("user_id"))
        return True
    log.warning("[%s] refresh failed", state_code)
    return False

app = Flask(__name__)

@app.after_request
def _cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp

@app.route("/", methods=["GET"])
def index():
    now = time.time()
    return jsonify({
        "status": "success",
        "service": "agristack-vercel",
        "states": ALL_STATES,
        "cache": {s: {
            "cached": s in _cache and _cache[s]["expires_at"] > now,
            "expires_in": int(_cache[s]["expires_at"] - now) if s in _cache else 0,
        } for s in ALL_STATES},
    })

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "ts": int(time.time())})

@app.route("/<state>", methods=["GET"])
def get_token(state):
    state = state.upper()
    if state not in WORKING_CREDS:
        return jsonify({"status": False, "message": f"Unsupported: {state}",
                        "supported": ALL_STATES}), 400

    cached = cache_get(state)
    if cached:
        return jsonify({
            "status": "success", "state": state, "cached": True,
            "user_token": cached["user_token"],
            "auth_token": cached["auth_token"],
            "dpop_private_key": cached["dpop_private_key"],
            "expires_in": int(cached["expires_at"] - time.time()),
            "age_sec": int(time.time() - cached["fetched_at"]),
        })

    t0 = time.time()
    ok = refresh_state(state)
    elapsed = round(time.time() - t0, 2)
    if not ok:
        return jsonify({"status": False, "state": state,
                        "message": "login failed", "elapsed_sec": elapsed}), 502

    c = cache_get(state)
    return jsonify({
        "status": "success", "state": state, "cached": False,
        "user_token": c["user_token"], "auth_token": c["auth_token"],
        "dpop_private_key": c["dpop_private_key"],
        "expires_in": int(c["expires_at"] - time.time()),
        "elapsed_sec": elapsed,
    })

@app.route("/<state>/refresh", methods=["GET", "POST"])
def force_refresh(state):
    state = state.upper()
    if state not in WORKING_CREDS:
        return jsonify({"status": False, "message": f"Unsupported: {state}"}), 400
    t0 = time.time()
    ok = refresh_state(state)
    elapsed = round(time.time() - t0, 2)
    if ok:
        c = cache_get(state)
        return jsonify({
            "status": "success", "state": state,
            "user_token": c["user_token"], "auth_token": c["auth_token"],
            "dpop_private_key": c["dpop_private_key"],
            "expires_in": int(c["expires_at"] - time.time()),
            "elapsed_sec": elapsed,
        })
    return jsonify({"status": False, "state": state, "elapsed_sec": elapsed}), 502
