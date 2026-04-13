import os
import json
import base64
import secrets
import re
import hashlib
import hmac
from datetime import datetime, timedelta, timezone
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, FileResponse, Response, JSONResponse

from dotenv import load_dotenv, dotenv_values
import requests

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    import bcrypt
except Exception:
    bcrypt = None

MAGIC = b"SMCI1"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ENV_PATH = os.path.join(BASE_DIR, ".env")


def _load_env() -> None:
    # Load explicitly from local .env (handles BOM via utf-8-sig)
    if os.path.exists(ENV_PATH):
        try:
            values = dotenv_values(ENV_PATH, encoding="utf-8-sig")
            for k, v in values.items():
                if v is None:
                    continue
                os.environ[k] = v.strip().strip('"').strip("'")
        except Exception:
            pass
    load_dotenv(ENV_PATH, override=True)


_load_env()

SUPABASE_URL = (os.getenv("SUPABASE_URL", "") or "").strip()
SUPABASE_SERVICE_ROLE_KEY = (os.getenv("SUPABASE_SERVICE_ROLE_KEY", "") or "").strip()
LICENSE_PRIVATE_KEY_B64 = (os.getenv("LICENSE_PRIVATE_KEY_B64", "") or "").strip()
LICENSE_ENC_KEY_B64 = (os.getenv("LICENSE_ENC_KEY_B64", "") or "").strip()

TABLE_LICENSE = "smci-licence-users"
TABLE_AUTH = "smci-auth"

SESSION_COOKIE = "smci_session"
SESSION_TTL_SEC = 12 * 60 * 60
SESSIONS: dict[str, dict] = {}

app = FastAPI(title="SMCI License Generator")

INDEX_HTML = os.path.join(BASE_DIR, "index.html")
LOCAL_COUNTER_FILE = os.path.join(BASE_DIR, "counter.txt")


def _b64(s: bytes) -> str:
    return base64.b64encode(s).decode("utf-8")


def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("utf-8"))


def _get_private_key() -> Ed25519PrivateKey:
    if not LICENSE_PRIVATE_KEY_B64:
        raise RuntimeError("LICENSE_PRIVATE_KEY_B64 not set")
    key_bytes = _b64d(LICENSE_PRIVATE_KEY_B64)
    return Ed25519PrivateKey.from_private_bytes(key_bytes)


def _get_enc_key() -> bytes:
    if not LICENSE_ENC_KEY_B64:
        raise RuntimeError("LICENSE_ENC_KEY_B64 not set")
    key = _b64d(LICENSE_ENC_KEY_B64)
    if len(key) not in (16, 24, 32):
        raise RuntimeError("Invalid encryption key length")
    return key


def _sign_and_encrypt(data: dict) -> bytes:
    priv = _get_private_key()
    enc_key = _get_enc_key()

    data_bytes = json.dumps(data, sort_keys=True).encode("utf-8")
    sig = priv.sign(data_bytes)
    package = {
        "data": _b64(data_bytes),
        "sig": _b64(sig)
    }
    pkg_bytes = json.dumps(package).encode("utf-8")

    aes = AESGCM(enc_key)
    nonce = os.urandom(12)
    ct = aes.encrypt(nonce, pkg_bytes, None)
    return MAGIC + nonce + ct


def _supabase_enabled() -> bool:
    return bool(SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY)


def _supabase_headers(prefer: str = "return=minimal") -> dict:
    return {
        "apikey": SUPABASE_SERVICE_ROLE_KEY,
        "Authorization": f"Bearer {SUPABASE_SERVICE_ROLE_KEY}",
        "Content-Type": "application/json",
        "Prefer": prefer
    }


def _parse_license_number(license_id: str) -> int:
    if not license_id:
        return 0
    prefix = "SMCI-CLIENT-"
    if not license_id.startswith(prefix):
        return 0
    tail = license_id[len(prefix):].strip()
    return int(tail) if tail.isdigit() else 0


def _format_license_id(n: int) -> str:
    return f"SMCI-CLIENT-{str(n).zfill(2)}"


def _get_total_users() -> int:
    if not _supabase_enabled():
        return 0
    url = f"{SUPABASE_URL.rstrip('/')}/rest/v1/{TABLE_LICENSE}?select=license_id&limit=1"
    try:
        res = requests.get(url, headers=_supabase_headers(prefer="count=exact"), timeout=10)
        if not res.ok:
            return 0
        content_range = res.headers.get("content-range") or res.headers.get("Content-Range")
        if content_range and "/" in content_range:
            total = content_range.split("/")[-1]
            return int(total)
    except Exception:
        return 0
    return 0


def _get_last_license_number() -> int:
    if not _supabase_enabled():
        return 0
    url = f"{SUPABASE_URL.rstrip('/')}/rest/v1/{TABLE_LICENSE}?select=license_id&order=created_at.desc&limit=1"
    try:
        res = requests.get(url, headers=_supabase_headers(prefer="count=exact"), timeout=10)
        if not res.ok:
            return 0
        data = res.json()
        if not data:
            return 0
        return _parse_license_number(data[0].get("license_id", ""))
    except Exception:
        return 0


def _next_local_counter() -> int:
    n = 0
    try:
        if os.path.exists(LOCAL_COUNTER_FILE):
            with open(LOCAL_COUNTER_FILE, "r", encoding="utf-8") as f:
                n = int((f.read() or "0").strip())
    except Exception:
        n = 0
    n += 1
    try:
        with open(LOCAL_COUNTER_FILE, "w", encoding="utf-8") as f:
            f.write(str(n))
    except Exception:
        pass
    return n


def _save_to_supabase(record: dict) -> tuple[bool, str]:
    if not _supabase_enabled():
        return True, ""
    url = f"{SUPABASE_URL.rstrip('/')}/rest/v1/{TABLE_LICENSE}"
    try:
        res = requests.post(url, headers=_supabase_headers(prefer="return=minimal"), json=record, timeout=10)
        if res.status_code in (200, 201, 204):
            return True, ""
        if res.status_code == 409:
            return False, "conflict"
        return False, f"Supabase error ({res.status_code}): {res.text}"
    except Exception as e:
        return False, f"Supabase error: {e}"


def _hash_password(password: str, salt: bytes | None = None) -> str:
    if salt is None:
        salt = secrets.token_bytes(16)
    iterations = 120000
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return f"pbkdf2${iterations}${_b64(salt)}${_b64(dk)}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        if stored.startswith("pbkdf2$"):
            parts = stored.split("$")
            if len(parts) != 4 or parts[0] != "pbkdf2":
                return False
            iterations = int(parts[1])
            salt = _b64d(parts[2])
            expected = _b64d(parts[3])
            dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
            return hmac.compare_digest(dk, expected)
        if stored.startswith("$2"):
            if bcrypt is None:
                return False
            return bcrypt.checkpw(password.encode("utf-8"), stored.encode("utf-8"))
        return False
    except Exception:
        return False

def _valid_contact(contact: str) -> bool:
    if not contact:
        return False
    email = re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", contact)
    phone = re.match(r"^[+]?\d[\d\s\-()]{6,}$", contact)
    return bool(email or phone)
def _get_auth_user(user_id: str) -> dict | None:
    if not _supabase_enabled():
        return None
    url = f"{SUPABASE_URL.rstrip('/')}/rest/v1/{TABLE_AUTH}"
    params = {
        "select": "user_id,password_hash,status",
        "user_id": f"eq.{user_id}",
        "limit": "1"
    }
    try:
        res = requests.get(url, headers=_supabase_headers(prefer="count=exact"), params=params, timeout=10)
        if not res.ok:
            return None
        data = res.json()
        if not data:
            return None
        return data[0]
    except Exception:
        return None


def _update_password(user_id: str, new_hash: str) -> tuple[bool, str]:
    if not _supabase_enabled():
        return False, "Supabase not configured"
    url = f"{SUPABASE_URL.rstrip('/')}/rest/v1/{TABLE_AUTH}?user_id=eq.{user_id}"
    try:
        res = requests.patch(url, headers=_supabase_headers(prefer="return=minimal"), json={"password_hash": new_hash}, timeout=10)
        if res.status_code in (200, 204):
            return True, ""
        return False, f"Supabase error ({res.status_code}): {res.text}"
    except Exception as e:
        return False, f"Supabase error: {e}"


def _create_session(user_id: str) -> str:
    token = secrets.token_urlsafe(32)
    SESSIONS[token] = {
        "user_id": user_id,
        "created": datetime.now(timezone.utc).timestamp()
    }
    return token


def _get_session(request: Request) -> dict | None:
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    s = SESSIONS.get(token)
    if not s:
        return None
    if datetime.now(timezone.utc).timestamp() - s.get("created", 0) > SESSION_TTL_SEC:
        SESSIONS.pop(token, None)
        return None
    return s


def _require_auth(request: Request) -> tuple[bool, str | None]:
    if not _supabase_enabled():
        return False, "Supabase not configured"
    session = _get_session(request)
    if not session:
        return False, "Not authenticated"
    return True, session["user_id"]


def _query_licenses(search: str, page: int, page_size: int) -> tuple[list, int]:
    if not _supabase_enabled():
        return [], 0
    page = max(page, 1)
    page_size = max(min(page_size, 50), 1)
    start = (page - 1) * page_size
    end = start + page_size - 1
    url = f"{SUPABASE_URL.rstrip('/')}/rest/v1/{TABLE_LICENSE}"
    params = {
        "select": "license_id,name,organization,contact,expiry,issued_at,created_at",
        "order": "created_at.desc"
    }
    if search:
        q = search.replace("*", "").replace("%", "")
        params["or"] = f"(license_id.ilike.*{q}*,name.ilike.*{q}*,organization.ilike.*{q}*,contact.ilike.*{q}*)"
    headers = _supabase_headers(prefer="count=exact")
    headers["Range"] = f"{start}-{end}"
    try:
        res = requests.get(url, headers=headers, params=params, timeout=10)
        if not res.ok:
            return [], 0
        data = res.json()
        content_range = res.headers.get("content-range") or res.headers.get("Content-Range")
        total = 0
        if content_range and "/" in content_range:
            total = int(content_range.split("/")[-1])
        return data, total
    except Exception:
        return [], 0


@app.get("/")
async def index():
    if os.path.exists(INDEX_HTML):
        return FileResponse(INDEX_HTML)
    return HTMLResponse("License tool UI not found", status_code=404)


@app.get("/logo.png")
async def get_logo():
    logo_path = os.path.join(BASE_DIR, "logo.png")
    if os.path.exists(logo_path):
        return FileResponse(logo_path)
    return Response(status_code=404)


@app.get("/api/auth/me")
async def auth_me(request: Request):
    ok, user_id = _require_auth(request)
    if not ok:
        return {"authenticated": False}
    return {"authenticated": True, "user_id": user_id}


@app.post("/api/auth/login")
async def auth_login(body: dict):
    user_id = (body.get("user_id") or "").strip()
    password = body.get("password") or ""
    if not user_id or not password:
        return JSONResponse({"success": False, "error": "Missing user id or password"}, status_code=400)

    user = _get_auth_user(user_id)
    if not user:
        return JSONResponse({"success": False, "error": "Invalid credentials"}, status_code=401)
    if int(user.get("status", 0)) != 1:
        return JSONResponse({"success": False, "error": "User is inactive"}, status_code=403)
    if not _verify_password(password, user.get("password_hash", "")):
        return JSONResponse({"success": False, "error": "Invalid credentials"}, status_code=401)

    token = _create_session(user_id)
    resp = JSONResponse({"success": True, "user_id": user_id})
    resp.set_cookie(SESSION_COOKIE, token, httponly=True, samesite="Lax")
    return resp


@app.post("/api/auth/logout")
async def auth_logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        SESSIONS.pop(token, None)
    resp = JSONResponse({"success": True})
    resp.delete_cookie(SESSION_COOKIE)
    return resp


@app.post("/api/auth/update_password")
async def auth_update_password(request: Request, body: dict):
    ok, user_id = _require_auth(request)
    if not ok:
        return JSONResponse({"success": False, "error": user_id}, status_code=401)

    current_password = body.get("current_password") or ""
    new_password = body.get("new_password") or ""
    if not current_password or not new_password:
        return JSONResponse({"success": False, "error": "Missing password"}, status_code=400)

    user = _get_auth_user(user_id)
    if not user or not _verify_password(current_password, user.get("password_hash", "")):
        return JSONResponse({"success": False, "error": "Current password invalid"}, status_code=401)

    new_hash = _hash_password(new_password)
    ok2, err = _update_password(user_id, new_hash)
    if not ok2:
        return JSONResponse({"success": False, "error": err}, status_code=500)
    return {"success": True}


@app.get("/api/licenses/next")
async def licenses_next(request: Request):
    ok, _ = _require_auth(request)
    if not ok:
        return JSONResponse({"success": False, "error": "Not authenticated"}, status_code=401)
    total = _get_total_users()
    last = _get_last_license_number()
    next_id = _format_license_id(max(total, last) + 1)
    return {"success": True, "next_id": next_id, "total": total}


@app.get("/api/licenses")
async def licenses_list(request: Request, search: str = "", page: int = 1, page_size: int = 10):
    ok, _ = _require_auth(request)
    if not ok:
        return JSONResponse({"success": False, "error": "Not authenticated"}, status_code=401)
    data, total = _query_licenses(search, page, page_size)
    return {"success": True, "items": data, "total": total, "page": page, "page_size": page_size}


@app.post("/api/generate")
async def generate_license(request: Request, body: dict):
    ok, user_id = _require_auth(request)
    if not ok:
        return JSONResponse({"success": False, "error": user_id}, status_code=401)

    name = (body.get("name") or "").strip()
    contact = (body.get("contact") or "").strip()
    organization = (body.get("organization") or "").strip()
    expiry = (body.get("expiry") or "").strip()  # MM-DD-YYYY
    if not name or not contact or not organization or not expiry:
        return JSONResponse({"success": False, "error": "All fields are required"}, status_code=400)

    # validate date
    exp_dt = datetime.strptime(expiry, "%m-%d-%Y").date()
    if exp_dt < datetime.now().date():
        return JSONResponse({"success": False, "error": "Expiry must be today or later"}, status_code=400)

    if not _valid_contact(contact):
        return JSONResponse({"success": False, "error": "Invalid contact (email or phone)"}, status_code=400)
    # Generate hidden license key (random hash-like string)
    license_key_hash = secrets.token_hex(32)
    issued_at = datetime.now().strftime("%m-%d-%Y")

    license_id = ""
    base = max(_get_total_users(), _get_last_license_number())
    last_err = ""
    for i in range(1, 6):
        candidate = _format_license_id(base + i)
        record = {
            "license_id": candidate,
            "name": name,
            "contact": contact,
            "organization": organization,
            "expiry": expiry,
            "license_key_hash": license_key_hash,
            "issued_at": issued_at
        }
        ok2, last_err = _save_to_supabase(record)
        if ok2:
            license_id = candidate
            break
        if last_err != "conflict":
            return JSONResponse({"success": False, "error": last_err}, status_code=500)
    if not license_id:
        return JSONResponse({"success": False, "error": "Failed to assign license id"}, status_code=500)

    data = {
        "license_id": license_id,
        "name": name,
        "contact": contact,
        "organization": organization,
        "expiry": expiry,
        "license_key_hash": license_key_hash,
        "issued_at": issued_at,
        "issued_by": user_id
    }

    lic_bytes = _sign_and_encrypt(data)

    headers = {
        "Content-Disposition": f"attachment; filename={license_id}.lic",
        "X-License-Id": license_id
    }
    return Response(content=lic_bytes, media_type="application/octet-stream", headers=headers)


@app.post("/api/reissue")
async def reissue_license(request: Request, body: dict):
    ok, user_id = _require_auth(request)
    if not ok:
        return JSONResponse({"success": False, "error": user_id}, status_code=401)
        
    license_id = (body.get("license_id") or "").strip()
    if not license_id:
        return JSONResponse({"success": False, "error": "Missing license id"}, status_code=400)
        
    if not _supabase_enabled():
        return JSONResponse({"success": False, "error": "Supabase not configured"}, status_code=500)
        
    url = f"{SUPABASE_URL.rstrip('/')}/rest/v1/{TABLE_LICENSE}"
    params = {
        "select": "license_id,name,contact,organization,expiry,license_key_hash,issued_at", 
        "license_id": f"eq.{license_id}", 
        "limit": "1"
    }
    
    try:
        res = requests.get(url, headers=_supabase_headers(prefer="count=exact"), params=params, timeout=10)
        if not res.ok:
            return JSONResponse({"success": False, "error": "Database error"}, status_code=500)
        data_list = res.json()
        if not data_list:
            return JSONResponse({"success": False, "error": "License not found"}, status_code=404)
            
        record = data_list[0]
    except Exception as e:
        return JSONResponse({"success": False, "error": str(e)}, status_code=500)
        
    data = {
        "license_id": record.get("license_id"),
        "name": record.get("name"),
        "contact": record.get("contact"),
        "organization": record.get("organization"),
        "expiry": record.get("expiry"),
        "license_key_hash": record.get("license_key_hash"),
        "issued_at": record.get("issued_at"),
        "issued_by": user_id
    }
    
    lic_bytes = _sign_and_encrypt(data)
    
    headers = {
        "Content-Disposition": f"attachment; filename={license_id}.lic",
        "X-License-Id": license_id
    }
    return Response(content=lic_bytes, media_type="application/octet-stream", headers=headers)

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9000)



