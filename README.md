# SMCI License Generator

A FastAPI-based license generation tool with a web UI for authenticated users. Licenses are signed, encrypted, and optionally stored in Supabase.

## Features
- Web UI served from `index.html`
- User authentication against Supabase `smci-auth` table
- Generates signed, encrypted `.lic` license files
- Auto-increments license IDs like `SMCI-CLIENT-01`
- License reissue support for existing records
- Password hashing supports PBKDF2 and bcrypt

## Requirements
- Python 3.10+
- `fastapi`
- `uvicorn`
- `cryptography`
- `python-dotenv`
- `requests`
- `bcrypt` (optional, only required for bcrypt password hashes)

Install dependencies:

```bash
pip install -r requirements.txt
```

## Setup

### 1. Generate keys

Run:

```bash
python generate_keys.py
```

Copy the generated values into `.env` in the project root.

### 2. Configure `.env`

Create `licence-generator/.env` with:

```env
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_SERVICE_ROLE_KEY=your-service-role-key
LICENSE_PRIVATE_KEY_B64=...
LICENSE_ENC_KEY_B64=...
```

### 3. Configure Supabase

The app expects these tables in Supabase:

- `smci-licence-users`
- `smci-auth`

#### `smci-auth` table
Columns:
- `user_id` (text, primary key)
- `password_hash` (text)
- `status` (integer)

A user must have `status = 1` to login successfully.

## Password Hashing

Supported password formats:

- PBKDF2:
  ```
pbkdf2$120000$<base64_salt>$<base64_hash>
```
- bcrypt:
  - Any bcrypt hash starting with `$2`

Generate a PBKDF2 password hash:

```bash
python -c "import os,hashlib,base64; salt=os.urandom(16); dk=hashlib.pbkdf2_hmac('sha256', b'YOUR_PASSWORD', salt, 120000); print('pbkdf2$120000$'+base64.b64encode(salt).decode()+'$'+base64.b64encode(dk).decode())"
```

## Run the app

Start the server:

```bash
python app.py
```

Open in your browser:

```text
http://localhost:9000
```

## Usage

1. Login with a Supabase user from `smci-auth`.
2. Generate a new license by entering:
   - Name
   - Contact (email or phone)
   - Organization
   - Expiry date
3. Download the signed and encrypted `.lic` file.
4. Reissue a license using an existing `license_id`.

## API Endpoints

- `GET /` - Serve the UI
- `GET /api/auth/me` - Check current session
- `POST /api/auth/login` - Login with `user_id` and `password`
- `POST /api/auth/logout` - Logout
- `POST /api/auth/update_password` - Update password
- `GET /api/licenses/next` - Get next license ID
- `GET /api/licenses` - List licenses
- `POST /api/generate` - Generate a new license
- `POST /api/reissue` - Reissue an existing license

## Notes

- `generate_keys.py` also prints `LICENSE_PUBLIC_KEY_B64`, but `app.py` only requires the private and encryption keys.
- `counter.txt` is included, but license storage and auth rely on Supabase.
- Authentication and license generation require Supabase to be configured correctly.

## Troubleshooting

- If login fails, verify `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY`.
- If license generation fails, ensure the auth user is active and the license table exists.
- Ensure `LICENSE_PRIVATE_KEY_B64` and `LICENSE_ENC_KEY_B64` are valid Base64 values.
