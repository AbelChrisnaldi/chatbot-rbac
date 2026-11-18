import hashlib
import hmac
import os
import secrets
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from dotenv import load_dotenv

load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET", "rahasia_modul2_jwt_2026")
JWT_ALGORITHM = "HS256"
security = HTTPBearer(auto_error=False)


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000)
    return f"{salt}${dk.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt, expected_hex = stored_hash.split("$", 1)
    except ValueError:
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000)
    return hmac.compare_digest(dk.hex(), expected_hex)


def create_access_token(username: str, admin_id: int) -> str:
    payload = {
        "sub": username,
        "admin_id": admin_id,
        "role": "admin",
        "exp": datetime.now(timezone.utc) + timedelta(hours=12),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def get_current_admin(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> dict:
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token admin tidak ditemukan. Silakan login terlebih dahulu.",
        )
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("role") != "admin":
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Akses khusus admin.")
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sesi login telah berakhir.")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token tidak valid.")


def create_user_access_token(username: str, user_id: int) -> str:
    payload = {
        "sub": username,
        "user_id": user_id,
        "token_type": "user",
        "exp": datetime.now(timezone.utc) + timedelta(hours=8),
    }

    return jwt.encode(
        payload,
        JWT_SECRET,
        algorithm=JWT_ALGORITHM
    )


def get_current_identity(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
) -> dict:

    # Memastikan pengguna mengirimkan token
    if not credentials or not credentials.credentials:
        raise HTTPException(
            status_code=401,
            detail="Silakan login untuk mengakses chatbot."
        )

    # Memvalidasi JWT
    try:
        payload = jwt.decode(
            credentials.credentials,
            JWT_SECRET,
            algorithms=[JWT_ALGORITHM]
        )

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=401,
            detail="Sesi login telah berakhir."
        )

    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Token tidak valid."
        )

    # Import di sini untuk menghindari circular import
    from app.database import get_connection

    conn = get_connection()

    try:
        # Memeriksa identitas admin
        if (
            payload.get("role") == "admin"
            and isinstance(payload.get("admin_id"), int)
        ):
            row = conn.execute(
                "SELECT id, username FROM admins WHERE id = ?",
                (payload["admin_id"],)
            ).fetchone()

            if row and row["username"] == payload.get("sub"):
                return {
                    "type": "admin",
                    "id": row["id"],
                    "username": row["username"],
                    "role": "admin"
                }

        # Memeriksa identitas mahasiswa atau dosen
        elif (
            payload.get("token_type") == "user"
            and isinstance(payload.get("user_id"), int)
        ):
            row = conn.execute("""
                SELECT
                    u.id,
                    u.username,
                    r.name AS role
                FROM users u
                JOIN roles r ON r.id = u.role_id
                WHERE u.id = ?
                AND u.is_active = 1
            """, (payload["user_id"],)).fetchone()

            if row and row["username"] == payload.get("sub"):
                return {
                    "type": "user",
                    "id": row["id"],
                    "username": row["username"],
                    "role": row["role"]
                }

    finally:
        conn.close()

    raise HTTPException(
        status_code=401,
        detail="Akun tidak ditemukan atau akses sudah dicabut."
    )

def get_current_user(
    identity: dict = Depends(get_current_identity)
) -> dict:

    if identity["type"] != "user":
        raise HTTPException(
            status_code=403,
            detail="Gunakan akun mahasiswa atau dosen untuk chatbot."
        )

    return identity
