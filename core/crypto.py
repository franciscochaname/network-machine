# core/crypto.py
"""
Motor de Cifrado Simétrico para credenciales de infraestructura.
Usa Fernet (AES-128-CBC + HMAC-SHA256) para proteger contraseñas de routers en SQLite.
La clave maestra se lee del .env (SECRET_KEY) y se deriva con PBKDF2.
"""
import os
import base64
import hashlib
import logging
from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger("crypto")

def _derive_key() -> bytes:
    """Deriva una clave Fernet válida (32 bytes base64) a partir del SECRET_KEY del .env."""
    from dotenv import load_dotenv
    load_dotenv()
    secret = os.getenv("SECRET_KEY", "default_insecure_key_change_me")
    # PBKDF2 con SHA256 para derivar 32 bytes exactos
    key_bytes = hashlib.pbkdf2_hmac('sha256', secret.encode(), b'noc_salt_v4', 100_000)
    return base64.urlsafe_b64encode(key_bytes)


def _get_fernet() -> Fernet:
    """Retorna una instancia de Fernet con la clave derivada."""
    return Fernet(_derive_key())


def encrypt_password(plain_password: str) -> str:
    """
    Encripta una contraseña con Fernet (AES-128-CBC + HMAC).
    Retorna un token base64 seguro para almacenar en SQLite.
    """
    if not plain_password:
        return ""
    try:
        f = _get_fernet()
        token = f.encrypt(plain_password.encode('utf-8'))
        return token.decode('utf-8')
    except Exception as e:
        logger.error(f"Error encriptando credencial: {e}")
        return plain_password  # Fallback: guardar sin encriptar (backward compat)


def decrypt_password(encrypted_token: str) -> str:
    """
    Desencripta una contraseña almacenada con Fernet.
    Si el valor no es un token Fernet válido (contraseña legacy en texto plano),
    lo retorna tal cual para backward compatibility.
    """
    if not encrypted_token:
        return ""
    try:
        f = _get_fernet()
        plain = f.decrypt(encrypted_token.encode('utf-8'))
        return plain.decode('utf-8')
    except InvalidToken:
        # Backward compatibility: la contraseña es texto plano (legacy)
        logger.warning("Credencial legacy detectada (texto plano). Se recomienda re-encriptar.")
        return encrypted_token
    except Exception as e:
        logger.error(f"Error desencriptando credencial: {e}")
        return encrypted_token


# ──────────────────────────────────────────────
# SESSION TOKENS (HMAC-SHA256)
# ──────────────────────────────────────────────

def _get_secret() -> str:
    """Obtiene el SECRET_KEY del .env."""
    from dotenv import load_dotenv
    load_dotenv()
    return os.getenv("SECRET_KEY", "default_insecure_key")


def create_session_token(username: str, role: str) -> str:
    """Crea un token de sesión firmado con HMAC-SHA256 + timestamp."""
    import hmac, json, time
    secret = _get_secret()
    data = json.dumps({"u": username, "r": role, "ts": time.time()})
    data_b64 = base64.b64encode(data.encode()).decode()
    signature = hmac.new(secret.encode(), data_b64.encode(), hashlib.sha256).hexdigest()
    return f"{data_b64}.{signature}"


def verify_session_token(token: str) -> dict | None:
    """Verifica un token de sesión firmado con HMAC-SHA256. TTL: 8 horas."""
    import hmac, json, time
    secret = _get_secret()
    try:
        parts = token.split(".")
        if len(parts) != 2:
            return None
        data_b64, signature = parts
        expected_sig = hmac.new(secret.encode(), data_b64.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected_sig):
            return None
        data = json.loads(base64.b64decode(data_b64))
        if time.time() - data.get("ts", 0) > 28800:  # 8h TTL
            return None
        return data
    except Exception:
        return None
