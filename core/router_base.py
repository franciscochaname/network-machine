# core/router_base.py
"""
Módulo de conexión base al router MikroTik vía RouterOS API (puerto 8728).
Estrategia: pre-check rápido del puerto → conexión directa → diagnóstico preciso.
Sin Port Knocking.
"""
import socket
import logging
import routeros_api

logger = logging.getLogger("router_base")

# Timeout en segundos para la verificación TCP del puerto
_PORT_CHECK_TIMEOUT = 1.5


def check_port_open(host: str, port: int = 8728, timeout: float = _PORT_CHECK_TIMEOUT) -> bool:
    """
    Verifica si un puerto TCP está RESPONDIENDO (accept o reject).
    Un DROP silencioso del firewall causa timeout → retorna False.
    Un REJECT (connection refused) retorna True de forma inmediata.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        # result==0: abierto | result==10061/111: rechazado (igual = alcanzable)
        # result==10060/ETIMEDOUT: silenciado por DROP
        return result in (0, 10061, 111, 61)   # 10061=WinError refused, 111=Linux refused, 61=macOS refused
    except socket.timeout:
        return False
    except Exception:
        return False


def is_host_reachable(host: str, timeout: float = 1.0) -> bool:
    """
    Verifica si el host es alcanzable a nivel de red (cualquier puerto común).
    Usa el puerto 80 como proxy ICMP-like para confirmar conectividad L3.
    """
    # Intentar varios puertos conocidos que suelen estar disponibles
    for port in (80, 443, 22, 8291):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            if result in (0, 10061, 111, 61):  # respondió aunque sea con RST
                return True
        except Exception:
            continue
    return False


class RouterConnection:
    def __init__(self, host: str, username: str, password: str, port: int = 8728):
        self.host = host
        self.username = username
        # SEC-01: Desencriptar contraseña automáticamente (backward compatible con texto plano)
        from core.crypto import decrypt_password
        self.password = decrypt_password(password)
        self.port = port
        self.connection = None
        self.api = None

    def connect(self, **kwargs) -> tuple:
        """
        Conecta a la API del MikroTik con diagnóstico rápido y preciso.

        Flujo optimizado (falla rápido):
          1. Pre-check TCP del puerto 8728 (1.5s máx)
             → BLOQUEADO (DROP silencioso): retorna "BLOCKED" inmediatamente
             → RESPONDIENDO: procede al paso 2
          2. Intento de autenticación (8s máx)
             → OK: conexión establecida
             → Falla de credenciales: retorna "CREDENTIALS"
             → Otro error: retorna detalles

        Returns:
            (True, msg_ok)         — conexión exitosa
            (False, "BLOCKED")     — puerto bloqueado silenciosamente por firewall
            (False, "CREDENTIALS") — puerto abierto pero auth falló
            (False, "ERROR:xxx")   — otro tipo de error
        """
        # ── PASO 1: Pre-check rápido del puerto (falla rápido si está DROP'd)
        port_responds = check_port_open(self.host, self.port, timeout=_PORT_CHECK_TIMEOUT)

        if not port_responds:
            # El puerto no respondió en 1.5s → DROP silencioso del firewall
            logger.warning(f"Puerto {self.port} no responde en {self.host} (DROP silencioso detectado)")
            return False, "BLOCKED"

        # ── PASO 2: Puerto alcanzable → intentar autenticación
        return self._try_connect()

    def _try_connect(self) -> tuple:
        """Intento directo de autenticación vía API RouterOS."""
        try:
            self.connection = routeros_api.RouterOsApiPool(
                self.host,
                username=self.username,
                password=self.password,
                port=self.port,
                plaintext_login=True,
            )
            self.api = self.connection.get_api()
            logger.info(f"Conectado exitosamente a {self.host}:{self.port}")
            return True, f"✅ Conexión exitosa con {self.host}"

        except Exception as e:
            self.connection = None
            self.api = None
            error_str = str(e).lower()
            logger.warning(f"Fallo de autenticación con {self.host}: {e}")

            # Credenciales o acceso denegado
            if any(k in error_str for k in ("login", "denied", "password", "authentication", "wrong", "cannot")):
                return False, "CREDENTIALS"

            # Timeout inesperado (el puerto respondió en pre-check pero se colgó la sesión)
            if "timed out" in error_str or "timeout" in error_str:
                return False, "BLOCKED"

            return False, f"ERROR:{e}"


    def disconnect(self):
        """Cierra la conexión limpiamente."""
        if self.connection:
            try:
                self.connection.disconnect()
            except Exception:
                pass
            self.connection = None
            self.api = None

    def is_api_reachable(self) -> bool:
        """Verifica si el puerto API está alcanzable (sin autenticar)."""
        return check_port_open(self.host, self.port)

    def is_local_network(self) -> bool:
        """Detecta si el host es una IP de red privada RFC1918."""
        try:
            parts = self.host.split('.')
            return (
                self.host.startswith('192.168.') or
                self.host.startswith('10.') or
                (self.host.startswith('172.') and 16 <= int(parts[1]) <= 31)
            )
        except Exception:
            return False