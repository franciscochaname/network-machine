# core/router_base.py
import routeros_api
import logging
from core.port_knock import port_knock, check_api_reachable

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

class RouterConnection:
    def __init__(self, host, username, password, port=8728):
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.connection = None
        self.api = None
        self._knock_attempted = False

    def connect(self, auto_knock: bool = True) -> tuple:
        """
        Conecta al router MikroTik vía API.
        Si `auto_knock` es True y la API está bloqueada, intenta Port Knocking
        automáticamente antes de conectar.

        Returns:
            (success: bool, message: str)
        """
        # Paso 1: Intentar conexión directa
        success, msg = self._try_connect()
        if success:
            return True, msg

        # Paso 2: Si falló y auto_knock habilitado, intentar Port Knocking
        if auto_knock and not self._knock_attempted:
            self._knock_attempted = True
            logging.info(f"API bloqueada en {self.host}. Intentando Port Knocking...")
            knock_ok, knock_msg = port_knock(self.host)
            if knock_ok:
                logging.info(f"Port Knocking: {knock_msg}")
                # Reintentar conexión después del knock con un poco más de paciencia
                import time
                time.sleep(2.0)  # Aumentamos a 2s para routers lentos
                success2, msg2 = self._try_connect()
                if success2:
                    return True, f"🔑 Conexión establecida via Port Knocking con {self.host}"
                else:
                    return False, f"Secuencia Tok Tok enviada pero la API sigue sin responder ({msg2}). Revisa el orden de las reglas NAT/Firewall."
            else:
                return False, f"Port Knocking falló: {knock_msg}. Error original: {msg}"

        return False, msg

    def _try_connect(self) -> tuple:
        """Intento directo de conexión API sin lógica de knock."""
        try:
            self.connection = routeros_api.RouterOsApiPool(
                self.host, username=self.username, password=self.password,
                port=self.port, plaintext_login=True
            )
            self.api = self.connection.get_api()
            return True, f"Conexión exitosa con {self.host}"
        except Exception as e:
            logging.error(f"Fallo al conectar con {self.host}: {str(e)}")
            self.connection = None
            self.api = None
            return False, f"Error de conexión: {str(e)}"

    def disconnect(self):
        if self.connection:
            try:
                self.connection.disconnect()
            except Exception:
                pass
            self.api = None

    def is_api_reachable(self) -> bool:
        """Verifica si el puerto API del router está accesible (sin autenticar)."""
        return check_api_reachable(self.host, self.port)