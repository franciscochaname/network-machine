# core/router_api.py
from core.router_base import RouterConnection
from core.router_telemetry import TelemetryMixin
from core.router_vpn import VPNMixin
from core.router_security import SecurityMixin
from core.router_qos import QoSMixin
from core.router_backup import BackupMixin

class RouterManager(RouterConnection, TelemetryMixin, VPNMixin, SecurityMixin, QoSMixin, BackupMixin):
    """
    Clase Maestra (Facade).
    Hereda la conexión de RouterConnection y todas las funciones de los Mixins.
    Gracias a esta estructura, app.py no se rompe y el código es modular.
    """
    pass