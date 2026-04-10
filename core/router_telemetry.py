# core/router_telemetry.py
"""
Módulo Principal de Telemetría (Facade).
Combina todos los sub-módulos de telemetría en un único Mixin Maestro.

Arquitectura:
    TelemetryMixin
    ├── HardwareTelemetryMixin    — CPU, RAM, temp, voltaje, storage
    ├── NetworkTelemetryMixin     — Interfaces, tráfico, SFP, routing, DNS
    ├── WirelessTelemetryMixin    — WiFi interfaces, clientes, escaneo RF
    ├── AnalysisTelemetryMixin    — Top Talkers, protocolos, subredes
    ├── MonitoringTelemetryMixin  — Conexiones live, Netwatch, saturación FW
    └── DeviceTelemetryMixin      — Inventario unificado de dispositivos
"""

from core.telemetry.hardware import HardwareTelemetryMixin
from core.telemetry.networking import NetworkTelemetryMixin
from core.telemetry.wireless import WirelessTelemetryMixin
from core.telemetry.analysis import AnalysisTelemetryMixin
from core.telemetry.monitoring import MonitoringTelemetryMixin
from core.telemetry.devices import DeviceTelemetryMixin


class TelemetryMixin(
    HardwareTelemetryMixin,
    NetworkTelemetryMixin,
    WirelessTelemetryMixin,
    AnalysisTelemetryMixin,
    MonitoringTelemetryMixin,
    DeviceTelemetryMixin,
):
    """
    Mixin Maestro de Telemetría.
    Combina todas las capacidades de extracción de datos de MikroTik.
    RouterManager hereda de este mixin para tener acceso a todos los métodos.
    """
    pass