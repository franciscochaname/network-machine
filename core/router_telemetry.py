# core/router_telemetry.py
"""
Módulo Principal de Telemetría (Facade).
Este archivo ha sido fragmentado para mejorar la escalabilidad y mantenimiento.
Hereda funcionalidades de Hardware, Networking, Wireless y Analysis.
"""

from core.telemetry.hardware import HardwareTelemetryMixin
from core.telemetry.networking import NetworkTelemetryMixin
from core.telemetry.wireless import WirelessTelemetryMixin
from core.telemetry.analysis import AnalysisTelemetryMixin

class TelemetryMixin(HardwareTelemetryMixin, 
                     NetworkTelemetryMixin, 
                     WirelessTelemetryMixin, 
                     AnalysisTelemetryMixin):
    """
    Mixin Maestro de Telemetría.
    Combina todas las capacidades de extracción de datos de MikroTik.
    """
    pass