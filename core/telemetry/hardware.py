# core/telemetry/hardware.py
"""
Módulo de Telemetría de Hardware — Estado físico y de recursos del equipo MikroTik.
Incluye: CPU, RAM, temperatura, voltaje, uptime, almacenamiento y capacidades del equipo.
"""
from datetime import datetime
from typing import Dict

from core.telemetry._utils import (
    require_api, parse_mikrotik_uptime, safe_int, logger,
)


class HardwareTelemetryMixin:
    """Mixin para extracción de telemetría de hardware del RouterOS."""

    @require_api(default_return={})
    def get_system_info(self) -> Dict:
        """
        Extrae información completa del sistema MikroTik.

        Returns:
            Dict con: name, cpu_load, cpu_count, free_memory, total_memory,
            free_hdd, total_hdd, uptime, last_reboot, version, temperature,
            voltage, architecture_name, board_name, bad_blocks, has_ap.
        """
        try:
            identity = self.api.get_resource('/system/identity').get()[0].get('name', 'N/A')
            res = self.api.get_resource('/system/resource').get()[0]

            # Sensores de salud (temperatura, voltaje)
            temp, voltage = self._read_health_sensors()

            # Cálculo de último reinicio
            uptime_str = res.get('uptime', '0s')
            last_reboot = self._calculate_last_reboot(uptime_str)

            # Detección de capacidades WiFi
            has_ap = self._detect_wireless_capability()

            return {
                "name": identity,
                "cpu_load": safe_int(res.get('cpu-load', 0)),
                "cpu_count": safe_int(res.get('cpu-count', 1)),
                "free_memory": safe_int(res.get('free-memory', 0)),
                "total_memory": safe_int(res.get('total-memory', 0)),
                "free_hdd": safe_int(res.get('free-hdd-space', 0)),
                "total_hdd": safe_int(res.get('total-hdd-space', 0)),
                "uptime": uptime_str,
                "last_reboot": last_reboot,
                "version": res.get('version', 'Desconocida'),
                "temperature": temp,
                "voltage": voltage,
                "architecture_name": res.get('architecture-name', 'N/A'),
                "board_name": res.get('board-name', 'N/A'),
                "bad_blocks": res.get('bad-blocks', '0'),
                "has_ap": has_ap,
            }
        except Exception as e:
            logger.error(f"Error en telemetría de hardware: {e}")
            return {}

    def _read_health_sensors(self) -> tuple:
        """
        Lee sensores de salud del equipo (temperatura, voltaje).
        Compatible con RouterOS 6 (clave-valor plano) y RouterOS 7 (name/value pares).

        Returns:
            Tuple (temperatura: str, voltaje: str).
        """
        temp, voltage = 'N/A', 'N/A'
        try:
            health = self.api.get_resource('/system/health').get()
            if not health:
                return temp, voltage

            # RouterOS 7+: formato [{name: "temperature", value: "45"}, ...]
            if 'name' in health[0]:
                for item in health:
                    name = str(item.get('name', '')).lower()
                    value = item.get('value', 'N/A')
                    if any(k in name for k in ('temperature', 'temp', 'cpu-temp')):
                        temp = value
                    elif any(k in name for k in ('voltage', 'volt')):
                        voltage = value
            else:
                # RouterOS 6: formato [{temperature: "45", voltage: "24"}]
                for key in ('temperature', 'cpu-temperature', 'board-temperature'):
                    if key in health[0]:
                        temp = health[0][key]
                        break
                if 'voltage' in health[0]:
                    voltage = health[0]['voltage']

        except Exception as e:
            logger.debug(f"Sensores de salud no disponibles: {e}")

        return temp, voltage

    def _calculate_last_reboot(self, uptime_str: str) -> str:
        """Calcula la fecha/hora del último reinicio basándose en el uptime."""
        try:
            td = parse_mikrotik_uptime(uptime_str)
            return (datetime.now() - td).strftime("%d/%m/%Y %H:%M:%S")
        except Exception as e:
            logger.debug(f"Error calculando último reinicio: {e}")
            return "Desconocido"

    def _detect_wireless_capability(self) -> bool:
        """Detecta si el equipo tiene interfaces wireless (AP mode)."""
        try:
            # RouterOS 7+ (/interface/wifi)
            try:
                wifi = self.api.get_resource('/interface/wifi').get()
                if wifi:
                    return True
            except Exception:
                pass
            # RouterOS 6 (/interface/wireless)
            wireless = self.api.get_resource('/interface/wireless').get()
            return bool(wireless)
        except Exception:
            return False

    @require_api(default_return={})
    def get_storage_info(self) -> Dict:
        """
        Obtiene información detallada del almacenamiento del equipo.

        Returns:
            Dict con: total_hdd, free_hdd, used_pct, write_sect_total, bad_blocks.
        """
        try:
            res = self.api.get_resource('/system/resource').get()[0]
            total = safe_int(res.get('total-hdd-space', 0))
            free = safe_int(res.get('free-hdd-space', 0))
            used_pct = round(((total - free) / total) * 100, 1) if total > 0 else 0

            return {
                "total_hdd": total,
                "free_hdd": free,
                "used_pct": used_pct,
                "write_sect_total": safe_int(res.get('write-sect-total', 0)),
                "bad_blocks": res.get('bad-blocks', '0'),
            }
        except Exception as e:
            logger.error(f"Error leyendo almacenamiento: {e}")
            return {}
