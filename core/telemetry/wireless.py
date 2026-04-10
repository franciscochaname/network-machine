# core/telemetry/wireless.py
"""
Módulo de Telemetría Wireless — Interfaces WiFi, clientes conectados y escaneo RF.
Compatible con RouterOS 6 (/interface/wireless) y RouterOS 7+ (/interface/wifi).
"""
from typing import Dict, List, Optional

from core.telemetry._utils import require_api, logger


class WirelessTelemetryMixin:
    """Mixin para extracción de telemetría wireless del RouterOS."""

    @require_api(default_return=[])
    def get_wifi_interfaces(self) -> List[Dict]:
        """
        Lista todas las interfaces WiFi del equipo con su configuración.
        Intenta primero RouterOS 7+ (/interface/wifi), fallback a RouterOS 6.

        Returns:
            Lista con: name, mac, ssid, frequency, band, channel_width,
            running, disabled.
        """
        try:
            # RouterOS 7+
            try:
                wifi = self.api.get_resource('/interface/wifi').get()
                if wifi:
                    return [{
                        'name': w.get('name', ''),
                        'mac': w.get('mac-address', ''),
                        'ssid': w.get('configuration.ssid', w.get('ssid', '')),
                        'frequency': w.get('frequency', ''),
                        'band': w.get('band', ''),
                        'channel_width': w.get('channel-width', ''),
                        'running': w.get('running', 'false'),
                        'disabled': w.get('disabled', 'false'),
                    } for w in wifi]
            except Exception:
                pass

            # RouterOS 6
            wireless = self.api.get_resource('/interface/wireless').get()
            return [{
                'name': w.get('name', ''),
                'mac': w.get('mac-address', ''),
                'ssid': w.get('ssid', ''),
                'frequency': w.get('frequency', ''),
                'band': w.get('band', ''),
                'channel_width': w.get('channel-width', ''),
                'running': w.get('running', 'false'),
                'disabled': w.get('disabled', 'false'),
            } for w in wireless]
        except Exception as e:
            logger.debug(f"Interfaces WiFi no disponibles: {e}")
            return []

    @require_api(default_return=[])
    def get_wifi_neighbors(self) -> List[Dict]:
        """
        Obtiene clientes WiFi conectados desde la Registration Table.
        Intenta primero RouterOS 7+ (/interface/wifi/registration-table),
        fallback a RouterOS 6 (/interface/wireless/registration-table).

        Returns:
            Lista con: interface, mac, signal, tx_rate, rx_rate, uptime,
            packets, bytes, hostname (solo v6), ccq (solo v6).
        """
        try:
            # RouterOS 7+
            try:
                reg = self.api.get_resource('/interface/wifi/registration-table').get()
                if reg:
                    return [{
                        'interface': r.get('interface', ''),
                        'mac': r.get('mac-address', '').upper(),
                        'signal': r.get('signal', ''),
                        'tx_rate': r.get('tx-rate', ''),
                        'rx_rate': r.get('rx-rate', ''),
                        'uptime': r.get('uptime', ''),
                        'packets': r.get('packets', ''),
                        'bytes': r.get('bytes', ''),
                    } for r in reg]
            except Exception:
                pass

            # RouterOS 6
            reg = self.api.get_resource('/interface/wireless/registration-table').get()
            return [{
                'interface': r.get('interface', ''),
                'mac': r.get('mac-address', '').upper(),
                'signal': r.get('signal-strength', r.get('signal-strength-ch0', '')),
                'ccq': r.get('tx-ccq', ''),
                'tx_rate': r.get('tx-rate', ''),
                'rx_rate': r.get('rx-rate', ''),
                'uptime': r.get('uptime', ''),
                'bytes': r.get('bytes', ''),
                'hostname': r.get('last-ip', ''),
            } for r in reg]
        except Exception as e:
            logger.debug(f"Registration table no disponible: {e}")
            return []

    @require_api(default_return=[])
    def get_wifi_scan(self, interface: str = 'wlan1', duration: int = 5) -> List[Dict]:
        """
        Ejecuta un escaneo de espectro RF desde una interfaz WiFi.
        Detecta APs cercanos con SSID, señal, frecuencia y seguridad.

        Args:
            interface: Nombre de la interfaz WiFi a usar para el escaneo.
            duration: Duración del escaneo en segundos (default: 5).

        Returns:
            Lista de APs detectados con: bssid, ssid, signal, frequency,
            channel, security, band, radio_name (solo v6), routeros_version (solo v6).
        """
        try:
            # RouterOS 7+
            try:
                scan_results = self.api.get_resource('/interface/wifi').call(
                    'scan', {'.id': interface, 'duration': str(duration)}
                )
                if scan_results:
                    return [{
                        'bssid': ap.get('bssid', '').upper(),
                        'ssid': ap.get('ssid', ''),
                        'signal': ap.get('signal', ''),
                        'frequency': ap.get('frequency', ''),
                        'channel': ap.get('channel', ''),
                        'security': ap.get('security', ''),
                        'band': ap.get('band', ''),
                    } for ap in scan_results]
            except Exception:
                pass

            # RouterOS 6
            scan_results = self.api.get_resource('/interface/wireless').call(
                'scan', {'.id': interface, 'duration': str(duration)}
            )
            return [{
                'bssid': ap.get('address', '').upper(),
                'ssid': ap.get('ssid', ''),
                'signal': ap.get('signal-strength', ''),
                'frequency': ap.get('frequency', ''),
                'channel': ap.get('channel', ''),
                'security': ap.get('security-profile', ''),
                'band': ap.get('band', ''),
                'radio_name': ap.get('radio-name', ''),
                'routeros_version': ap.get('routeros-version', ''),
            } for ap in scan_results]
        except Exception as e:
            logger.error(f"Error en escaneo WiFi: {e}")
            return []
