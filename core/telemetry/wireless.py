# core/telemetry/wireless.py
import logging

class WirelessTelemetryMixin:
    def get_wifi_interfaces(self):
        if not self.api: return []
        try:
            # RouterOS 7+
            try:
                wifi = self.api.get_resource('/interface/wifi').get()
                if wifi:
                    return [{
                        'name': w.get('name', ''), 'mac': w.get('mac-address', ''),
                        'ssid': w.get('configuration.ssid', w.get('ssid', '')),
                        'frequency': w.get('frequency', ''), 'band': w.get('band', ''),
                        'channel_width': w.get('channel-width', ''),
                        'running': w.get('running', 'false'), 'disabled': w.get('disabled', 'false'),
                    } for w in wifi]
            except Exception: pass
            
            # RouterOS 6
            wireless = self.api.get_resource('/interface/wireless').get()
            return [{
                'name': w.get('name', ''), 'mac': w.get('mac-address', ''),
                'ssid': w.get('ssid', ''), 'frequency': w.get('frequency', ''),
                'band': w.get('band', ''), 'channel_width': w.get('channel-width', ''),
                'running': w.get('running', 'false'), 'disabled': w.get('disabled', 'false'),
            } for w in wireless]
        except Exception: return []

    def get_wifi_neighbors(self):
        if not self.api: return []
        try:
            # RouterOS 7+
            try:
                reg = self.api.get_resource('/interface/wifi/registration-table').get()
                if reg:
                    return [{
                        'interface': r.get('interface', ''), 'mac': r.get('mac-address', '').upper(),
                        'signal': r.get('signal', ''), 'tx_rate': r.get('tx-rate', ''),
                        'rx_rate': r.get('rx-rate', ''), 'uptime': r.get('uptime', ''),
                        'packets': r.get('packets', ''), 'bytes': r.get('bytes', ''),
                    } for r in reg]
            except Exception: pass
            
            # RouterOS 6
            reg = self.api.get_resource('/interface/wireless/registration-table').get()
            return [{
                'interface': r.get('interface', ''), 'mac': r.get('mac-address', '').upper(),
                'signal': r.get('signal-strength', r.get('signal-strength-ch0', '')),
                'ccq': r.get('tx-ccq', ''), 'tx_rate': r.get('tx-rate', ''),
                'rx_rate': r.get('rx-rate', ''), 'uptime': r.get('uptime', ''),
                'bytes': r.get('bytes', ''), 'hostname': r.get('last-ip', ''),
            } for r in reg]
        except: return []

    def get_wifi_scan(self, interface: str = 'wlan1', duration: int = 5):
        if not self.api: return []
        try:
            # RouterOS 7+
            try:
                scan_results = self.api.get_resource('/interface/wifi').call('scan', {'.id': interface, 'duration': str(duration)})
                if scan_results:
                    return [{ 'bssid': ap.get('bssid', '').upper(), 'ssid': ap.get('ssid', ''), 'signal': ap.get('signal', ''), 'frequency': ap.get('frequency', ''), 'channel': ap.get('channel', ''), 'security': ap.get('security', ''), 'band': ap.get('band', ''), } for ap in scan_results]
            except Exception: pass
            
            # RouterOS 6
            scan_results = self.api.get_resource('/interface/wireless').call('scan', {'.id': interface, 'duration': str(duration)})
            return [{ 'bssid': ap.get('address', '').upper(), 'ssid': ap.get('ssid', ''), 'signal': ap.get('signal-strength', ''), 'frequency': ap.get('frequency', ''), 'channel': ap.get('channel', ''), 'security': ap.get('security-profile', ''), 'band': ap.get('band', ''), 'radio_name': ap.get('radio-name', ''), 'routeros_version': ap.get('routeros-version', ''), } for ap in scan_results]
        except: return []
