# core/telemetry/devices.py
"""
Módulo de Telemetría de Dispositivos — Inventario unificado de equipos conectados.
Construye una lista enriquecida de dispositivos LAN, WiFi y VPN con verificación de estado real.
Extraído de router_security.py para separar inventario de seguridad.
"""
from typing import Dict, List

from core.telemetry._utils import require_api, safe_int, logger


class DeviceTelemetryMixin:
    """Mixin para inventario y enriquecimiento de dispositivos conectados."""

    def get_active_devices_enriched(self, datos: Dict) -> List[Dict]:
        """
        Construye una lista unificada de TODOS los dispositivos conectados
        (LAN via DHCP + WiFi via Registration Table + VPN) con deduplicación por MAC.
        Verifica el estado real de cada dispositivo mediante ping desde el router.

        Args:
            datos: Dict con claves esperadas: 'dhcp', 'wifi_neighbors', 'arp_table'.

        Returns:
            Lista ordenada por IP con: ip, mac, hostname, connection_type,
            network, status, signal, extra, latency.
        """
        devices = {}

        # 1. Dispositivos LAN (DHCP Leases)
        self._merge_dhcp_devices(devices, datos.get('dhcp', []))

        # 2. Dispositivos WiFi (Registration Table)
        self._merge_wifi_devices(devices, datos.get('wifi_neighbors', []), datos.get('arp_table', {}))

        # 3. Verificación de Estado Real (Ping MikroTik)
        self._verify_device_status(devices)

        # 4. Convertir a lista y ordenar por IP
        return sorted(devices.values(), key=lambda x: x.get('ip', ''))

    def _classify_device(self, mac: str, hostname: str) -> str:
        """Clasifica el rol del dispositivo según su MAC/Vendor y hostname."""
        mac_upper = (mac or "").upper()
        host_lower = (hostname or "").lower()

        # OUI Prefixes de fabricantes de Infraestructura comunes
        infra_ouis = [
            "F4:92:BF", "FC:EC:DA", "04:18:D6", "24:5A:4C", "44:D9:E7", "80:2A:A8", "18:E8:29", # Ubiquiti
            "00:0C:42", "4C:5E:0C", "D4:CA:6D", "E4:8D:8C", "18:FD:74", "DC:2C:6E",             # MikroTik
            "00:0F:7D", "00:7E:56", "0A:00:3E",                                                # Cambium / Motorola
        ]

        if any(mac_upper.startswith(oui) for oui in infra_ouis):
            if "sw" in host_lower or "switch" in host_lower:
                return "🖧 Switch (Infra)"
            return "📡 Access Point/CPE"
            
        if "ap-" in host_lower or "ap " in host_lower or "sector" in host_lower:
            return "📡 Access Point/Antena"
        if "sw-" in host_lower or "switch" in host_lower:
            return "🖧 Switch (Infra)"
        if "cam" in host_lower or "dvr" in host_lower or "nvr" in host_lower:
            return "📷 Cámara/Seguridad"
            
        return "💻 Cliente (PC/Móvil)"

    def _merge_dhcp_devices(self, devices: Dict, dhcp_leases: List[Dict]) -> None:
        """Agrega dispositivos desde DHCP Leases al inventario."""
        for lease in dhcp_leases:
            mac = (lease.get('mac-address') or '').upper()
            ip = lease.get('address', '')
            hostname = lease.get('host-name', '')
            server = lease.get('server', '')
            status = lease.get('status', '')
            key = mac or ip
            if key:
                devices[key] = {
                    'ip': ip,
                    'mac': mac,
                    'hostname': hostname,
                    'device_role': self._classify_device(mac, hostname),
                    'connection_type': 'LAN (DHCP)',
                    'network': server,
                    'status': '🟢 Conectado' if status == 'bound' else '🔴 Offline',
                    'signal': '-',
                    'extra': f"Red: {server}",
                    'latency': '-',
                }

    def _merge_wifi_devices(self, devices: Dict, wifi_neighbors: List[Dict], arp_table: Dict) -> None:
        """Agrega o enriquece dispositivos con datos WiFi del Registration Table."""
        for client in wifi_neighbors:
            mac = (client.get('mac') or '').upper()
            signal = client.get('signal', 'N/A')
            interface = client.get('interface', '')
            ip_from_hostname = client.get('hostname', '')
            key = mac
            if not key:
                continue

            if key in devices:
                # Enriquecer: ya está en DHCP, agregar datos WiFi
                devices[key]['connection_type'] = 'WiFi + LAN'
                devices[key]['signal'] = signal
                devices[key]['extra'] = f"Interface: {interface} | Señal: {signal}"
            else:
                # Buscar IP en ARP por MAC
                ip_found = ''
                for arp_ip, arp_mac in arp_table.items():
                    if arp_mac.upper() == mac:
                        ip_found = arp_ip
                        break

                devices[key] = {
                    'ip': ip_found or ip_from_hostname,
                    'mac': mac,
                    'hostname': ip_from_hostname or 'WiFi Client',
                    'device_role': self._classify_device(mac, ip_from_hostname),
                    'connection_type': 'WiFi',
                    'network': interface,
                    'status': '🟢 Conectado',
                    'signal': signal,
                    'extra': f"Interface: {interface} | Señal: {signal}",
                    'latency': '-',
                }

    def _verify_device_status(self, devices: Dict) -> None:
        """
        Verifica el estado real de cada dispositivo mediante ping rápido
        desde el router al dispositivo (1 ping, RTT < 1s).
        """
        if not self.api:
            return

        try:
            p_res = self.api.get_resource('/tool')
            for d in devices.values():
                ip = d.get('ip')
                if not ip or '.' not in ip:
                    continue
                try:
                    ping = p_res.call('ping', {'address': ip, 'count': '1'})
                    if ping and safe_int(ping[0].get('received', 0)) > 0:
                        d['status'] = '🟢 EN LÍNEA (Ping OK)'
                        d['latency'] = f"{ping[0].get('avg-rtt', '0')}ms"
                    else:
                        d['status'] = '🟠 STANDBY / SILENCIOSO'
                        d['latency'] = '-'
                except Exception:
                    d['latency'] = '-'
        except Exception as e:
            logger.debug(f"Verificación de estado por ping no disponible: {e}")

