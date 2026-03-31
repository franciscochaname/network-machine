# core/telemetry/networking.py
import logging

class NetworkTelemetryMixin:
    def get_interface_health(self):
        """Detecta errores físicos (FCS, CRC, Drops) en los puertos para predecir fallos de cableado."""
        if not self.api: return []
        try:
            stats = self.api.get_resource('/interface').get()
            anomalias = []
            for s in stats:
                name = s.get('name', 'eth')
                tx_err = int(s.get('tx-error', 0))
                rx_err = int(s.get('rx-error', 0))
                tx_drop = int(s.get('tx-drop', 0))
                rx_drop = int(s.get('rx-drop', 0))
                
                if tx_err > 0 or rx_err > 0 or tx_drop > 500 or rx_drop > 500:
                    anomalias.append({
                        "interface": name,
                        "errors": tx_err + rx_err,
                        "drops": tx_drop + rx_drop,
                        "status": "⚠️ Alerta de Capa 1"
                    })
            return anomalias
        except: return []

    def get_smart_traffic(self):
        if not self.api: return []
        try:
            interfaces = self.api.get_resource('/interface').get()
            running = [i['name'] for i in interfaces if i.get('running', 'false') == 'true' and i.get('type') != 'dummy']
            resultados = []
            for iface in running:
                try:
                    t = self.api.get_resource('/interface').call('monitor-traffic', {'interface': iface, 'once': 'yes'})[0]
                    rx = int(t.get('rx-bits-per-second', 0)) / 1048576
                    tx = int(t.get('tx-bits-per-second', 0)) / 1048576
                    if rx > 0.05 or tx > 0.05:
                        resultados.append({"name": iface, "rx": round(rx, 2), "tx": round(tx, 2)})
                except: continue
            return sorted(resultados, key=lambda x: x['rx'], reverse=True)
        except: return []

    def get_sfp_diagnostics(self):
        """Monitorea potencia óptica (SFP DOM) y señal inalámbrica (LTE) para diagnóstico remoto."""
        if not self.api: return []
        diagnosticos = []
        try:
            # 1. Diagnóstico de SFPs (Fibra Óptica)
            eths = self.api.get_resource('/interface/ethernet').get()
            sfps = [e['name'] for e in eths if 'sfp' in e.get('name', '').lower()]
            for name in sfps:
                try:
                    m = self.api.get_resource('/interface/ethernet').call('monitor', {'.id': name, 'once': 'yes'})[0]
                    rx_pwr = m.get('rx-power', 'N/A')
                    tx_pwr = m.get('tx-power', 'N/A')
                    temp = m.get('sfp-temperature', 'N/A')
                    if rx_pwr != 'N/A':
                        diagnosticos.append({
                            "interface": name, "tipo": "Óptico (SFP)",
                            "señal": f"{rx_pwr} dBm", "temp": f"{temp}°C",
                            "status": "🔴 Crítico" if float(rx_pwr) < -25 else "🟢 Saludable"
                        })
                except: continue

            # 2. Diagnóstico LTE/Modem (Señal Inalámbrica)
            ltes = self.api.get_resource('/interface/lte').get()
            for l in ltes:
                name = l.get('name', 'lte1')
                try:
                    m = self.api.get_resource('/interface/lte').call('monitor', {'.id': name, 'once': 'yes'})[0]
                    rssi = m.get('rssi', m.get('signal-strength', 'N/A'))
                    status = m.get('status', 'connected')
                    diagnosticos.append({
                        "interface": name, "tipo": "Módem LTE",
                        "señal": f"{rssi} dBm", "temp": "N/A",
                        "status": "🟠 Débil" if float(rssi) < -90 else "🟢 Fuerte"
                    })
                except: continue
            return diagnosticos
        except: return []

    def get_dhcp_leases(self):
        if not self.api: return []
        try: return [l for l in self.api.get_resource('/ip/dhcp-server/lease').get() if l.get('status') == 'bound']
        except: return []

    def get_router_ips(self):
        if not self.api: return []
        try:
            direcciones = self.api.get_resource('/ip/address').get()
            return [d.get('address', '').split('/')[0] for d in direcciones if 'address' in d]
        except Exception as e:
            logging.error(f"Error IPs: {e}")
            return []

    def get_arp_table(self):
        if not self.api: return {}
        try:
            arp_data = self.api.get_resource('/ip/arp').get()
            return {item['address']: item['mac-address'].upper() for item in arp_data if 'address' in item and 'mac-address' in item}
        except: return {}

    def get_local_networks(self):
        if not self.api: return []
        try:
            direcciones = self.api.get_resource('/ip/address').get()
            redes = []
            for d in direcciones:
                m = d.get('address', '').split('/')[-1] if '/' in d.get('address', '') else ''
                if d.get('disabled') != 'true' and d.get('dynamic') != 'true' and m not in ['32','30']:
                    redes.append({
                        "network": f"{d.get('network')}/{m}",
                        "interface": d.get('interface'),
                        "comment": d.get('comment', f"Red {d.get('interface')}")
                    })
            return redes
        except: return []
