# core/telemetry/analysis.py
import logging

class AnalysisTelemetryMixin:
    def get_top_talkers(self):
        """Descarga conexiones activas y cruza destinos con la Caché DNS para saber qué páginas visitan."""
        if not self.api: return []
        try:
            # 1. Cache DNS
            try:
                dns_cache = self.api.get_resource('/ip/dns/cache').get()
                ip_to_domain = {d['address']: d['name'] for d in dns_cache if 'address' in d and 'name' in d}
            except: ip_to_domain = {}

            # 2. Conexiones
            conns = self.api.get_resource('/ip/firewall/connection').get()
            uso = {}
            for c in conns:
                src_full = c.get('src-address', '')
                dst_full = c.get('dst-address', '')
                if not src_full or not dst_full: continue
                src = src_full.split(':')[0]
                dst = dst_full.split(':')[0]
                total_b = int(c.get('repl-bytes', 0)) + int(c.get('orig-bytes', 0))
                
                if src.startswith('192.168.') or src.startswith('10.') or src.startswith('172.'):
                    if src not in uso:
                        uso[src] = {"bytes": 0, "destinations": {}}
                    uso[src]["bytes"] += total_b
                    if total_b > 5000:
                        domain = ip_to_domain.get(dst, dst)
                        uso[src]["destinations"][domain] = uso[src]["destinations"].get(domain, 0) + total_b
            
            # 3. Formatear Top 5
            top = []
            for ip, vals in sorted(uso.items(), key=lambda x: x[1]['bytes'], reverse=True)[:5]:
                top_dests = sorted(vals["destinations"].items(), key=lambda x: x[1], reverse=True)[:5]
                dest_list = [{"domain": d[0], "mb": d[1] / 1048576, "mins_est": int((d[1] / 1048576) * 2) or 1} for d in top_dests]
                top.append({"ip": ip, "bytes": vals["bytes"], "domains": dest_list})
            return top
        except Exception as e:
            logging.error(f"Error top talkers analysis: {e}")
            return []
