# core/telemetry/analysis.py
"""
Módulo de Telemetría de Análisis — Top Talkers, distribución de protocolos y consumo por subred.
Cruza conexiones activas con la caché DNS del MikroTik para resolución de dominios.
"""
from typing import Dict, List

from core.telemetry._utils import (
    require_api, resolve_dns_cache, safe_int, format_bytes, logger,
    PORT_SERVICE_MAP,
)


class AnalysisTelemetryMixin:
    """Mixin para análisis avanzado de tráfico en el RouterOS."""

    @require_api(default_return=[])
    def get_top_talkers(self) -> List[Dict]:
        """
        Identifica los dispositivos locales con mayor consumo de ancho de banda.
        Cruza la tabla de conexiones con la caché DNS para resolver dominios visitados.

        Returns:
            Lista (Top 10) ordenada por consumo, cada elemento con:
            ip, bytes, bytes_formatted, domains (lista de {domain, mb, mins_est}),
            connection_count, protocols (distribución de protocolos).
        """
        try:
            # 1. Cache DNS compartida (una sola llamada)
            ip_to_domain = resolve_dns_cache(self.api)

            # 2. Conexiones activas
            conns = self.api.get_resource('/ip/firewall/connection').get()
            uso = {}

            for c in conns:
                src_full = c.get('src-address', '')
                dst_full = c.get('dst-address', '')
                if not src_full or not dst_full:
                    continue

                src = src_full.split(':')[0]
                dst = dst_full.split(':')[0]
                protocol = c.get('protocol', 'tcp')
                total_b = safe_int(c.get('repl-bytes', 0)) + safe_int(c.get('orig-bytes', 0))

                # Solo dispositivos de redes privadas como origen
                if not (src.startswith('192.168.') or src.startswith('10.') or src.startswith('172.')):
                    continue

                if src not in uso:
                    uso[src] = {"bytes": 0, "destinations": {}, "connections": 0, "protocols": {}}

                uso[src]["bytes"] += total_b
                uso[src]["connections"] += 1
                uso[src]["protocols"][protocol] = uso[src]["protocols"].get(protocol, 0) + 1

                if total_b > 5000:
                    domain = ip_to_domain.get(dst, dst)
                    uso[src]["destinations"][domain] = uso[src]["destinations"].get(domain, 0) + total_b

            # 3. Formatear Top 10
            top = []
            for ip, vals in sorted(uso.items(), key=lambda x: x[1]['bytes'], reverse=True)[:10]:
                top_dests = sorted(vals["destinations"].items(), key=lambda x: x[1], reverse=True)[:5]
                dest_list = [{
                    "domain": d[0],
                    "mb": round(d[1] / 1_048_576, 2),
                    "mins_est": max(1, int((d[1] / 1_048_576) * 2)),
                } for d in top_dests]

                top.append({
                    "ip": ip,
                    "bytes": vals["bytes"],
                    "bytes_formatted": format_bytes(vals["bytes"]),
                    "domains": dest_list,
                    "connection_count": vals["connections"],
                    "protocols": vals["protocols"],
                })
            return top
        except Exception as e:
            logger.error(f"Error en análisis de top talkers: {e}")
            return []

    @require_api(default_return={})
    def get_protocol_distribution(self) -> Dict:
        """
        Analiza la distribución de protocolos en las conexiones activas.

        Returns:
            Dict con: total_connections, protocols (dict protocol→count),
            tcp_states (dict state→count), top_ports (lista de {port, count, service}).
        """
        try:
            conns = self.api.get_resource('/ip/firewall/connection').get()
            protocols = {}
            tcp_states = {}
            ports = {}

            for c in conns:
                # Protocolos
                proto = c.get('protocol', 'unknown')
                protocols[proto] = protocols.get(proto, 0) + 1

                # TCP States
                if proto == 'tcp':
                    state = c.get('tcp-state', 'unknown')
                    tcp_states[state] = tcp_states.get(state, 0) + 1

                # Puertos destino
                dst = c.get('dst-address', '')
                if ':' in dst:
                    port = dst.split(':')[1]
                    ports[port] = ports.get(port, 0) + 1

            # Top 10 puertos
            top_ports = sorted(ports.items(), key=lambda x: x[1], reverse=True)[:10]
            top_ports_list = [{
                "port": p[0],
                "count": p[1],
                "service": PORT_SERVICE_MAP.get(p[0], f"Port {p[0]}"),
            } for p in top_ports]

            return {
                "total_connections": len(conns),
                "protocols": protocols,
                "tcp_states": tcp_states,
                "top_ports": top_ports_list,
            }
        except Exception as e:
            logger.error(f"Error en distribución de protocolos: {e}")
            return {}

    @require_api(default_return=[])
    def get_bandwidth_by_subnet(self) -> List[Dict]:
        """
        Calcula el consumo de ancho de banda agrupado por subred local.

        Returns:
            Lista con: subnet, total_bytes, total_mb, device_count, top_device.
        """
        try:
            conns = self.api.get_resource('/ip/firewall/connection').get()

            # Agrupar por /24
            subnets = {}
            for c in conns:
                src = c.get('src-address', '').split(':')[0]
                if not (src.startswith('192.168.') or src.startswith('10.') or src.startswith('172.')):
                    continue

                parts = src.split('.')
                if len(parts) == 4:
                    subnet = f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
                    total_b = safe_int(c.get('repl-bytes', 0)) + safe_int(c.get('orig-bytes', 0))

                    if subnet not in subnets:
                        subnets[subnet] = {"bytes": 0, "devices": {}}
                    subnets[subnet]["bytes"] += total_b
                    subnets[subnet]["devices"][src] = subnets[subnet]["devices"].get(src, 0) + total_b

            result = []
            for subnet, data in sorted(subnets.items(), key=lambda x: x[1]['bytes'], reverse=True):
                top_dev = max(data["devices"].items(), key=lambda x: x[1]) if data["devices"] else ("N/A", 0)
                result.append({
                    "subnet": subnet,
                    "total_bytes": data["bytes"],
                    "total_mb": round(data["bytes"] / 1_048_576, 2),
                    "device_count": len(data["devices"]),
                    "top_device": top_dev[0],
                    "top_device_mb": round(top_dev[1] / 1_048_576, 2),
                })
            return result
        except Exception as e:
            logger.error(f"Error en análisis por subred: {e}")
            return []
