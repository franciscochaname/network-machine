# core/telemetry/monitoring.py
"""
Módulo de Telemetría de Monitoreo — Conexiones en vivo, tráfico por dispositivo y Netwatch.
Extraído de router_security.py para separar responsabilidades (lectura vs. acción).
"""
from typing import Dict, List

from core.telemetry._utils import (
    require_api, resolve_dns_cache, resolve_service, resolve_port_service,
    clean_ip, safe_int, format_bytes, logger,
)


class MonitoringTelemetryMixin:
    """Mixin para monitoreo en tiempo real de conexiones y servicios."""

    @require_api(default_return={"conexiones_activas": 0, "max_conexiones": 300000})
    def get_security_saturation(self) -> Dict:
        """
        Mide la saturación de la tabla de conexiones del firewall.

        Returns:
            Dict con: conexiones_activas, max_conexiones, saturation_pct, status.
        """
        try:
            conn_count = len(self.api.get_resource('/ip/firewall/connection').get())
            max_conn = 300000
            pct = round((conn_count / max_conn) * 100, 1)

            if pct > 80:
                status = "🔴 CRÍTICO"
            elif pct > 50:
                status = "🟠 ALTO"
            elif pct > 25:
                status = "🟡 MODERADO"
            else:
                status = "🟢 NORMAL"

            return {
                "conexiones_activas": conn_count,
                "max_conexiones": max_conn,
                "saturation_pct": pct,
                "status": status,
            }
        except Exception as e:
            logger.error(f"Error leyendo saturación de firewall: {e}")
            return {"conexiones_activas": 0, "max_conexiones": 300000}

    @require_api(default_return=[])
    def get_device_live_traffic(self, device_ip: str) -> List[Dict]:
        """
        Monitor en vivo: muestra TODAS las conexiones activas de un dispositivo,
        cruzadas con la caché DNS del MikroTik para resolver dominios.
        Agrupa por dominio base para consolidar múltiples conexiones al mismo servicio.

        Args:
            device_ip: IP del dispositivo a monitorear (acepta formatos con puerto o hostname).

        Returns:
            Lista ordenada por consumo con: dominio, dominio_raw, icono, ip_destino,
            puerto, servicio, protocolo, consumo_mb, conexiones, domain_key.
        """
        if not device_ip:
            return []
        try:
            ip_clean = clean_ip(device_ip)

            # 1. Caché DNS compartida
            dns_map = resolve_dns_cache(self.api)

            # 2. Obtener conexiones activas del dispositivo
            all_conns = self.api.get_resource('/ip/firewall/connection').get()
            domains_seen = {}

            for c in all_conns:
                src_full = c.get('src-address', '')
                dst_full = c.get('dst-address', '')
                src_ip = src_full.split(':')[0] if ':' in src_full else src_full
                dst_ip = dst_full.split(':')[0] if ':' in dst_full else dst_full
                dst_port = dst_full.split(':')[1] if ':' in dst_full else ''

                # Solo conexiones de ESTE dispositivo como origen
                if src_ip != ip_clean:
                    continue

                protocol = c.get('protocol', 'tcp')
                orig_bytes = safe_int(c.get('orig-bytes', 0))
                repl_bytes = safe_int(c.get('repl-bytes', 0))
                total_bytes = orig_bytes + repl_bytes

                # Resolver dominio y servicio usando helpers compartidos
                domain = dns_map.get(dst_ip, dst_ip)
                domain_display, service_icon = resolve_service(domain)
                port_service = resolve_port_service(dst_port, protocol)

                # Agrupar por dominio base
                parts = domain.split('.')
                domain_base = '.'.join(parts[-2:]) if len(parts) >= 2 else domain

                if domain_base not in domains_seen:
                    domains_seen[domain_base] = {
                        'domain_raw': domain,
                        'domain_display': domain_display,
                        'icon': service_icon,
                        'dst_ip': dst_ip,
                        'port': dst_port,
                        'port_service': port_service,
                        'protocol': protocol.upper(),
                        'total_bytes': 0,
                        'connections': 0,
                    }

                domains_seen[domain_base]['total_bytes'] += total_bytes
                domains_seen[domain_base]['connections'] += 1

            # 3. Convertir a lista y ordenar por consumo
            result = []
            for domain_key, data in domains_seen.items():
                mb = data['total_bytes'] / 1_048_576
                result.append({
                    'dominio': data['domain_display'],
                    'dominio_raw': data['domain_raw'],
                    'icono': data['icon'],
                    'ip_destino': data['dst_ip'],
                    'puerto': data['port'],
                    'servicio': data['port_service'],
                    'protocolo': data['protocol'],
                    'consumo_mb': round(mb, 3),
                    'consumo_formatted': format_bytes(data['total_bytes']),
                    'conexiones': data['connections'],
                    'domain_key': domain_key,
                })

            return sorted(result, key=lambda x: x['consumo_mb'], reverse=True)
        except Exception as e:
            logger.error(f"Error en monitor de tráfico por dispositivo: {e}")
            return []

    @require_api(default_return=[])
    def get_connection_flows(self, limit: int = 500) -> List[Dict]:
        """
        Descarga la tabla de conexiones activas (Connection Tracking) con estados,
        timeouts y tasas de consumo para el Monitor Táctico.

        Args:
            limit: Máximo de conexiones a retornar (default: 500, ordenadas por consumo).

        Returns:
            Lista de conexiones con: .id, src-address, dst-address, protocol,
            timeout, tcp-state, orig-bytes, repl-bytes, orig-rate, repl-rate,
            total_bytes, total_formatted.
        """
        try:
            conns = self.api.get_resource('/ip/firewall/connection').get()

            result = []
            for c in conns:
                orig_b = safe_int(c.get('orig-bytes', 0))
                repl_b = safe_int(c.get('repl-bytes', 0))
                total = orig_b + repl_b
                result.append({
                    '.id': c.get('.id', ''),
                    'src-address': c.get('src-address', ''),
                    'dst-address': c.get('dst-address', ''),
                    'protocol': c.get('protocol', '-'),
                    'timeout': c.get('timeout', '0s'),
                    'tcp-state': c.get('tcp-state', '-'),
                    'orig-bytes': orig_b,
                    'repl-bytes': repl_b,
                    'orig-rate': c.get('orig-rate', '0bps'),
                    'repl-rate': c.get('repl-rate', '0bps'),
                    'total_bytes': total,
                    'total_formatted': format_bytes(total),
                })

            return sorted(result, key=lambda x: x['total_bytes'], reverse=True)[:limit]
        except Exception as e:
            logger.error(f"Error descargando conexiones: {e}")
            return []

    @require_api(default_return=[])
    def get_server_latency(self) -> List[Dict]:
        """
        Lee el estado de los monitores Netwatch (ping probes a servicios externos).

        Returns:
            Lista con: host, comment, status ('up'/'down'/'unknown'),
            since, interval, timeout.
        """
        try:
            netwatch = self.api.get_resource('/tool/netwatch').get()
            return [{
                "host": n.get('host', ''),
                "comment": n.get('comment', ''),
                "status": n.get('status', 'unknown'),
                "since": n.get('since', ''),
                "interval": n.get('interval', ''),
                "timeout": n.get('timeout', ''),
            } for n in netwatch]
        except Exception as e:
            # Netwatch puede no existir — no es un error crítico
            if "!empty" not in str(e):
                logger.debug(f"Netwatch no disponible: {e}")
            return []
