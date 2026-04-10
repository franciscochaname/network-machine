# core/telemetry/networking.py
"""
Módulo de Telemetría de Red — Interfaces, tráfico, diagnósticos y enrutamiento.
Cubre Capa 1 (errores físicos), Capa 2 (ARP/Bridge), Capa 3 (IP/Routing)
y diagnósticos de transceptores (SFP/LTE).
"""
from typing import Dict, List

from core.telemetry._utils import require_api, safe_int, logger


class NetworkTelemetryMixin:
    """Mixin para extracción de telemetría de red del RouterOS."""

    @require_api(default_return={})
    def get_wan_status(self) -> Dict:
        """
        Determina el estado de la conexión principal a Internet (WAN).
        Detecta rutas default, balanceos, failover y tipo de asignación (Estática/Dinámica).
        """
        try:
            # 1. Rutas por defecto (0.0.0.0/0)
            routes = self.api.get_resource('/ip/route').get()
            default_routes = [r for r in routes if r.get('dst-address') == '0.0.0.0/0']
            
            wans = []
            for r in default_routes:
                gateway = r.get('gateway', 'Unknown')
                distance = safe_int(r.get('distance', 1))
                active = r.get('active', 'false') == 'true'
                status = "🟢 Principal (Activo)" if active else "🟠 Respaldo/Failover (Standby)"
                wans.append({
                    "gateway": gateway,
                    "distance": distance,
                    "status": status,
                    "active": active,
                    "interface": r.get('gateway-status', '').split(' via ')[-1] if 'via' in r.get('gateway-status', '') else 'Unknown'
                })
                
            wans = sorted(wans, key=lambda x: x['distance'])
            active_wan = next((w for w in wans if w['active']), None)
            
            # 2. Determinar método de conexión (Estática vs DHCP/PPPoE)
            connection_method = "Estática (Manual)"
            dhcp_client = self.api.get_resource('/ip/dhcp-client').get()
            pppoe_client = self.api.get_resource('/interface/pppoe-client').get()
            
            # También revisamos si hay una IP pública/WAN dinámica
            addrs = self.api.get_resource('/ip/address').get()
            wan_ip = "N/A"
            if active_wan and active_wan['interface'] != 'Unknown':
                # Buscar IP de la interfaz WAN
                for a in addrs:
                    if a.get('interface') == active_wan['interface']:
                        wan_ip = a.get('address', 'N/A')
                        if a.get('dynamic', 'false') == 'true':
                            # Si es dinámica y no hemos detectado el tipo aún
                            connection_method = "Dinámica (Auto Asignada)"
                        break

            if dhcp_client and any(d.get('status') == 'bound' for d in dhcp_client):
                connection_method = "Dinámica (DHCP Client)"
            elif pppoe_client and any(p.get('running') == 'true' for p in pppoe_client):
                connection_method = "Dinámica (PPPoE Client)"
                
            return {
                "wans": wans,
                "has_failover": len(wans) > 1,
                "active_wan": active_wan,
                "connection_method": connection_method,
                "wan_ip": wan_ip
            }
        except Exception as e:
            logger.error(f"Error en GET WAN STATUS: {e}")
            return {}

    # ─────────────────────────────────────────────────
    # CAPA 1 — Diagnóstico Físico
    # ─────────────────────────────────────────────────

    @require_api(default_return=[])
    def get_interface_health(self) -> List[Dict]:
        """
        Detecta anomalías en la capa física de las interfaces.
        Monitorea: errores TX/RX, drops, FCS, CRC para predicción de fallos de cableado.

        Returns:
            Lista de interfaces con anomalías, ordenadas por severidad, cada una con:
            interface, tx_errors, rx_errors, tx_drops, rx_drops, total_errors,
            total_drops, running, type, severity, status.
        """
        try:
            stats = self.api.get_resource('/interface').get()
            anomalias = []
            for s in stats:
                name = s.get('name', 'eth')
                tx_err = safe_int(s.get('tx-error', 0))
                rx_err = safe_int(s.get('rx-error', 0))
                tx_drop = safe_int(s.get('tx-drop', 0))
                rx_drop = safe_int(s.get('rx-drop', 0))
                fp_err = safe_int(s.get('fp-rx-error', 0)) + safe_int(s.get('fp-tx-error', 0))

                total_errors = tx_err + rx_err + fp_err
                total_drops = tx_drop + rx_drop

                if total_errors > 0 or total_drops > 500:
                    if total_errors > 1000 or total_drops > 50000:
                        severity, status = "CRITICAL", "🔴 Reemplazo de cable recomendado"
                    elif total_errors > 100 or total_drops > 10000:
                        severity, status = "WARNING", "🟠 Degradación de Capa 1"
                    else:
                        severity, status = "INFO", "🟡 Anomalía menor detectada"

                    anomalias.append({
                        "interface": name,
                        "tx_errors": tx_err,
                        "rx_errors": rx_err,
                        "tx_drops": tx_drop,
                        "rx_drops": rx_drop,
                        "total_errors": total_errors,
                        "total_drops": total_drops,
                        "running": s.get('running', 'false'),
                        "type": s.get('type', 'unknown'),
                        "severity": severity,
                        "status": status,
                    })
            return sorted(anomalias, key=lambda x: x['total_errors'], reverse=True)
        except Exception as e:
            logger.error(f"Error en diagnóstico de interfaces: {e}")
            return []

    # ─────────────────────────────────────────────────
    # TRÁFICO — Monitoreo en Tiempo Real
    # ─────────────────────────────────────────────────

    @require_api(default_return=[])
    def get_smart_traffic(self) -> List[Dict]:
        """
        Monitoreo inteligente de tráfico en tiempo real por interfaz.
        Solo retorna interfaces con tráfico activo (> 50 Kbps).
        Filtra loopbacks, dummies e interfaces inactivas.

        Returns:
            Lista ordenada por RX descendente con: name, rx, tx, total (en Mbps),
            running, type.
        """
        try:
            interfaces = self.api.get_resource('/interface').get()
            running_ifaces = [
                i for i in interfaces
                if i.get('running', 'false') == 'true'
                and i.get('type') not in ('dummy', 'loopback')
                and not i.get('name', '').startswith('loop')
            ]

            resultados = []
            for iface in running_ifaces:
                iface_name = iface['name']
                try:
                    t = self.api.get_resource('/interface').call(
                        'monitor-traffic',
                        {'interface': iface_name, 'once': 'yes'}
                    )[0]
                    rx_mbps = safe_int(t.get('rx-bits-per-second', 0)) / 1_048_576
                    tx_mbps = safe_int(t.get('tx-bits-per-second', 0)) / 1_048_576

                    if rx_mbps > 0.05 or tx_mbps > 0.05:
                        resultados.append({
                            "name": iface_name,
                            "rx": round(rx_mbps, 2),
                            "tx": round(tx_mbps, 2),
                            "total": round(rx_mbps + tx_mbps, 2),
                            "running": iface.get('running', 'true'),
                            "type": iface.get('type', 'ethernet'),
                        })
                except Exception:
                    continue

            return sorted(resultados, key=lambda x: x['rx'], reverse=True)
        except Exception as e:
            logger.error(f"Error en monitoreo de tráfico: {e}")
            return []

    # ─────────────────────────────────────────────────
    # DIAGNÓSTICOS — SFP / LTE
    # ─────────────────────────────────────────────────

    @require_api(default_return=[])
    def get_sfp_diagnostics(self) -> List[Dict]:
        """
        Diagnóstico de transceptores ópticos (SFP DOM) y módems LTE.
        Monitorea potencia óptica, temperatura SFP y señal celular.

        Returns:
            Lista de diagnósticos con: interface, type, signal/rx_power,
            temperature, status, severity.
        """
        diagnosticos = []
        try:
            diagnosticos.extend(self._diagnose_sfp_modules())
            diagnosticos.extend(self._diagnose_lte_modems())
            return diagnosticos
        except Exception as e:
            logger.error(f"Error en diagnóstico SFP/LTE: {e}")
            return []

    def _diagnose_sfp_modules(self) -> List[Dict]:
        """Diagnóstico detallado de módulos SFP con clasificación de severidad."""
        results = []
        try:
            eths = self.api.get_resource('/interface/ethernet').get()
            sfps = [e['name'] for e in eths if 'sfp' in e.get('name', '').lower()]

            for name in sfps:
                try:
                    m = self.api.get_resource('/interface/ethernet').call(
                        'monitor', {'.id': name, 'once': 'yes'}
                    )[0]
                    rx_pwr = m.get('rx-power', 'N/A')
                    tx_pwr = m.get('tx-power', 'N/A')
                    temp = m.get('sfp-temperature', 'N/A')

                    if rx_pwr != 'N/A':
                        rx_float = float(rx_pwr)
                        if rx_float < -25:
                            status, severity = "🔴 Señal crítica", "CRITICAL"
                        elif rx_float < -20:
                            status, severity = "🟠 Señal baja", "WARNING"
                        else:
                            status, severity = "🟢 Saludable", "OK"

                        results.append({
                            "interface": name,
                            "type": "SFP (Óptico)",
                            "rx_power": f"{rx_pwr} dBm",
                            "tx_power": f"{tx_pwr} dBm",
                            "temperature": f"{temp}°C",
                            # Backward compat con el campo 'señal' original
                            "señal": f"{rx_pwr} dBm",
                            "temp": f"{temp}°C",
                            "status": status,
                            "severity": severity,
                        })
                except Exception:
                    continue
        except Exception:
            pass
        return results

    def _diagnose_lte_modems(self) -> List[Dict]:
        """Diagnóstico detallado de módems LTE con RSRP y SINR."""
        results = []
        try:
            ltes = self.api.get_resource('/interface/lte').get()
            for lte in ltes:
                name = lte.get('name', 'lte1')
                try:
                    m = self.api.get_resource('/interface/lte').call(
                        'monitor', {'.id': name, 'once': 'yes'}
                    )[0]
                    rssi = m.get('rssi', m.get('signal-strength', 'N/A'))
                    rsrp = m.get('rsrp', 'N/A')
                    sinr = m.get('sinr', 'N/A')
                    operator = m.get('current-operator', 'N/A')

                    try:
                        rssi_val = float(rssi)
                        if rssi_val < -100:
                            status, severity = "🔴 Sin cobertura", "CRITICAL"
                        elif rssi_val < -90:
                            status, severity = "🟠 Señal débil", "WARNING"
                        elif rssi_val < -70:
                            status, severity = "🟡 Señal moderada", "INFO"
                        else:
                            status, severity = "🟢 Señal fuerte", "OK"
                    except (ValueError, TypeError):
                        status, severity = "⚪ Indeterminada", "UNKNOWN"

                    results.append({
                        "interface": name,
                        "type": "Módem LTE",
                        "signal": f"{rssi} dBm",
                        # Backward compat
                        "señal": f"{rssi} dBm",
                        "temp": "N/A",
                        "rsrp": rsrp,
                        "sinr": sinr,
                        "operator": operator,
                        "temperature": "N/A",
                        "status": status,
                        "severity": severity,
                    })
                except Exception:
                    continue
        except Exception:
            pass
        return results

    # ─────────────────────────────────────────────────
    # CAPA 2 — ARP, Bridge, Neighbors
    # ─────────────────────────────────────────────────

    @require_api(default_return=[])
    def get_dhcp_leases(self) -> List[Dict]:
        """
        Obtiene leases DHCP activos (status = 'bound').

        Returns:
            Lista de leases activos con todos los campos del RouterOS.
        """
        try:
            leases = self.api.get_resource('/ip/dhcp-server/lease').get()
            return [l for l in leases if l.get('status') == 'bound']
        except Exception as e:
            logger.error(f"Error leyendo DHCP leases: {e}")
            return []

    @require_api(default_return=[])
    def get_router_ips(self) -> List[str]:
        """
        Obtiene todas las IPs asignadas al router (sin máscara).

        Returns:
            Lista de strings con IPs limpias.
        """
        try:
            direcciones = self.api.get_resource('/ip/address').get()
            return [d['address'].split('/')[0] for d in direcciones if 'address' in d]
        except Exception as e:
            logger.error(f"Error obteniendo IPs del router: {e}")
            return []

    @require_api(default_return={})
    def get_arp_table(self) -> Dict[str, str]:
        """
        Obtiene la tabla ARP como mapa IP → MAC.

        Returns:
            Dict {ip_address: mac_address} con MACs en uppercase.
        """
        try:
            arp_data = self.api.get_resource('/ip/arp').get()
            return {
                item['address']: item['mac-address'].upper()
                for item in arp_data
                if 'address' in item and 'mac-address' in item
            }
        except Exception as e:
            logger.error(f"Error leyendo tabla ARP: {e}")
            return {}

    @require_api(default_return=[])
    def get_local_networks(self) -> List[Dict]:
        """
        Obtiene las redes locales configuradas.
        Incluye redes dinámicas (PPPoE/DHCP) y point-to-point (/30) para visibilidad completa.

        Returns:
            Lista con: network (CIDR), interface, address, comment, dynamic (bool).
        """
        try:
            direcciones = self.api.get_resource('/ip/address').get()
            redes = []
            for d in direcciones:
                address = d.get('address', '')
                if '/' not in address:
                    continue
                mask = address.split('/')[-1]
                if d.get('disabled') == 'true':
                    continue
                # Ya no excluimos dinámicas ni /30 — son infraestructura real
                if mask == '32':
                    continue
                is_dynamic = d.get('dynamic', 'false') == 'true'
                redes.append({
                    "network": f"{d.get('network')}/{mask}",
                    "interface": d.get('interface'),
                    "address": address,
                    "comment": d.get('comment', f"Red {d.get('interface')}"),
                    "dynamic": is_dynamic,
                })
            return redes
        except Exception as e:
            logger.error(f"Error leyendo redes locales: {e}")
            return []

    @require_api(default_return=[])
    def get_ethernet_neighbors(self) -> List[Dict]:
        """
        Descubrimiento de vecinos por cable (CDP, LLDP, MNDP).
        Detecta APs, Switches y otros equipos MikroTik en la red L2.
        """
        try:
            return self.api.get_resource('/ip/neighbor').get()
        except Exception as e:
            logger.debug(f"Neighbors no disponible: {e}")
            return []

    @require_api(default_return=[])
    def get_bridge_hosts(self) -> List[Dict]:
        """
        Mapeo L2 de MACs a puertos físicos del Bridge.
        Descubre equipos 'detrás' de cada AP/Switch/Puerto.
        """
        try:
            return self.api.get_resource('/interface/bridge/host').get()
        except Exception as e:
            logger.debug(f"Bridge hosts no disponible: {e}")
            return []

    # ─────────────────────────────────────────────────
    # CAPA 3 — Routing y DNS
    # ─────────────────────────────────────────────────

    @require_api(default_return={"rutas_totales": 0, "rutas_activas": 0, "ospf_neighbors": []})
    def get_routing_health(self) -> Dict:
        """
        Estado completo de la tabla de enrutamiento incluyendo OSPF y BGP.

        Returns:
            Dict con: rutas_totales, rutas_activas, static_routes, dynamic_routes,
            default_gateway, ospf_neighbors, bgp_peers.
        """
        try:
            rutas = self.api.get_resource('/ip/route').get()

            active = [r for r in rutas if r.get('active', 'false') == 'true']
            static = [r for r in rutas if r.get('static', 'false') == 'true']
            dynamic = [r for r in rutas if r.get('dynamic', 'false') == 'true']

            # Gateway por defecto
            default_gw = 'N/A'
            for r in active:
                if r.get('dst-address') == '0.0.0.0/0':
                    default_gw = r.get('gateway', 'N/A')
                    break

            # OSPF Neighbors (implementado completamente)
            ospf = []
            try:
                ospf_raw = self.api.get_resource('/routing/ospf/neighbor').get()
                ospf = [{
                    "router_id": n.get('router-id', ''),
                    "address": n.get('address', ''),
                    "state": n.get('state', ''),
                    "interface": n.get('interface', ''),
                } for n in ospf_raw]
            except Exception:
                pass

            # BGP Peers
            bgp = []
            try:
                bgp_raw = self.api.get_resource('/routing/bgp/peer').get()
                bgp = [{
                    "name": p.get('name', ''),
                    "remote_address": p.get('remote-address', ''),
                    "remote_as": p.get('remote-as', ''),
                    "state": p.get('state', ''),
                } for p in bgp_raw]
            except Exception:
                pass

            return {
                "rutas_totales": len(rutas),
                "rutas_activas": len(active),
                "static_routes": len(static),
                "dynamic_routes": len(dynamic),
                "default_gateway": default_gw,
                "ospf_neighbors": ospf,
                "bgp_peers": bgp,
            }
        except Exception as e:
            logger.error(f"Error leyendo routing: {e}")
            return {"rutas_totales": 0, "rutas_activas": 0, "ospf_neighbors": []}

    @require_api(default_return={})
    def get_dns_config(self) -> Dict:
        """
        Obtiene la configuración DNS del router.

        Returns:
            Dict con: servers, dynamic_servers, allow_remote, cache_size, cache_used.
        """
        try:
            dns = self.api.get_resource('/ip/dns').get()
            if dns:
                d = dns[0] if isinstance(dns, list) else dns
                return {
                    "servers": d.get('servers', ''),
                    "dynamic_servers": d.get('dynamic-servers', ''),
                    "allow_remote": d.get('allow-remote-requests', 'false'),
                    "cache_size": d.get('cache-size', '2048'),
                    "cache_used": d.get('cache-used', '0'),
                }
            return {}
        except Exception as e:
            logger.debug(f"Error leyendo DNS: {e}")
            return {}
