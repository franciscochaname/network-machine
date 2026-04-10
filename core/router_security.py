# core/router_security.py
"""
Módulo de Seguridad — Operaciones de Firewall y Control de Acceso.
Contiene SOLO métodos de acción (bloqueo, desbloqueo, flush, reboot).
Los métodos de lectura/monitoreo han sido migrados a core/telemetry/monitoring.py y devices.py.
"""
import logging

from core.telemetry._utils import (
    SOCIAL_DOMAIN_MAP, expand_social_domains, clean_ip, logger,
)




class SecurityMixin:
    """
    Mixin para operaciones de seguridad y control de firewall en MikroTik.
    Métodos de ACCIÓN: block, unblock, flush, reboot.
    """

    # ================================================================
    # BLOQUEO DE IPs Y SUBREDES
    # ================================================================

    def block_ip(self, ip_address, comment="Bloqueo automático"):
        """Agrega una IP a la Blacklist del Firewall."""
        if not self.api:
            return False, "API desconectada."
        try:
            ip_limpia = clean_ip(ip_address)
            self.api.get_resource('/ip/firewall/address-list').add(
                list="Blacklist", address=ip_limpia, comment=comment
            )
            return True, f"✅ IP {ip_limpia} neutralizada."
        except Exception as e:
            return False, str(e)

    def create_advanced_block(self, block_type, target, comment="Bloqueo Táctico SOC", target_origen="Todos"):
        """
        Inyecta reglas prioritarias y fuerza el reset de conexiones.
        Soporta: Kill Switch, IP/Subred, Página Web, Puerto.

        Args:
            block_type: Tipo de bloqueo ('Kill Switch', 'IP / Subred', 'Página Web', 'Puerto').
            target: Objetivo del bloqueo (IP, dominio, puerto).
            comment: Comentario descriptivo para la regla.
            target_origen: IP de origen específica o 'Todos' para aplicar globalmente.
        """
        if not self.api:
            return False, "API desconectada."
        try:
            target_clean = target.split(':')[0].strip().lower()
            fw = self.api.get_resource('/ip/firewall/filter')
            al = self.api.get_resource('/ip/firewall/address-list')

            # --- SHIELD ENGINE: REGLAS MAESTRAS (Posición 0) ---
            self._ensure_shield_rules(fw)

            src_address_param = {}
            prefix_log = "Aplica a todos los usuarios"
            if target_origen and target_origen != "Todos":
                src_address_param = {'src-address': target_origen}
                prefix_log = f"Aplica solo para: {target_origen}"

            # --- LÓGICA DE INTERVENCIÓN TÁCTICA ---
            if "Kill Switch" in block_type or "0.0.0.0/0" in target_clean:
                return self._execute_kill_switch(fw, comment, src_address_param, target_origen)

            elif "IP / Subred" in block_type:
                return self._execute_ip_block(fw, al, target_clean, comment, src_address_param, target_origen)

            elif "Página Web" in block_type:
                return self._execute_web_block(fw, al, target_clean, comment, src_address_param, target_origen, prefix_log)

            elif "Puerto" in block_type:
                return self._execute_port_block(fw, target_clean, comment, src_address_param, prefix_log)

            return False, "Estrategia no reconocida."
        except Exception as e:
            return False, f"Fallo en motor táctico: {str(e)}"

    def _ensure_shield_rules(self, fw):
        """Garantiza que las reglas maestras del Shield Engine existan en posición 0."""
        try:
            if not fw.get(comment="GLOBAL_SOC_QUIC_DROP"):
                fw.add(chain="forward", action="drop", protocol="udp", dst_port="443",
                       comment="GLOBAL_SOC_QUIC_DROP", **{'place-before': '0'})

            if not fw.get(comment="GLOBAL_SOC_NETWORKS_DROP"):
                fw.add(chain="forward", action="drop", dst_address_list="Redes_Bloqueadas",
                       comment="GLOBAL_SOC_NETWORKS_DROP", **{'place-before': '0'})

            if not fw.get(comment="GLOBAL_SOC_BLACKLIST_DROP"):
                fw.add(chain="forward", action="drop", src_address_list="Blacklist",
                       comment="GLOBAL_SOC_BLACKLIST_DROP", **{'place-before': '0'})
                fw.add(chain="forward", action="drop", dst_address_list="Blacklist",
                       comment="GLOBAL_SOC_BLACKLIST_DROP", **{'place-before': '0'})
        except Exception as e:
            logger.warning(f"Error creando reglas Shield: {e}")

    def _execute_kill_switch(self, fw, comment, src_address_param, target_origen):
        """Kill Switch: Bloqueo absoluto de tránsito e input."""
        fw.add(chain="forward", action="drop",
               comment=f"SOC KILL-SWITCH: {comment}", **src_address_param, **{'place-before': '0'})
        fw.add(chain="input", action="drop",
               comment=f"SOC KILL-SWITCH-LOCAL: {comment}", **src_address_param, **{'place-before': '0'})
        self._flush_connections(target_origen)
        return True, f"🛑 [KILL SWITCH] Dispositivo {target_origen} totalmente aislado de la red."

    def _execute_ip_block(self, fw, al, target_clean, comment, src_address_param, target_origen):
        """Bloqueo por IP o subred."""
        if target_origen and target_origen != "Todos":
            fw.add(chain="forward", action="drop", src_address=target_origen,
                   dst_address=target_clean, comment=f"SOC Drop Cruzado: {comment}",
                   **{'place-before': '0'})
            self._flush_connections(target_origen)
            return True, f"✅ IP {target_clean} neutralizada para {target_origen}."
        else:
            al.add(list="Blacklist", address=target_clean, comment=f"SOC Blacklist: {comment}")
            return True, f"✅ {target_clean} en Blacklist Global."

    def _execute_web_block(self, fw, al, target_clean, comment, src_address_param, target_origen, prefix_log):
        """Bloqueo de página web con expansión de dominios satélite y bloqueo L7."""
        # Expandir dominios usando constante compartida
        dominios = expand_social_domains(target_clean)

        for d in dominios:
            try:
                al.add(list="Redes_Bloqueadas", address=d, comment=f"SOC Tactical: {comment}")
            except Exception:
                pass

        # Bloqueo estricto de Capa 7 (SNI / Content)
        self._inject_l7_rules(fw, dominios, src_address_param)

        # DNS Trap
        self._inject_dns_trap(fw, target_origen, target_clean, src_address_param)

        self._flush_connections(target_origen)
        return True, f"✅ Estrategia '{target_clean}' inyectada con Bloqueo SNI/SSL y Flush. {prefix_log}."

    def _execute_port_block(self, fw, target_clean, comment, src_address_param, prefix_log):
        """Bloqueo por puerto (TCP + UDP)."""
        fw.add(chain="forward", action="drop", protocol="tcp", dst_port=target_clean,
               comment=f"SOC Port Block TCP: {comment}", **src_address_param,
               **{'place-before': '0'})
        fw.add(chain="forward", action="drop", protocol="udp", dst_port=target_clean,
               comment=f"SOC Port Block UDP: {comment}", **src_address_param,
               **{'place-before': '0'})
        self._flush_connections(None)
        return True, f"✅ Puerto {target_clean} cerrado con prioridad SOC. {prefix_log}."

    def _inject_l7_rules(self, fw, dominios, src_address_param):
        """Inyecta reglas de bloqueo de Capa 7 (TLS SNI + HTTP Content)."""
        for d in dominios:
            d_base = d.replace('www.', '')
            try:
                fw.add(chain="forward", action="drop", protocol="tcp", dst_port="443",
                       comment=f"SOC TLS-Block: {d_base}",
                       **{'tls-host': f"*{d_base}*", 'place-before': '0'}, **src_address_param)
            except Exception:
                pass
            try:
                fw.add(chain="forward", action="drop", protocol="tcp", dst_port="80",
                       comment=f"SOC HTTP-Block: {d_base}",
                       **{'content': d_base, 'place-before': '0'}, **src_address_param)
            except Exception:
                pass

    def _inject_dns_trap(self, fw, target_origen, target_clean, src_address_param):
        """Inyecta reglas DNS Trap para forzar uso del DNS local."""
        if target_origen and target_origen != "Todos":
            try:
                fw.add(chain="forward", action="drop", protocol="udp", dst_port="53",
                       src_address=target_origen, comment="SOC DNS-Trap",
                       **{'place-before': '0'})
            except Exception:
                pass
            try:
                fw.add(chain="forward", action="drop", dst_address_list="Redes_Bloqueadas",
                       src_address=target_origen, comment=f"SOC Target-Block: {target_clean}",
                       **{'place-before': '0'})
            except Exception:
                pass
        else:
            try:
                fw.add(chain="forward", action="drop", protocol="udp", dst_port="53",
                       comment="SOC GLOBAL DNS-Trap", **{'place-before': '0'})
            except Exception:
                pass

    # ================================================================
    # FLUSH DE CONEXIONES (efecto instantáneo)
    # ================================================================

    def _flush_connections(self, ip_target):
        """
        Mata TODAS las conexiones existentes de una IP para efecto INSTANTÁNEO.
        Busca conexiones donde el dispositivo es ORIGEN o DESTINO.
        Crítico para flujos QUIC (UDP 443) y sesiones TCP activas.
        """
        if not self.api or not ip_target:
            return

        try:
            ip_clean = clean_ip(ip_target)
            conn_res = self.api.get_resource('/ip/firewall/connection')

            try:
                # Filtrado por API (eficiente)
                for c in conn_res.get(src_address=ip_clean):
                    try:
                        conn_res.remove(id=c['.id'])
                    except Exception:
                        pass
                for c in conn_res.get(dst_address=ip_clean):
                    try:
                        conn_res.remove(id=c['.id'])
                    except Exception:
                        pass
            except Exception:
                # Fallback: iteración manual para versiones antiguas
                for c in conn_res.get():
                    src = c.get('src-address', '').split(':')[0]
                    dst = c.get('dst-address', '').split(':')[0]
                    if src == ip_clean or dst == ip_clean:
                        try:
                            conn_res.remove(id=c['.id'])
                        except Exception:
                            pass

            logging.info(f"SOC Flush: Conexiones de {ip_clean} purgadas del Firewall.")
        except Exception as e:
            logging.warning(f"Error en flush táctico: {e}")

    # ================================================================
    # BLOQUEO POR PÁGINA WEB (por dispositivo)
    # ================================================================

    def block_page_for_device(self, device_ip, domain, reason="Bloqueo de Página SOC"):
        """
        Bloquea una página web específica SOLO para un dispositivo concreto.
        Usa Address List + regla Forward con src-address para targeting preciso.
        Incluye bloqueo L7 (TLS SNI + HTTP Content) y DNS Trap.

        Args:
            device_ip: IP del dispositivo objetivo.
            domain: Dominio a bloquear.
            reason: Razón del bloqueo para trazabilidad.
        """
        if not self.api:
            return False, "API desconectada."
        try:
            domain_clean = domain.strip().lower()
            ip_clean = clean_ip(device_ip)
            al = self.api.get_resource('/ip/firewall/address-list')
            fw = self.api.get_resource('/ip/firewall/filter')

            # Expandir dominios usando constante compartida
            dominios = expand_social_domains(domain_clean)

            list_name = f"SOC_BLOCK_{ip_clean}"
            comment_tag = f"SOC-PAGE-BLOCK:{ip_clean}:{domain_clean}:{reason[:50]}"

            # 1. Address List exclusiva para este dispositivo
            for d in dominios:
                try:
                    al.add(list=list_name, address=d, comment=comment_tag)
                except Exception:
                    pass

            # 2. Regla de bloqueo forward específica
            try:
                fw.add(chain="forward", action="drop", dst_address_list=list_name,
                       src_address=ip_clean, comment=comment_tag,
                       **{'place-before': '0'})
            except Exception:
                pass

            # 3. Bloqueo estricto de Capa 7 (SNI + HTTP)
            for d in dominios:
                d_base = d.replace('www.', '')
                try:
                    fw.add(chain="forward", action="drop", protocol="tcp", dst_port="443",
                           src_address=ip_clean, comment=comment_tag,
                           **{'tls-host': f"*{d_base}*", 'place-before': '0'})
                except Exception:
                    pass
                try:
                    fw.add(chain="forward", action="drop", protocol="tcp", dst_port="80",
                           src_address=ip_clean, comment=comment_tag,
                           **{'content': d_base, 'place-before': '0'})
                except Exception:
                    pass

            # 4. DNS Trap por dispositivo
            try:
                existing_dns_trap = fw.get(comment=f"SOC DNS-Trap:{ip_clean}")
                if not existing_dns_trap:
                    fw.add(chain="forward", action="drop", protocol="udp", dst_port="53",
                           src_address=ip_clean, comment=f"SOC DNS-Trap:{ip_clean}",
                           **{'place-before': '0'})
            except Exception:
                pass

            # 5. Flush conexiones para efecto instantáneo
            self._flush_connections(ip_clean)

            return True, f"✅ {domain_clean} bloqueado estrictamente (L3 + L7/SNI). {len(dominios)} dominio(s) procesados."
        except Exception as e:
            return False, f"Error bloqueando página: {str(e)}"

    # ================================================================
    # SISTEMA
    # ================================================================

    def reboot_router(self):
        """Envía orden de reinicio al equipo MikroTik."""
        if not self.api:
            return False, "API desconectada."
        try:
            self.api.get_resource('/system').call('reboot')
            return True, "Reiniciando..."
        except Exception:
            return True, "⚡ Orden de reinicio enviada."

    # ================================================================
    # LECTURA DEL ESTADO DE BLOQUEOS
    # ================================================================

    def get_blacklisted_ips(self):
        """Obtiene las IPs y Reglas SOC que están actualmente bloqueadas en el Firewall."""
        if not self.api:
            return []
        try:
            lista = []

            # 1. Address Lists (Cuarentena y Redes)
            try:
                items = self.api.get_resource('/ip/firewall/address-list').get()
                for i in items:
                    l_name = i.get('list')
                    if l_name in ['Blacklist', 'Redes_Bloqueadas']:
                        prefix = "L3" if l_name == 'Blacklist' else "WEB"
                        lista.append({
                            "id": i['.id'], "target": i['address'],
                            "comment": f"[{prefix}] {i.get('comment', '')}",
                            "type": "address-list", "bytes": "N/A", "packets": "N/A",
                        })
            except Exception as e:
                logger.warning(f"Error leyendo address-list: {e}")

            # 2. Filter Rules (Tácticas SOC)
            try:
                filters = self.api.get_resource('/ip/firewall/filter').get()
                for f in filters:
                    comment = f.get('comment', '').upper()
                    if any(tag in comment for tag in ['SOC', 'TACTICAL', 'TARGET', 'TLS', 'HTTP']):
                        target = f.get('dst-address',
                                       f.get('tls-host',
                                             f.get('dst-port', 'Filtro Dinámico')))

                        if 'tls-host' in f:
                            target = f"Dominio Web: {f['tls-host']}"
                        elif 'content' in f:
                            target = f"Contenido HTTP: {f['content']}"
                        elif 'dst-address-list' in f:
                            target = f"Lista de Redes: {f['dst-address-list']}"

                        origen = f.get('src-address', f.get('src-mac-address', 'Red Local (Global)'))
                        b = int(f.get('bytes', 0))
                        p = int(f.get('packets', 0))

                        lista.append({
                            "id": f['.id'],
                            "target": f"{target} (Origen: {origen})",
                            "comment": f.get('comment', ''),
                            "type": "filter",
                            "bytes": b,
                            "packets": p,
                        })
            except Exception as e:
                logger.error(f"Error detectando reglas de red: {e}")

            return lista
        except Exception:
            return []

    # ================================================================
    # DESBLOQUEO
    # ================================================================

    def unblock_ip(self, ip_id, rule_type="address-list"):
        """Desbloquea una IP o regla específica eliminándola del Firewall."""
        if not self.api:
            return False, "API desconectada."
        try:
            if rule_type == "filter":
                self.api.get_resource('/ip/firewall/filter').remove(id=ip_id)
            else:
                self.api.get_resource('/ip/firewall/address-list').remove(id=ip_id)
            return True, "✅ Restricción levantada (Regla eliminada del Firewall)."
        except Exception as e:
            return False, f"Fallo al eliminar: {str(e)}"

    def unblock_by_ip(self, ip_address):
        """
        Busca y elimina TODAS las reglas (Filter y Address-list) que mencionen una IP.
        Ideal para revertir bloqueos de un dispositivo de golpe.
        """
        if not self.api or not ip_address:
            return False, "Sin conexión o IP."
        try:
            ip_clean = clean_ip(ip_address)

            # 1. Limpiar Address Lists
            al = self.api.get_resource('/ip/firewall/address-list')
            for item in al.get(address=ip_clean):
                try:
                    al.remove(id=item['.id'])
                except Exception:
                    pass

            # 2. Limpiar Filter Rules
            fw = self.api.get_resource('/ip/firewall/filter')
            for f in fw.get():
                comment = f.get('comment', '')
                src = f.get('src-address', '')
                if ip_clean in src or ip_clean in comment:
                    try:
                        fw.remove(id=f['.id'])
                    except Exception:
                        pass

            # 3. Limpiar Address Lists dinámicas de bloqueos de página
            list_name = f"SOC_BLOCK_{ip_clean}"
            for item in al.get(list=list_name):
                try:
                    al.remove(id=item['.id'])
                except Exception:
                    pass

            return True, f"✅ Todas las reglas de {ip_clean} han sido revertidas."
        except Exception as e:
            return False, f"Error en limpieza masiva: {e}"

    def unblock_all_soc_rules(self):
        """Limpia TODO el Firewall eliminando cualquier regla inyectada por el SOC."""
        if not self.api:
            return False, "API desconectada."
        try:
            removed = 0

            # Limpiar Filters
            fw = self.api.get_resource('/ip/firewall/filter')
            for f in fw.get():
                if 'SOC' in f.get('comment', '').upper():
                    try:
                        fw.remove(id=f['.id'])
                        removed += 1
                    except Exception:
                        pass

            # Limpiar Address Lists
            al = self.api.get_resource('/ip/firewall/address-list')
            for item in al.get():
                if 'SOC' in item.get('comment', '').upper() or 'SOC_BLOCK' in item.get('list', ''):
                    try:
                        al.remove(id=item['.id'])
                        removed += 1
                    except Exception:
                        pass

            return True, f"✅ Limpieza total completada: {removed} reglas SOC eliminadas."
        except Exception as e:
            return False, f"Error en limpieza total SOC: {e}"

    # ================================================================
    # BLOQUEO PERSISTENTE POR DISPOSITIVO (MAC + IP)
    # ================================================================

    def block_device(self, ip_address, mac_address=None, hostname="", reason="Bloqueo Administrativo", connection_type="LAN"):
        """
        Bloquea un dispositivo inyectando reglas multicapa en el Firewall.
        - Si hay MAC: Bloquea por src-mac-address (persiste si cambia IP)
        - Siempre bloquea por IP en cadenas forward + input
        - Flush de conexiones existentes para efecto inmediato

        Returns:
            (exito: bool, mensaje: str, lista_ids_reglas: list)
        """
        if not self.api:
            return False, "API desconectada.", []
        try:
            fw = self.api.get_resource('/ip/firewall/filter')
            rule_ids = []
            ip_clean = clean_ip(ip_address) if ip_address else ""
            mac_clean = mac_address.strip().upper() if mac_address else ""
            comment_tag = f"SOC-DEVICE-BLOCK:{ip_clean}:{mac_clean}:{reason[:50]}"

            # 1. Bloqueo por MAC (L2) — Cubre WiFi y cambios de IP
            if mac_clean:
                for chain in ("forward", "input"):
                    try:
                        r = fw.add(chain=chain, action="drop", comment=comment_tag,
                                   **{'src-mac-address': mac_clean, 'place-before': '0'})
                        rule_ids.append(r)
                    except Exception as e:
                        logging.warning(f"No se pudo bloquear MAC {chain}: {e}")

            # 2. Bloqueo por IP (L3) — Forward + Input
            if ip_clean:
                for chain in ("forward", "input"):
                    try:
                        r = fw.add(chain=chain, action="drop", src_address=ip_clean,
                                   comment=comment_tag, **{'place-before': '0'})
                        rule_ids.append(r)
                    except Exception as e:
                        logging.warning(f"No se pudo bloquear IP {chain}: {e}")

            # 3. Flush de conexiones activas
            self._flush_connections(ip_clean)

            if rule_ids:
                real_ids = []
                for r in rule_ids:
                    if isinstance(r, list) and len(r) > 0:
                        real_ids.append(r[0].get('ret', r[0].get('.id', '')))
                    elif isinstance(r, dict):
                        real_ids.append(r.get('ret', r.get('.id', '')))
                    elif isinstance(r, str):
                        real_ids.append(r)

                return True, f"✅ Dispositivo {hostname or ip_clean} bloqueado ({connection_type}). {len(rule_ids)} reglas inyectadas.", real_ids
            else:
                return False, "No se pudo crear ninguna regla de bloqueo.", []
        except Exception as e:
            return False, f"Error en bloqueo de dispositivo: {str(e)}", []

    def unblock_device(self, firewall_rule_ids_csv):
        """
        Desbloquea un dispositivo eliminando todas las reglas de Firewall asociadas.

        Args:
            firewall_rule_ids_csv: String con IDs separados por coma.
        """
        if not self.api:
            return False, "API desconectada."
        try:
            fw = self.api.get_resource('/ip/firewall/filter')
            ids = [rid.strip() for rid in firewall_rule_ids_csv.split(',') if rid.strip()]
            eliminados = 0
            for rid in ids:
                try:
                    fw.remove(id=rid)
                    eliminados += 1
                except Exception:
                    pass
            return True, f"✅ {eliminados} regla(s) eliminada(s) del Firewall."
        except Exception as e:
            return False, f"Error al desbloquear: {str(e)}"

    def get_device_blocks_from_firewall(self):
        """Lee las reglas de bloqueo por dispositivo directamente del Firewall."""
        if not self.api:
            return []
        try:
            fw = self.api.get_resource('/ip/firewall/filter')
            rules = fw.get()
            blocks = []
            for r in rules:
                comment = r.get('comment', '')
                if comment.startswith('SOC-DEVICE-BLOCK:'):
                    parts = comment.replace('SOC-DEVICE-BLOCK:', '').split(':', 2)
                    ip = parts[0] if len(parts) > 0 else ''
                    mac = parts[1] if len(parts) > 1 else ''
                    reason = parts[2] if len(parts) > 2 else ''
                    blocks.append({
                        'id': r['.id'],
                        'chain': r.get('chain', ''),
                        'ip': ip,
                        'mac': mac or r.get('src-mac-address', ''),
                        'reason': reason,
                        'disabled': r.get('disabled', 'false'),
                    })
            return blocks
        except Exception:
            return []