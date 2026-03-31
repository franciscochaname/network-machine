# core/router_security.py
import logging

class SecurityMixin:
    def get_security_saturation(self):
        if not self.api: return {"conexiones_activas": 0, "max_conexiones": 300000}
        try: return {"conexiones_activas": len(self.api.get_resource('/ip/firewall/connection').get()), "max_conexiones": 300000}
        except: return {"conexiones_activas": 0, "max_conexiones": 300000}

    def block_ip(self, ip_address, comment="Bloqueo automático"):
        if not self.api: return False, "API desconectada."
        try:
            ip_limpia = ip_address.split(':')[0]
            self.api.get_resource('/ip/firewall/address-list').add(list="Blacklist", address=ip_limpia, comment=comment)
            return True, f"✅ IP {ip_limpia} neutralizada."
        except Exception as e: return False, str(e)

    def create_advanced_block(self, block_type, target, comment="Bloqueo Táctico SOC", target_origen="Todos"):
        """Inyecta reglas prioritarias y fuerza el reset de conexiones para asegurar la efectividad del bloqueo."""
        if not self.api: return False, "API desconectada."
        try:
            target_clean = target.split(':')[0].strip().lower()
            fw = self.api.get_resource('/ip/firewall/filter')
            al = self.api.get_resource('/ip/firewall/address-list')
            
            # --- SHIELD ENGINE: REGLAS MAESTRAS (Posición 0) ---
            try:
                # 1. Bloqueo Global de QUIC (UDP 443) a nivel Forward para forzar fallback a TCP
                if not fw.get(comment="GLOBAL_SOC_QUIC_DROP"):
                    fw.add(chain="forward", action="drop", protocol="udp", dst_port="443", comment="GLOBAL_SOC_QUIC_DROP", **{'place-before': '0'})
                
                # 2. Bloqueo Maestro de la lista 'Redes_Bloqueadas'
                if not fw.get(comment="GLOBAL_SOC_NETWORKS_DROP"):
                    fw.add(chain="forward", action="drop", dst_address_list="Redes_Bloqueadas", comment="GLOBAL_SOC_NETWORKS_DROP", **{'place-before': '0'})
                
                # 3. Bloqueo Maestro de la lista 'Blacklist'
                if not fw.get(comment="GLOBAL_SOC_BLACKLIST_DROP"):
                    fw.add(chain="forward", action="drop", src_address_list="Blacklist", comment="GLOBAL_SOC_BLACKLIST_DROP", **{'place-before': '0'})
                    fw.add(chain="forward", action="drop", dst_address_list="Blacklist", comment="GLOBAL_SOC_BLACKLIST_DROP", **{'place-before': '0'})
            except: pass

            src_address_param = {}
            prefix_log = "Aplica a todos los usuarios"
            if target_origen and target_origen != "Todos":
                src_address_param = {'src-address': target_origen}
                prefix_log = f"Aplica solo para: {target_origen}"
            
            # --- LÓGICA DE INTERVENCIÓN TÁCTICA ---
            if "Kill Switch" in block_type or "0.0.0.0/0" in target_clean:
                # KILL SWITCH: Bloqueo absoluto de tránsito (Internet) y acceso al router (Input)
                fw.add(chain="forward", action="drop", comment=f"SOC KILL-SWITCH: {comment}", **src_address_param, **{'place-before': '0'})
                fw.add(chain="input", action="drop", comment=f"SOC KILL-SWITCH-LOCAL: {comment}", **src_address_param, **{'place-before': '0'})
                self._flush_connections(target_origen)
                return True, f"🛑 [KILL SWITCH] Dispositivo {target_origen} totalmente aislado de la red."

            elif "IP / Subred" in block_type:
                if target_origen and target_origen != "Todos":
                    fw.add(chain="forward", action="drop", src_address=target_origen, dst_address=target_clean, comment=f"SOC Drop Cruzado: {comment}", **{'place-before': '0'})
                    self._flush_connections(target_origen)
                    return True, f"✅ IP {target_clean} neutralizada para {target_origen}."
                else:
                    al.add(list="Blacklist", address=target_clean, comment=f"SOC Blacklist: {comment}")
                    return True, f"✅ {target_clean} en Blacklist Global."
                
            elif "Página Web" in block_type:
                # Diccionario de dominios satélite por cada red social conocidos para bloqueo total
                social_map = {
                    "youtube": ["youtube.com", "googlevideo.com", "ytimg.com", "i.ytimg.com", "yt.be", "ggpht.com"],
                    "facebook": ["facebook.com", "fbcdn.net", "fbsbx.com", "messenger.com", "facebook.net"],
                    "tiktok": ["tiktok.com", "tiktokv.com", "byteoversea.com", "ibyteimg.com", "snssdk.com"],
                    "instagram": ["instagram.com", "cdninstagram.com", "ig.me"],
                    "netflix": ["netflix.com", "nflxext.com", "nflxvideo.net", "nflxso.net"]
                }
                
                dominios = [target_clean]
                for k, v in social_map.items():
                    if k in target_clean: dominios = list(set(dominios + v)); break
                
                for d in dominios:
                    try: al.add(list="Redes_Bloqueadas", address=d, comment=f"SOC Tactical: {comment}")
                    except: pass
                
                # --- NUEVO: BLOQUEO ESTRICTO DE CAPA 7 (SNI DENTRO DEL NAVEGADOR) GLOBAL ---
                for d in dominios:
                    d_base = d.replace('www.', '')
                    try:
                        fw.add(chain="forward", action="drop", protocol="tcp", dst_port="443",
                               comment=f"SOC TLS-Block: {d_base}", **{'tls-host': f"*{d_base}*", 'place-before': '0'}, **src_address_param)
                    except: pass
                    try:
                        fw.add(chain="forward", action="drop", protocol="tcp", dst_port="80",
                               comment=f"SOC HTTP-Block: {d_base}", **{'content': d_base, 'place-before': '0'}, **src_address_param)
                    except: pass

                if target_origen and target_origen != "Todos":
                    # DNS-Trap: Bloqueamos DNS externo (UDP 53) para forzar uso de DNS local y resolución de la lista
                    try: fw.add(chain="forward", action="drop", protocol="udp", dst_port="53", src_address=target_origen, comment="SOC DNS-Trap", **{'place-before': '0'})
                    except: pass
                    try: fw.add(chain="forward", action="drop", dst_address_list="Redes_Bloqueadas", src_address=target_origen, comment=f"SOC Target-Block: {target_clean}", **{'place-before': '0'})
                    except: pass
                else:
                    # Aplicar DNS Trap Global (CUIDADO: bloquea DNS custom de toda la red, asumiendo DNS Relay local)
                    try: fw.add(chain="forward", action="drop", protocol="udp", dst_port="53", comment="SOC GLOBAL DNS-Trap", **{'place-before': '0'})
                    except: pass

                self._flush_connections(target_origen)
                return True, f"✅ Estrategia '{target_clean}' inyectada con Bloqueo SNI/SSL y Flush de conexiones. {prefix_log}."
                
            elif "Puerto" in block_type:
                fw.add(chain="forward", action="drop", protocol="tcp", dst_port=target_clean, comment=f"SOC Port Block TCP: {comment}", **src_address_param, **{'place-before': '0'})
                fw.add(chain="forward", action="drop", protocol="udp", dst_port=target_clean, comment=f"SOC Port Block UDP: {comment}", **src_address_param, **{'place-before': '0'})
                self._flush_connections(target_origen)
                return True, f"✅ Puerto {target_clean} cerrado con prioridad SOC. {prefix_log}."
                
            return False, "Estrategia no reconocida."
        except Exception as e:
            return False, f"Fallo en motor táctico: {str(e)}"

    def _flush_connections(self, ip_target):
        """
        Mata TODAS las conexiones existentes de una IP para efecto INSTANTÁNEO.
        Busca conexiones donde el dispositivo es ORIGEN o DESTINO para evitar fugas.
        Especialmente crítico para flujos QUIC (UDP 443) y Sesiones TCP activas.
        """
        if not self.api or not ip_target:
            return
            
        try:
            ip_clean = ip_target.split(' (')[0].strip()
            conn_res = self.api.get_resource('/ip/firewall/connection')
            
            # Intentamos realizar un filtrado por API para mayor velocidad y eficiencia
            # Esto evita descargar 5000+ conexiones si el router tiene carga.
            try:
                # Buscamos conexiones donde la IP sea origen
                src_conns = conn_res.get(src_address=ip_clean)
                for c in src_conns:
                    try: conn_res.remove(id=c['.id'])
                    except: pass
                
                # Buscamos conexiones donde la IP sea destino (respuesta de servidores)
                dst_conns = conn_res.get(dst_address=ip_clean)
                for c in dst_conns:
                    try: conn_res.remove(id=c['.id'])
                    except: pass
                    
            except Exception:
                # Fallback: Iteración manual si el filtrado por API falla en versiones antiguas
                all_con = conn_res.get()
                for c in all_con:
                    src = c.get('src-address', '').split(':')[0]
                    dst = c.get('dst-address', '').split(':')[0]
                    if src == ip_clean or dst == ip_clean:
                        try: conn_res.remove(id=c['.id'])
                        except: pass
            
            logging.info(f"SOC Flush: Conexiones de {ip_clean} purgadas del Firewall.")
        except Exception as e:
            logging.warning(f"Error en flush táctico: {e}")

    def get_device_live_traffic(self, device_ip):
        """
        Monitor en vivo: muestra TODAS las conexiones activas de un dispositivo específico,
        cruzadas con la caché DNS del MikroTik para resolver dominios.
        Retorna lista de conexiones con: dominio, IP destino, protocolo, puerto, bytes, duración.
        """
        if not self.api or not device_ip:
            return []
        try:
            ip_clean = device_ip.split(' (')[0].strip()
            
            # 1. Cargar caché DNS para resolver IPs → dominios
            dns_map = {}
            try:
                dns_cache = self.api.get_resource('/ip/dns/cache').get()
                for entry in dns_cache:
                    addr = entry.get('address', '')
                    name = entry.get('name', '')
                    if addr and name:
                        dns_map[addr] = name
            except:
                pass
            
            # 2. Obtener conexiones activas del dispositivo
            all_conns = self.api.get_resource('/ip/firewall/connection').get()
            device_traffic = []
            domains_seen = {}  # Agrupar por dominio para consolidar
            
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
                orig_bytes = int(c.get('orig-bytes', 0))
                repl_bytes = int(c.get('repl-bytes', 0))
                total_bytes = orig_bytes + repl_bytes
                timeout = c.get('timeout', '')
                
                # Resolver dominio
                domain = dns_map.get(dst_ip, dst_ip)
                
                # Limpiar dominios CDN para mostrar el servicio real
                domain_display = domain
                service_icon = "🌐"
                if 'googlevideo' in domain or 'youtube' in domain or 'ytimg' in domain:
                    domain_display = f"YouTube ({domain})"
                    service_icon = "🎬"
                elif 'facebook' in domain or 'fbcdn' in domain or 'fb.com' in domain:
                    domain_display = f"Facebook ({domain})"
                    service_icon = "📘"
                elif 'instagram' in domain or 'cdninstagram' in domain:
                    domain_display = f"Instagram ({domain})"
                    service_icon = "📸"
                elif 'tiktok' in domain or 'byteoversea' in domain or 'musical.ly' in domain:
                    domain_display = f"TikTok ({domain})"
                    service_icon = "🎵"
                elif 'netflix' in domain or 'nflx' in domain:
                    domain_display = f"Netflix ({domain})"
                    service_icon = "🎥"
                elif 'whatsapp' in domain:
                    domain_display = f"WhatsApp ({domain})"
                    service_icon = "💬"
                elif 'spotify' in domain or 'scdn' in domain:
                    domain_display = f"Spotify ({domain})"
                    service_icon = "🎧"
                elif 'twitch' in domain or 'ttvnw' in domain:
                    domain_display = f"Twitch ({domain})"
                    service_icon = "🟣"
                elif 'google' in domain or 'gstatic' in domain or 'googleapis' in domain:
                    service_icon = "🔍"
                elif 'microsoft' in domain or 'msn' in domain or 'office' in domain:
                    service_icon = "🪟"
                elif 'amazon' in domain or 'aws' in domain:
                    service_icon = "📦"
                
                # Determinar tipo de servicio por puerto
                port_service = ""
                if dst_port == "443":
                    port_service = "HTTPS"
                elif dst_port == "80":
                    port_service = "HTTP"
                elif dst_port == "53":
                    port_service = "DNS"
                elif dst_port == "8080" or dst_port == "8443":
                    port_service = "HTTP-Alt"
                else:
                    port_service = f"Port {dst_port}" if dst_port else protocol.upper()
                
                # Agrupar por dominio base
                domain_base = domain.split('.')[-2] + '.' + domain.split('.')[-1] if '.' in domain and len(domain.split('.')) >= 2 else domain
                
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
                mb = data['total_bytes'] / 1048576
                result.append({
                    'dominio': data['domain_display'],
                    'dominio_raw': data['domain_raw'],
                    'icono': data['icon'],
                    'ip_destino': data['dst_ip'],
                    'puerto': data['port'],
                    'servicio': data['port_service'],
                    'protocolo': data['protocol'],
                    'consumo_mb': round(mb, 3),
                    'conexiones': data['connections'],
                    'domain_key': domain_key,
                })
            
            return sorted(result, key=lambda x: x['consumo_mb'], reverse=True)
        except Exception as e:
            logging.error(f"Error en monitor de tráfico por dispositivo: {e}")
            return []

    def block_page_for_device(self, device_ip, domain, reason="Bloqueo de Página SOC"):
        """
        Bloquea una página web específica SOLO para un dispositivo concreto.
        Usa Address List + regla Forward con src-address para targeting preciso.
        """
        if not self.api:
            return False, "API desconectada."
        try:
            domain_clean = domain.strip().lower()
            ip_clean = device_ip.split(' (')[0].strip()
            al = self.api.get_resource('/ip/firewall/address-list')
            fw = self.api.get_resource('/ip/firewall/filter')
            
            # Mapa de dominios satélite conocidos
            social_map = {
                "youtube": ["youtube.com", "googlevideo.com", "ytimg.com", "yt.be", "ggpht.com"],
                "facebook": ["facebook.com", "fbcdn.net", "fbsbx.com", "messenger.com", "facebook.net"],
                "tiktok": ["tiktok.com", "tiktokv.com", "byteoversea.com", "ibyteimg.com", "snssdk.com"],
                "instagram": ["instagram.com", "cdninstagram.com", "ig.me"],
                "netflix": ["netflix.com", "nflxext.com", "nflxvideo.net", "nflxso.net"],
                "whatsapp": ["whatsapp.com", "whatsapp.net", "wa.me", "web.whatsapp.com", "d.whatsapp.net", "g.whatsapp.net", "mmg.whatsapp.net", "pps.whatsapp.net", "static.whatsapp.net"],
                "spotify": ["spotify.com", "scdn.co", "spotifycdn.com"],
                "twitch": ["twitch.tv", "ttvnw.net", "jtvnw.net"],
            }
            
            # Expandir dominios si es una red social conocida
            dominios = [domain_clean]
            for k, v in social_map.items():
                if k in domain_clean:
                    dominios = list(set(dominios + v))
                    break
            
            list_name = f"SOC_BLOCK_{ip_clean}"
            comment_tag = f"SOC-PAGE-BLOCK:{ip_clean}:{domain_clean}:{reason[:50]}"
            
            # 1. Agregar dominios a una Address List exclusiva para este dispositivo (Capa 3 / IP)
            for d in dominios:
                try:
                    al.add(list=list_name, address=d, comment=comment_tag)
                except:
                    pass
            
            # 2. Crear regla de bloqueo forward específica para este dispositivo
            try:
                fw.add(
                    chain="forward", action="drop",
                    dst_address_list=list_name,
                    src_address=ip_clean,
                    comment=comment_tag,
                    **{'place-before': '0'}
                )
            except:
                pass
                
            # --- NUEVO: BLOQUEO ESTRICTO DE CAPA 7 (SNI DENTRO DEL NAVEGADOR) ---
            for d in dominios:
                d_base = d.replace('www.', '')
                # 2.1 Bloquear HTTPS SNI (Navegación segura)
                try:
                    fw.add(
                        chain="forward", action="drop", protocol="tcp", dst_port="443",
                        src_address=ip_clean, comment=comment_tag,
                        **{'tls-host': f"*{d_base}*", 'place-before': '0'}
                    )
                except:
                    pass
                
                # 2.2 Bloquear HTTP plano (Payload content)
                try:
                    fw.add(
                        chain="forward", action="drop", protocol="tcp", dst_port="80",
                        src_address=ip_clean, comment=comment_tag,
                        **{'content': d_base, 'place-before': '0'}
                    )
                except:
                    pass
            
            # 3. Bloquear DNS externo para forzar uso del DNS del router
            try:
                existing_dns_trap = fw.get(comment=f"SOC DNS-Trap:{ip_clean}")
                if not existing_dns_trap:
                    fw.add(
                        chain="forward", action="drop",
                        protocol="udp", dst_port="53",
                        src_address=ip_clean,
                        comment=f"SOC DNS-Trap:{ip_clean}",
                        **{'place-before': '0'}
                    )
            except:
                pass
            
            # 4. Flush conexiones para efecto instantáneo
            self._flush_connections(ip_clean)
            
            return True, f"✅ {domain_clean} bloqueado estrictamente (L3 + L7/SNI). {len(dominios)} dominio(s) procesados."
        except Exception as e:
            return False, f"Error bloqueando página estrictamente: {str(e)}"

    def get_connection_flows(self, limit=500):
        """
        Descarga la tabla completa de conexiones (Winbox Connections) con estados,
        timeouts y tasas de consumo para el Monitor Táctico.
        """
        if not self.api: return []
        try:
            # Petición masiva a /ip/firewall/connection
            conns = self.api.get_resource('/ip/firewall/connection').get()
            
            # Formateamos para que coincida con la estructura esperada por la vista
            result = []
            for c in conns:
                result.append({
                    '.id': c.get('.id', ''),
                    'src-address': c.get('src-address', ''),
                    'dst-address': c.get('dst-address', ''),
                    'protocol': c.get('protocol', '-'),
                    'timeout': c.get('timeout', '0s'),
                    'tcp-state': c.get('tcp-state', '-'),
                    'orig-bytes': c.get('orig-bytes', 0),
                    'repl-bytes': c.get('repl-bytes', 0),
                    'orig-rate': c.get('orig-rate', '0bps'),
                    'repl-rate': c.get('repl-rate', '0bps')
                })
            
            # Ordenamos por consumo para que los más activos aparezcan arriba
            return sorted(result, key=lambda x: int(x.get('orig-bytes', 0)) + int(x.get('repl-bytes', 0)), reverse=True)[:limit]
        except Exception as e:
            logging.error(f"Error descargando conexiones: {e}")
            return []

    def get_server_latency(self):
        if not self.api: return []
        try:
            return [{"host": n.get('host', ''), "comment": n.get('comment', ''), "status": n.get('status', 'unknown')} 
                    for n in self.api.get_resource('/tool/netwatch').get()]
        except Exception as e:
            if "!empty" not in str(e): logging.error(f"Error netwatch: {e}")
            return []
            
    def reboot_router(self):
        if not self.api: return False, "API desconectada."
        try:
            self.api.get_resource('/system').call('reboot')
            return True, "Reiniciando..."
        except: return True, "⚡ Orden de reinicio enviada."

    def get_blacklisted_ips(self):
        """Obtiene las IPs y Reglas SOC que están actualmente bloqueadas en el Firewall."""
        if not self.api: return []
        try:
            lista = []
            
            # 1. Obtener Address Lists (Cuarentena y Redes)
            try:
                items = self.api.get_resource('/ip/firewall/address-list').get()
                for i in items:
                    l_name = i.get('list')
                    if l_name in ['Blacklist', 'Redes_Bloqueadas']:
                        prefix = "L3" if l_name == 'Blacklist' else "WEB"
                        lista.append({"id": i['.id'], "target": i['address'], "comment": f"[{prefix}] {i.get('comment', '')}", "type": "address-list", "bytes": "N/A", "packets": "N/A"})
            except: pass
            
            # 2. Obtener Filter Rules (Tácticas SOC) - Enfocado en reglas de filtrado de RED y REDES bloqueadas
            try:
                filters = self.api.get_resource('/ip/firewall/filter').get()
                for f in filters:
                    comment = f.get('comment', '').upper()
                    # Buscamos etiquetas clave inyectadas por el sistema de bloqueo estricto
                    if any(tag in comment for tag in ['SOC', 'TACTICAL', 'TARGET', 'TLS', 'HTTP']):
                        target = f.get('dst-address', f.get('tls-host', f.get('dst-port', 'Filtro Dinámico')))
                        
                        # Atributos específicos de la regla (Capa 7 vs Capa 3)
                        if 'tls-host' in f: target = f"Dominio Web: {f['tls-host']}"
                        elif 'content' in f: target = f"Contenido HTTP: {f['content']}"
                        elif 'dst-address-list' in f: target = f"Lista de Redes: {f['dst-address-list']}"
                        
                        origen = f.get('src-address', f.get('src-mac-address', 'Red Local (Global)'))
                        b = int(f.get('bytes', 0))
                        p = int(f.get('packets', 0))
                        
                        lista.append({
                            "id": f['.id'], 
                            "target": f"{target} (Origen: {origen})", 
                            "comment": f.get('comment', ''), 
                            "type": "filter", 
                            "bytes": b, 
                            "packets": p
                        })
            except Exception as e:
                logging.error(f"Error detectando reglas de red: {e}")
            
            return lista
        except: return []

    def unblock_ip(self, ip_id, rule_type="address-list"):
        """Desbloquea una IP o regla específica eliminándola del Firewall."""
        if not self.api: return False, "API desconectada."
        try:
            if rule_type == "filter":
                self.api.get_resource('/ip/firewall/filter').remove(id=ip_id)
            else:
                self.api.get_resource('/ip/firewall/address-list').remove(id=ip_id)
            return True, "✅ Restricción levantada (Regla eliminada del Firewall)."
        except Exception as e: return False, f"Fallo al eliminar: {str(e)}"

    def unblock_by_ip(self, ip_address):
        """
        Busca y elimina TODAS las reglas (Filter y Address-list) que mencionen una IP específica.
        Ideal para revertir bloqueos de un dispositivo de golpe.
        """
        if not self.api or not ip_address: return False, "Sin conexión o IP."
        try:
            ip_clean = ip_address.split(' (')[0].strip()
            # 1. Limpiar Address Lists
            al = self.api.get_resource('/ip/firewall/address-list')
            for item in al.get(address=ip_clean):
                try: al.remove(id=item['.id'])
                except: pass
            
            # 2. Limpiar Filter Rules que tengan la IP como origen o mención en el comentario
            fw = self.api.get_resource('/ip/firewall/filter')
            for f in fw.get():
                comment = f.get('comment', '')
                src = f.get('src-address', '')
                if ip_clean in src or ip_clean in comment:
                    try: fw.remove(id=f['.id'])
                    except: pass
            
            # 3. Limpiar Address Lists dinámicas de bloqueos de página (SOC_BLOCK_IP)
            list_name = f"SOC_BLOCK_{ip_clean}"
            for item in al.get(list=list_name):
                try: al.remove(id=item['.id'])
                except: pass
                
            return True, f"✅ Todas las reglas de {ip_clean} han sido revertidas."
        except Exception as e:
            return False, f"Error en limpieza masiva: {e}"

    def unblock_all_soc_rules(self):
        """Limpia TODO el Firewall eliminando cualquier regla inyectada por el SOC (etiqueta SOC)."""
        if not self.api: return False, "API desconectada."
        try:
            removed = 0
            # Limpiar Filters
            fw = self.api.get_resource('/ip/firewall/filter')
            for f in fw.get():
                if 'SOC' in f.get('comment', '').upper():
                    try: 
                        fw.remove(id=f['.id'])
                        removed += 1
                    except: pass
            
            # Limpiar Address Lists
            al = self.api.get_resource('/ip/firewall/address-list')
            for item in al.get():
                if 'SOC' in item.get('comment', '').upper() or 'SOC_BLOCK' in item.get('list', ''):
                    try: 
                        al.remove(id=item['.id'])
                        removed += 1
                    except: pass
            
            return True, f"✅ Limpieza total completada: {removed} reglas SOC eliminadas."
        except Exception as e:
            return False, f"Error en limpieza total SOC: {e}"

    # ================================================================
    # BLOQUEO PERSISTENTE POR DISPOSITIVO (MAC + IP)
    # ================================================================

    def block_device(self, ip_address, mac_address=None, hostname="", reason="Bloqueo Administrativo", connection_type="LAN"):
        """
        Bloquea un dispositivo inyectando reglas en el Firewall del MikroTik.
        Estrategia multicapa:
        - Si hay MAC: Bloquea por src-mac-address (persiste incluso si cambia la IP, ideal para WiFi)
        - Siempre bloquea por IP en cadenas forward + input
        - Flush de conexiones existentes para efecto inmediato
        Retorna: (exito: bool, mensaje: str, lista_ids_reglas: list)
        """
        if not self.api: return False, "API desconectada.", []
        try:
            fw = self.api.get_resource('/ip/firewall/filter')
            rule_ids = []
            ip_clean = ip_address.split(' (')[0].strip() if ip_address else ""
            mac_clean = mac_address.strip().upper() if mac_address else ""
            comment_tag = f"SOC-DEVICE-BLOCK:{ip_clean}:{mac_clean}:{reason[:50]}"

            # 1. Bloqueo por MAC (L2) si disponible — Cubre WiFi y cambios de IP
            if mac_clean:
                try:
                    r = fw.add(
                        chain="forward", action="drop",
                        comment=comment_tag,
                        **{'src-mac-address': mac_clean, 'place-before': '0'}
                    )
                    rule_ids.append(r)
                except Exception as e:
                    logging.warning(f"No se pudo bloquear por MAC forward: {e}")
                
                try:
                    r = fw.add(
                        chain="input", action="drop",
                        comment=comment_tag,
                        **{'src-mac-address': mac_clean, 'place-before': '0'}
                    )
                    rule_ids.append(r)
                except Exception as e:
                    logging.warning(f"No se pudo bloquear por MAC input: {e}")

            # 2. Bloqueo por IP (L3) — Forward (internet) + Input (acceso al router)
            if ip_clean:
                try:
                    r = fw.add(
                        chain="forward", action="drop",
                        src_address=ip_clean,
                        comment=comment_tag,
                        **{'place-before': '0'}
                    )
                    rule_ids.append(r)
                except Exception as e:
                    logging.warning(f"No se pudo bloquear IP forward: {e}")
                
                try:
                    r = fw.add(
                        chain="input", action="drop",
                        src_address=ip_clean,
                        comment=comment_tag,
                        **{'place-before': '0'}
                    )
                    rule_ids.append(r)
                except Exception as e:
                    logging.warning(f"No se pudo bloquear IP input: {e}")

            # 3. Flush de conexiones activas para efecto inmediato
            self._flush_connections(ip_clean)

            if rule_ids:
                # Extraer IDs reales del resultado
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
        firewall_rule_ids_csv: String con IDs separados por coma.
        """
        if not self.api: return False, "API desconectada."
        try:
            fw = self.api.get_resource('/ip/firewall/filter')
            ids = [rid.strip() for rid in firewall_rule_ids_csv.split(',') if rid.strip()]
            eliminados = 0
            for rid in ids:
                try:
                    fw.remove(id=rid)
                    eliminados += 1
                except Exception:
                    # La regla puede haber sido eliminada manualmente
                    pass
            return True, f"✅ {eliminados} regla(s) eliminada(s) del Firewall."
        except Exception as e:
            return False, f"Error al desbloquear: {str(e)}"

    def get_device_blocks_from_firewall(self):
        """Lee las reglas de bloqueo por dispositivo directamente del Firewall del router."""
        if not self.api: return []
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
        except:
            return []

    def get_active_devices_enriched(self, datos):
        """
        Construye una lista unificada de TODOS los dispositivos conectados
        (LAN via DHCP + WiFi via Registration Table + VPN) con deduplicación por MAC.
        """
        devices = {}
        
        # 1. Dispositivos LAN (DHCP Leases)
        for lease in datos.get('dhcp', []):
            mac = (lease.get('mac-address') or '').upper()
            ip = lease.get('address', '')
            hostname = lease.get('host-name', '')
            server = lease.get('server', '')
            status = lease.get('status', '')
            key = mac or ip
            if key:
                devices[key] = {
                    'ip': ip, 'mac': mac, 'hostname': hostname,
                    'connection_type': 'LAN (DHCP)',
                    'network': server,
                    'status': '🟢 Conectado' if status == 'bound' else '🔴 Offline',
                    'signal': '-',
                    'extra': f"Red: {server}"
                }
        
        # 2. Dispositivos WiFi (Registration Table)
        for client in datos.get('wifi_neighbors', []):
            mac = (client.get('mac') or '').upper()
            signal = client.get('signal', 'N/A')
            interface = client.get('interface', '')
            ip_from_hostname = client.get('hostname', '')
            key = mac
            if key:
                if key in devices:
                    # Enriquecer: ya está en DHCP, agregar datos WiFi
                    devices[key]['connection_type'] = 'WiFi + LAN'
                    devices[key]['signal'] = signal
                    devices[key]['extra'] = f"Interface: {interface} | Señal: {signal}"
                else:
                    # Buscar IP en ARP por MAC
                    ip_found = ''
                    for arp_ip, arp_mac in datos.get('arp_table', {}).items():
                        if arp_mac.upper() == mac:
                            ip_found = arp_ip
                            break
                    devices[key] = {
                        'ip': ip_found or ip_from_hostname, 'mac': mac, 
                        'hostname': ip_from_hostname or 'WiFi Client',
                        'connection_type': 'WiFi',
                        'network': interface,
                        'status': '🟢 Conectado',
                        'signal': signal,
                        'extra': f"Interface: {interface} | Señal: {signal}"
                    }
        
        # 3. Verificación de Estado Real (Ping MikroTik)
        # Hacemos pings rápidos solo a los dispositivos detectados para verificar si están REALMENTE en línea
        try:
            p_res = self.api.get_resource('/tool')
            for d in devices.values():
                ip = d.get('ip')
                if ip and '.' in ip:
                    try:
                        # Lanzamos 1 solo ping rápido rtt < 1s
                        ping = p_res.call('ping', {'address': ip, 'count': '1'})
                        if ping and int(ping[0].get('received', 0)) > 0:
                            d['status'] = '🟢 EN LÍNEA (Ping OK)'
                            d['latency'] = f"{ping[0].get('avg-rtt', '0')}ms"
                        else:
                            # Si no responde ping, pero está en DHCP/WiFi, puede estar en suspensión o bloqueando ICMP
                            d['status'] = '🟠 STANDBY / SILENCIOSO'
                            d['latency'] = '-'
                    except:
                        d['latency'] = '-'
        except: pass

        # 4. Convertir a lista y ordenar
        result = sorted(devices.values(), key=lambda x: x.get('ip', ''))
        return result