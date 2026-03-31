import streamlit as st
import pandas as pd
from datetime import datetime
import time

from core.network_scanner import detect_arp_anomalies, detect_rogue_dhcp, is_scapy_ready


# ================================================================
# FUNCIONES DE PERSISTENCIA (SQLite)
# ================================================================

def _save_block_to_db(router_id, ip, mac, hostname, connection_type, block_type, target, reason, blocked_by, rule_ids):
    """Guarda un registro de bloqueo en SQLite para persistencia."""
    try:
        from database.db_models import SessionLocal, BlockedDevice
        db = SessionLocal()
        block = BlockedDevice(
            router_id=router_id,
            ip_address=ip,
            mac_address=mac,
            hostname=hostname,
            connection_type=connection_type,
            block_type=block_type,
            block_target=target,
            reason=reason,
            blocked_by=blocked_by,
            firewall_rule_ids=",".join([str(r) for r in rule_ids]) if rule_ids else "",
            is_active=True,
        )
        db.add(block)
        db.commit()
        db.close()
        return True
    except Exception as e:
        import logging
        logging.error(f"Error guardando bloqueo en DB: {e}")
        return False


def _get_blocked_devices_from_db(router_id):
    """Lee todos los dispositivos bloqueados de SQLite."""
    try:
        from database.db_models import SessionLocal, BlockedDevice
        db = SessionLocal()
        blocks = db.query(BlockedDevice).filter(
            BlockedDevice.router_id == router_id,
            BlockedDevice.is_active == True
        ).order_by(BlockedDevice.created_at.desc()).all()
        result = []
        for b in blocks:
            result.append({
                'id': b.id,
                'ip': b.ip_address or '',
                'mac': b.mac_address or '',
                'hostname': b.hostname or '',
                'connection_type': b.connection_type or '',
                'block_type': b.block_type or 'device',
                'block_target': b.block_target or '',
                'reason': b.reason or '',
                'blocked_by': b.blocked_by or '',
                'firewall_rule_ids': b.firewall_rule_ids or '',
                'created_at': b.created_at.strftime('%Y-%m-%d %H:%M:%S') if b.created_at else '',
            })
        db.close()
        return result
    except Exception as e:
        import logging
        logging.error(f"Error leyendo bloqueos de DB: {e}")
        return []


def _deactivate_block_in_db(block_id):
    """Marca un bloqueo como inactivo en SQLite."""
    try:
        from database.db_models import SessionLocal, BlockedDevice
        db = SessionLocal()
        block = db.query(BlockedDevice).filter(BlockedDevice.id == block_id).first()
        if block:
            block.is_active = False
            db.commit()
        db.close()
        return True
    except Exception as e:
        import logging
        logging.error(f"Error desactivando bloqueo: {e}")
        return False


def _save_soc_log(router_id, action, status="INFO", user="admin", details=None):
    """Guarda un log de acción SOC persistente en SQLite."""
    try:
        from database.db_models import SessionLocal, SOCActionLog
        db = SessionLocal()
        log = SOCActionLog(
            router_id=router_id,
            action=action,
            status=status,
            user=user,
            details=details,
        )
        db.add(log)
        db.commit()
        db.close()
    except Exception as e:
        import logging
        logging.error(f"Error guardando SOC log: {e}")


def _get_soc_logs(router_id, limit=100):
    """Lee los últimos logs SOC persistentes de SQLite."""
    try:
        from database.db_models import SessionLocal, SOCActionLog
        db = SessionLocal()
        logs = db.query(SOCActionLog).filter(
            SOCActionLog.router_id == router_id
        ).order_by(SOCActionLog.created_at.desc()).limit(limit).all()
        result = []
        for l in logs:
            ts = l.created_at.strftime('%Y-%m-%d %H:%M:%S') if l.created_at else ''
            result.append(f"[{ts}] [{l.status}] {l.action}")
        db.close()
        return result
    except Exception as e:
        import logging
        logging.error(f"Error leyendo SOC logs: {e}")
        return []


# ================================================================
# VISTA PRINCIPAL
# ================================================================

def render_tactical_console(router_db, datos):
    # Inicializar session state para logs de sesión (complemento a DB)
    if 'soc_logs' not in st.session_state:
        st.session_state['soc_logs'] = []

    def add_log(action, status="INFO"):
        """Log dual: sesión + persistente en DB."""
        ts = datetime.now().strftime('%H:%M:%S')
        st.session_state['soc_logs'].insert(0, f"[{ts}] [{status}] {action}")
        _save_soc_log(router_db.id, action, status, st.session_state.get('username', 'admin'))

    st.title(f"🛡️ Centro Táctico — {router_db.name}")
    st.markdown("Gestión unificada de Red Local, VPN, Firewall y Recuperación ante Desastres.")

    # ==========================================
    # TABS DE NAVEGACIÓN INTERNA
    # ==========================================
    tab_lan, tab_vpn, tab_firewall, tab_devices, tab_backup = st.tabs([
        "🔌 Dispositivos LAN",
        "🌍 Gestión VPN",
        "🛡️ Firewall - Seguridad de la Red",
        "🚫 Control de Acceso (Bloqueos)",
        "🚑 Backups & Recovery"
    ])

    # ------------------------------------------
    # 1. MÓDULO LAN (DHCP)
    # ------------------------------------------
    with tab_lan:
        leases = datos.get('dhcp', [])
        
        # Métricas superiores
        total_leases = len(leases)
        activos = len([l for l in leases if l.get('status') == 'bound'])
        wifi_clients = len(datos.get('wifi_neighbors', []))
        
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("📡 Total Dispositivos", total_leases)
        c2.metric("✅ Conectados (Bound)", activos)
        c3.metric("📶 Clientes WiFi", wifi_clients)
        c4.metric("🔌 Servidores DHCP", len(set(l.get('server', '') for l in leases)) if leases else 0)
        
        st.markdown("---")
        st.markdown("### 💻 Auditoría de Equipos Locales")
        
        if leases:
            columnas_disponibles = ['address', 'mac-address', 'host-name', 'server', 'status', 'last-seen']
            columnas_presentes = [c for c in columnas_disponibles if any(c in l for l in leases)]
            
            df_leases = pd.DataFrame(leases)
            if columnas_presentes:
                df_leases = df_leases[[c for c in columnas_presentes if c in df_leases.columns]].fillna('N/A')
                renombrar = {
                    'address': '🖥️ IP', 'mac-address': '🔗 MAC', 'host-name': '📛 Hostname',
                    'server': '📡 Red', 'status': '📊 Estado', 'last-seen': '🕐 Última Vez'
                }
                df_leases.rename(columns={k: v for k, v in renombrar.items() if k in df_leases.columns}, inplace=True)
                st.dataframe(df_leases, hide_index=True, use_container_width=True)
        else:
            st.info("No se encontraron dispositivos conectados por DHCP.")

        # WiFi Registration Table
        if datos.get('wifi_neighbors'):
            st.markdown("---")
            st.markdown("### 📶 Clientes WiFi Conectados (Registration Table)")
            df_wifi = pd.DataFrame(datos['wifi_neighbors'])
            cols_wifi = ['mac', 'interface', 'signal', 'tx_rate', 'rx_rate', 'uptime', 'hostname']
            cols_presentes = [c for c in cols_wifi if c in df_wifi.columns]
            if cols_presentes:
                df_wifi_show = df_wifi[cols_presentes].copy()
                rename_wifi = {
                    'mac': '🔗 MAC', 'interface': '📡 Interface', 'signal': '📶 Señal',
                    'tx_rate': '⬆️ TX Rate', 'rx_rate': '⬇️ RX Rate',
                    'uptime': '⏱️ Conectado', 'hostname': '🖥️ IP/Host'
                }
                df_wifi_show.rename(columns={k: v for k, v in rename_wifi.items() if k in df_wifi_show.columns}, inplace=True)
                st.dataframe(df_wifi_show, hide_index=True, use_container_width=True)

    # ------------------------------------------
    # 2. MÓDULO VPN
    # ------------------------------------------
    with tab_vpn:
        vpns_activas = datos.get('vpns', [])

        c1, c2 = st.columns(2)
        c1.metric("🌍 Conexiones Activas", len(vpns_activas))
        protocolos = list(set(v.get('service', 'N/A') for v in vpns_activas)) if vpns_activas else []
        c2.metric("🔐 Protocolos en Uso", ", ".join(protocolos) if protocolos else "Ninguno")

        st.markdown("---")
        st.markdown("### 🌍 Usuarios Remotos y Sucursales")

        if vpns_activas:
            st.success(f"Hay **{len(vpns_activas)}** conexiones VPN activas en este momento.")
            
            columnas_vpn = ['name', 'service', 'caller-id', 'address', 'uptime']
            df_vpns = pd.DataFrame(vpns_activas)
            cols_presentes = [c for c in columnas_vpn if c in df_vpns.columns]
            df_vpns = df_vpns[cols_presentes]
            
            renombrar_vpn = {
                'name': '👤 Usuario/Sucursal', 'service': '🔐 Protocolo',
                'caller-id': '🌐 IP Pública', 'address': '🏠 IP Local', 'uptime': '⏱️ Conectado'
            }
            df_vpns.rename(columns={k: v for k, v in renombrar_vpn.items() if k in df_vpns.columns}, inplace=True)
            st.dataframe(df_vpns, hide_index=True, use_container_width=True)

            st.markdown("---")
            with st.expander("🚨 Forzar Desconexión de Usuario", expanded=False):
                col1, col2 = st.columns([3, 1])
                with col1:
                    nombres_vpn = [v['name'] for v in vpns_activas if 'name' in v]
                    user_kick = st.selectbox(
                        "Seleccionar túnel a cerrar:", 
                        ["-- Seleccionar --"] + nombres_vpn,
                        label_visibility="collapsed"
                    )
                with col2:
                    if st.button("⚡ Cortar Conexión", type="primary", use_container_width=True):
                        if user_kick != "-- Seleccionar --":
                            from core.router_api import RouterManager
                            router = RouterManager(router_db.ip_address, router_db.api_user, router_db.api_pass_encrypted)
                            if router.connect()[0]:
                                exito, msj = router.kick_vpn_user(user_kick)
                                router.disconnect()
                                if exito:
                                    st.success(msj)
                                    add_log(f"VPN Desconectada: {user_kick}", "SUCCESS")
                                    st.session_state['telemetria'] = None
                                    st.rerun()
                                else:
                                    st.error(msj)
                        else:
                            st.warning("⚠️ Selecciona un usuario u oficina de la lista para desconectar.")
        else:
            st.info("No hay usuarios VPN conectados actualmente.")

    # ------------------------------------------
    # 3. MÓDULO FIREWALL (Motor táctico existente)
    # ------------------------------------------
    with tab_firewall:
        blacklist = datos.get('blacklist', [])
        conn_activas = datos.get('sec', {}).get('conexiones_activas', 0)
        
        c1, c2, c3 = st.columns(3)
        c1.metric("🔥 Conexiones Firewall", f"{conn_activas:,}")
        c2.metric("⛔ Reglas Blacklist", len(blacklist))
        c3.metric("📊 Saturación", f"{(conn_activas / 300000) * 100:.1f}%")
        
        st.markdown("---")
        
        # --- MONITOR DE CONEXIONES ACTIVAS (WINBOX STYLE) ---
        st.markdown("### 🕸️ Monitor de Conexiones Activas (Live Tracking)")
        st.caption("Visualiza en tiempo real los flujos de tráfico, estados TCP/UDP y timeouts. Cruza esta tabla con las reglas para verificar el bloqueo.")

        # Filtro rápido por IP si hay un dispositivo seleccionado en el tab de dispositivos o manual
        filtro_ip = st.text_input("🔍 Filtrar conexiones por IP Origen/Destino:", placeholder="Ej: 192.168.50.22", key="conn_filter_ip")

        if 'flujos_sankey' in datos:
            raw_conns = datos.get('flujos_sankey', [])
            if raw_conns:
                # Filtrar si hay búsqueda
                if filtro_ip:
                    raw_conns = [c for c in raw_conns if filtro_ip in c.get('src-address', '') or filtro_ip in c.get('dst-address', '')]

                # Preparar datos para tabla amigable
                conns_display = []
                for c in raw_conns:
                    orig_bytes = int(c.get('orig-bytes', 0))
                    repl_bytes = int(c.get('repl-bytes', 0))
                    rate_orig = c.get('orig-rate', '0bps')
                    rate_repl = c.get('repl-rate', '0bps')
                    
                    # Determinar estado visual (emulando Winbox)
                    tcp_state = c.get('tcp-state', '-')
                    proto = c.get('protocol', 'unknown')
                    
                    status_emoji = "🟢" # Established
                    if tcp_state == 'time-wait': status_emoji = "⏳"
                    elif tcp_state == 'close': status_emoji = "🔴"
                    elif proto == 'udp': status_emoji = "🔵"
                    
                    conns_display.append({
                        "Estado": f"{status_emoji} {tcp_state.upper() if tcp_state != '-' else proto.upper()}",
                        "Origen": c.get('src-address', ''),
                        "Destino": c.get('dst-address', ''),
                        "Timeout": c.get('timeout', ''),
                        "Velocidad (O/R)": f"{rate_orig} / {rate_repl}",
                        "Tráfico": f"{round((orig_bytes + repl_bytes)/1024, 1)} KB"
                    })
                
        if 'flujos_sankey' in datos:
            raw_conns = datos.get('flujos_sankey', [])
            if raw_conns:
                # ... tabla de conexiones existente ...
                df_conns = pd.DataFrame(conns_display)
                st.dataframe(df_conns, hide_index=True, use_container_width=True, height=350)
                
                # --- NUEVA ACCIÓN RÁPIDA DESDE EL MONITOR ---
                with st.expander("⚡ Acción Rápida: Cortar Internet a una IP en vivo"):
                    # Extraer IPs únicas de origen de la tabla live
                    all_srcs = sorted(list(set([c.get('src-address', '').split(':')[0] for c in raw_conns if 'src-address' in c])))
                    col_sq, col_bq = st.columns([3, 1])
                    with col_sq:
                        ip_to_kill = st.selectbox("Selecciona IP de origen detectada:", ["-- Seleccionar --"] + all_srcs, key="quick_kill_ip")
                    with col_bq:
                        if st.button("⛔ KILL SWITCH", type="primary", use_container_width=True):
                            if ip_to_kill != "-- Seleccionar --":
                                from core.router_api import RouterManager
                                router = RouterManager(router_db.ip_address, router_db.api_user, router_db.api_pass_encrypted)
                                if router.connect()[0]:
                                    with st.spinner(f"Neutralizando {ip_to_kill}..."):
                                        exito, msj = router.block_device(ip_to_kill, "BLOQUEO TOTAL", "Corte rápido desde monitor")
                                        if exito: 
                                            st.success(f"✅ Host {ip_to_kill} bloqueado exitosamente.")
                                            time.sleep(1)
                                            st.rerun()
                                        else: 
                                            st.error(msj)
                                    router.disconnect()
            else:
                st.info("No hay conexiones activas detectadas en este instante.")

        st.markdown("---")
        # Bloqueo Avanzado (motor táctico existente)
        st.markdown("### ⛔ Motor de Contención y Defensa AIOps")
        st.caption("Inyecta bloqueos multicapa para neutralizar amenazas inmediatamente.")

        vendor = getattr(router_db, 'vendor', 'MikroTik').upper()
        
        c_tipo, c_alcance = st.columns(2)
        with c_tipo:
            block_type = st.selectbox("🎯 ¿Qué deseas bloquear? (Categoría Destino)", 
                                     ["Corte Total de Internet (Kill Switch)", 
                                      "Página Web / Red Social (Address List)", 
                                      "IP / Subred (Drop Específico)", 
                                      "Puerto (Ej: 22, 3389, 445)"])
        with c_alcance:
            scope_type = st.selectbox("👤 ¿A quién afecta el bloqueo? (Rango de Origen)", ["Toda la red (Bloqueo Global)", "A una IP Específica (Solo un equipo)", "A un Grupo (Una Subred entera)"])

        sub_red_social = None
        if "Corte Total" in block_type:
            target_bloqueo = "0.0.0.0/0"
            st.info("⚠️ El Kill Switch bloqueará TODO el tráfico saliente del dispositivo u origen seleccionado.")
        elif "Página Web" in block_type:
            sub_cola, sub_input = st.columns([1.5, 2])
            with sub_cola:
                sub_red_social = st.selectbox("Selecciona Pack Social:", ["Manual (Escribir dominio)", "WhatsApp", "YouTube", "Facebook", "TikTok", "Instagram", "Netflix"])
            with sub_input:
                if sub_red_social == "Manual (Escribir dominio)":
                    target_bloqueo = st.text_input("Ingresa el dominio principal:", placeholder="Ej: zoom.us")
                else:
                    target_bloqueo = sub_red_social.lower() + ".com"
                    st.text_input("Objetivo Detectado:", value=f"Pack {sub_red_social} (Dominio Base: {target_bloqueo})", disabled=True)
        else:
            placeholder = "IP Destino (Ej: 192.168.1.10)" if "IP / Subred" in block_type else "Puerto (Ej: 80, 443)"
            target_bloqueo = st.text_input("Ingresa el Destino:", placeholder=placeholder)

        col_origen, col_comentario, col_btn = st.columns([1.5, 1, 1])
        with col_origen:
            if "Toda la red" in scope_type:
                target_origen = "Todos"
                st.text_input("Paso 2: Ingresa el Origen", value="Afecta a todo el mundo", disabled=True)
            elif "IP Específica" in scope_type:
                ips_activas = set()
                for arp in datos.get('arp_table', []):
                    if isinstance(arp, dict) and arp.get('address'): 
                        ips_activas.add(arp['address'] + " (ARP)")
                for vpn in datos.get('vpns', []):
                    if isinstance(vpn, dict) and vpn.get('address'): 
                        ips_activas.add(vpn['address'] + " (VPN)")
                for dhcp in datos.get('dhcp', []):
                    if isinstance(dhcp, dict) and dhcp.get('status') == 'bound' and dhcp.get('address'): 
                        ips_activas.add(dhcp['address'] + f" (DHCP {dhcp.get('host-name', '')})")
                
                opciones = ["-- Seleccionar (Verificadas) --"] + sorted(list(ips_activas)) + ["Escribir IP Manualmente..."]
                seleccion = st.selectbox("Paso 2: Selecciona la IP Origen", opciones)
                
                if seleccion == "Escribir IP Manualmente...":
                    target_origen = st.text_input("Ingresa la IP Manual:", placeholder="Ej: 192.168.10.55")
                else:
                    target_origen = "" if seleccion == "-- Seleccionar (Verificadas) --" else seleccion.split(" (")[0]
            else:
                redes = set()
                for net in datos.get('local_networks', []):
                    if isinstance(net, dict) and net.get('network'): 
                        redes.add(net['network'] + " (Rango Completo LAN)")
                
                opciones = ["-- Seleccionar Rango CIDR --"] + sorted(list(redes)) + ["Especificar CIDR Manual..."]
                seleccion = st.selectbox("Paso 2: Selecciona la Subred (Afecta a todo el bloque DHCP)", opciones)
                
                if seleccion == "Especificar CIDR Manual...":
                    target_origen = st.text_input("Ingresa Segmento CIDR:", placeholder="Ej: 172.16.0.0/20 (Afecta a todos)")
                else:
                    target_origen = "" if seleccion == "-- Seleccionar Rango CIDR --" else seleccion.split(" (")[0]
        with col_comentario:
            comentario = st.text_input("Razón (Opcional)", placeholder="Ej: Ataque SOC")
        with col_btn:
            st.markdown("<br>", unsafe_allow_html=True)
            btn_ping, btn_block = st.columns(2)
            
            with btn_ping:
                if st.button("📡 Ping", help="Verificar si la víctima está en línea", use_container_width=True):
                    if target_origen and target_origen != "Todos":
                        from core.network_scanner import scan_network_scapy
                        ip_raw = target_origen.split(' (')[0].strip()
                        if scan_network_scapy(ip_raw):
                            st.toast(f"✅ Host {ip_raw} responde.")
                        else:
                            st.toast(f"❌ Host {ip_raw} NO responde.")
                    else:
                        st.warning("Selecciona una IP/Origen.")

            with btn_block:
                if st.button("🔨 Bloquear", type="primary", use_container_width=True):
                    if target_bloqueo and target_origen:
                        from core.router_api import RouterManager
                        router = RouterManager(router_db.ip_address, router_db.api_user, router_db.api_pass_encrypted)
                        if router.connect()[0]:
                            with st.spinner(f"Inyectando Escudo SOC en {vendor}..."):
                                exito, msj = router.create_advanced_block(block_type, target_bloqueo, comentario or "Bloqueo SOC", target_origen)
                                if exito:
                                    st.success(msj)
                                    add_log(f"Intervención: {block_type} -> {target_bloqueo} ({target_origen})", "SUCCESS")
                                    # Persistir en DB
                                    _save_block_to_db(
                                        router_id=router_db.id,
                                        ip=target_origen if target_origen != "Todos" else "",
                                        mac="",
                                        hostname="",
                                        connection_type="Firewall",
                                        block_type=block_type[:50],
                                        target=target_bloqueo,
                                        reason=comentario or "Bloqueo SOC",
                                        blocked_by=st.session_state.get('username', 'admin'),
                                        rule_ids=[]
                                    )
                                    st.session_state['telemetria'] = None
                                    st.rerun()
                                else:
                                    st.error(msj)
                                    add_log(f"Fallo en Intervención: {msj}", "ERROR")
                            router.disconnect()
                    else:
                        if not target_bloqueo:
                            st.error("⚠️ Debes ingresar un objetivo (IP, Dominio o Puerto).")
                        if not target_origen:
                            st.error("⚠️ Debes seleccionar o ingresar un origen (IP o red).")

        # Gestión de Restricciones Activas (Cuarentena)
            # --- NUEVAS OPCIONES DE LIMPIEZA MASIVA ---
            st.markdown("#### 🧹 Acciones Masivas")
            c_mass1, c_mass2 = st.columns(2)
            
            with c_mass1:
                # Extraer IPs únicas con reglas activas
                ips_activas = sorted(list(set([b['target'].split('(')[-1].replace('Origen: ', '').replace(')', '').strip() 
                                             for b in blacklist if 'Origen:' in b['target']])))
                col_sel_mass, col_btn_mass = st.columns([2,1])
                ip_clean_mass = col_sel_mass.selectbox("Limpiar Host:", ["-- Seleccionar --"] + ips_activas, label_visibility="collapsed")
                if col_btn_mass.button("🚿 Limpiar Host", use_container_width=True):
                    if ip_clean_mass != "-- Seleccionar --":
                         from core.router_api import RouterManager
                         router = RouterManager(router_db.ip_address, router_db.api_user, router_db.api_pass_encrypted)
                         if router.connect()[0]:
                             with st.spinner(f"Revirtiendo todo para {ip_clean_mass}..."):
                                 exito, msj = router.unblock_by_ip(ip_clean_mass)
                                 if exito: st.success(msj); st.session_state['telemetria'] = None; st.rerun()
                                 else: st.error(msj)
                             router.disconnect()

            with c_mass2:
                 if st.button("🧨 LIMPIEZA TOTAL SOC", type="primary", use_container_width=True, 
                              help="Elimina TODAS las reglas y listas SOC inyectadas en este Router"):
                      from core.router_api import RouterManager
                      router = RouterManager(router_db.ip_address, router_db.api_user, router_db.api_pass_encrypted)
                      if router.connect()[0]:
                          with st.spinner("Purgando Firewall..."):
                              exito, msj = router.unblock_all_soc_rules()
                              if exito: st.success(msj); st.session_state['telemetria'] = None; st.rerun()
                              else: st.error(msj)
                          router.disconnect()
            
            st.markdown("---")
            # --- GESTIÓN INDIVIDUAL ---
            st.markdown("#### 🧩 Gestión Individual de Reglas")
            col_bl, col_btn_bl = st.columns([3, 1])
            with col_bl:
                opciones_bl = {f"{b['target']} — {b['comment']}": (b['id'], b.get('type', 'address-list')) for b in blacklist}
                item_liberar = st.selectbox(
                    "Seleccionar Bloqueo a Levantar / Deshacer:",
                    ["-- Seleccionar --"] + list(opciones_bl.keys()),
                    label_visibility="collapsed", key="bl_individual_select"
                )
            with col_btn_bl:
                if st.button("✅ Levantar Bloqueo", use_container_width=True, key="btn_bl_indiv"):
                    if item_liberar != "-- Seleccionar --":
                        from core.router_api import RouterManager
                        target_id, tipo_regla = opciones_bl[item_liberar]
                        router = RouterManager(router_db.ip_address, router_db.api_user, router_db.api_pass_encrypted)
                        if router.connect()[0]:
                            with st.spinner("Removiendo regla del Firewall..."):
                                exito, msj = router.unblock_ip(target_id, rule_type=tipo_regla)
                                if exito:
                                    st.success(msj)
                                    add_log(f"Restricción Levantada: {item_liberar} ({tipo_regla})", "SUCCESS")
                                    st.session_state['telemetria'] = None
                                    st.rerun()
                                else:
                                    st.error(msj)
                                    add_log(f"Fallo al levantar restricción: {msj}", "ERROR")
                            router.disconnect()
                    else:
                        st.warning("⚠️ Selecciona una regla o restricción de la lista.")
        
        # --- MONITOR DE EFECTIVIDAD EN TIEMPO REAL ---
        st.markdown("---")
        st.markdown("### 📈 Efectividad del Bloqueo en Tiempo Real")
        st.caption("Tráfico y peticiones denegadas instantáneamente por las reglas inyectadas desde este panel.")
        blacklist_data = datos.get('blacklist', [])
        stats = []
        for b in blacklist_data:
            if b.get('type') == 'filter' and isinstance(b.get('bytes'), (int, float)):
                mb_bloqueados = b['bytes'] / 1048576
                stats.append({
                    'Objetivo': b['target'],
                    'Razón / Comentario': b['comment'],
                    'Paquetes Bloqueados': b['packets'],
                    'Tráfico Interceptado (MB)': round(mb_bloqueados, 3)
                })
        if stats:
            df_stats = pd.DataFrame(stats).sort_values(by='Tráfico Interceptado (MB)', ascending=False)
            
            import plotly.express as px
            fig = px.bar(
                df_stats.head(10),
                x='Tráfico Interceptado (MB)',
                y='Objetivo',
                orientation='h',
                title='Top Reglas por Volumen de Bloqueo',
                color='Tráfico Interceptado (MB)',
                color_continuous_scale='Reds',
                text_auto=True
            )
            fig.update_layout(
                template='plotly_dark', 
                margin=dict(l=10, r=10, t=40, b=10),
                yaxis={'categoryorder':'total ascending'}
            )
            
            st.plotly_chart(fig, use_container_width=True)
            st.dataframe(df_stats, hide_index=True, use_container_width=True)
        else:
            st.info("⏱️ Aún no hay registros de navegación interceptada o el dashboard está sincronizando...")

        # Auditoria de Capa 2
        st.markdown("---")
        st.markdown("### 🔍 Auditoría de Capa 2 (Detección Scapy)")
        col_s1, col_s2 = st.columns(2)
        
        with col_s1:
            with st.container(border=True):
                st.markdown("#### Monitor Anti-ARP Spoofing")
                current_arp = datos.get('arp_table', {})
                prev_arp = st.session_state.get('prev_arp_table', {})
                
                if prev_arp:
                    anomalies = detect_arp_anomalies(prev_arp, current_arp)
                    if anomalies:
                        criticals = [a for a in anomalies if a['severidad'] == 'CRÍTICO']
                        if criticals: st.error(f"🔴 {len(criticals)} ALERTA(S) CRÍTICA(S) de suplantación MAC detectada.")
                        st.dataframe(pd.DataFrame(anomalies), hide_index=True, use_container_width=True)
                    else:
                        st.success("✅ Sin anomalías ARP desde la última sincronización.")
                else:
                    st.info("📋 Se necesita una sincronización adicional para comparar la tabla ARP.")
                st.session_state['prev_arp_table'] = current_arp.copy()

        with col_s2:
            with st.container(border=True):
                st.markdown("#### Detector de DHCP Rogue")
                st.caption("Verifica Falsos Servidores lanzando paquetes simulados L2.")
                if is_scapy_ready():
                    if st.button("🔍 Escanear Red L2", type="primary", use_container_width=True):
                        with st.spinner("Inyectando paquete broadcast DHCP Discover..."):
                            result = detect_rogue_dhcp(timeout=8)
                        if result.get('alert'):
                            st.error(result['status'])
                            add_log(f"Alerta Rogue DHCP: {result['status']}", "CRITICAL")
                        else:
                            st.success(result['status'])
                            add_log("Escaneo DHCP Rogue ejecutado sin detección de anomalías.", "SUCCESS")
                        if result.get('servers'):
                            st.dataframe(pd.DataFrame(result['servers']), hide_index=True, use_container_width=True)
                else:
                    st.warning("⚠️ Módulo Scapy local no detectado. Instale Npcap.")

    # ------------------------------------------
    # 4. CONTROL DE ACCESO (BLOQUEO POR DISPOSITIVO) — PERSISTENTE
    # ------------------------------------------
    with tab_devices:
        st.markdown("### 🚫 Administración de Acceso a la Red")
        st.caption("Bloquea dispositivos individuales tanto por **Red LAN** como **WiFi**. Los bloqueos se guardan permanentemente y sobreviven recargas de página.")
        
        # ----- MÉTRICAS -----
        blocked_db = _get_blocked_devices_from_db(router_db.id)
        
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("📡 LAN Activos", len(datos.get('dhcp', [])))
        c2.metric("📶 WiFi Activos", len(datos.get('wifi_neighbors', [])))
        c3.metric("🚫 Bloqueados", len(blocked_db))
        c4.metric("🌍 VPN Activos", len(datos.get('vpns', [])))
        
        st.markdown("---")

        # ----- SECCIÓN 1: DISPOSITIVOS CONECTADOS -----
        st.markdown("### 📋 Dispositivos Conectados en la Red")
        st.caption("Lista unificada de todos los dispositivos detectados por DHCP, WiFi y ARP.")
        
        from core.router_api import RouterManager
        router_temp = RouterManager(router_db.ip_address, router_db.api_user, router_db.api_pass_encrypted)
        all_devices = router_temp.get_active_devices_enriched(datos)
        
        # Marcar dispositivos que ya están bloqueados
        blocked_ips = {b['ip'] for b in blocked_db if b['ip']}
        blocked_macs = {b['mac'].upper() for b in blocked_db if b['mac']}
        
        for dev in all_devices:
            if dev['ip'] in blocked_ips or dev['mac'] in blocked_macs:
                dev['estado_bloqueo'] = '🔴 BLOQUEADO'
            else:
                dev['estado_bloqueo'] = '🟢 Permitido'
        
        if all_devices:
            df_devices = pd.DataFrame(all_devices)
            cols_show = ['ip', 'mac', 'hostname', 'connection_type', 'status', 'latency', 'signal', 'estado_bloqueo']
            cols_available = [c for c in cols_show if c in df_devices.columns]
            df_show = df_devices[cols_available].copy()
            rename_map = {
                'ip': '🖥️ IP', 'mac': '🔗 MAC', 'hostname': '📛 Hostname',
                'connection_type': '📡 Tipo Conexión', 'status': '📊 Estado Real', 
                'latency': '⏱️ Latencia (ms)', 'signal': '📶 Señal', 'estado_bloqueo': '🔒 Acceso'
            }
            df_show.rename(columns={k: v for k, v in rename_map.items() if k in df_show.columns}, inplace=True)
            st.dataframe(df_show, hide_index=True, use_container_width=True, height=300)
        else:
            st.info("No se detectaron dispositivos en la red.")
        
        # ----- SECCIÓN 2: BLOQUEAR DISPOSITIVO -----
        st.markdown("---")
        st.markdown("### 🔨 Restringir Acceso a Dispositivo")
        
        with st.container(border=True):
            col_sel, col_tipo, col_reason = st.columns([2, 1, 1])
            
            with col_sel:
                # Construir opciones de dispositivos no bloqueados o parcialmente bloqueados
                device_options = []
                for dev in all_devices:
                    label = f"{dev['ip']} | {dev['mac']} | {dev['hostname']} ({dev['connection_type']})"
                    device_options.append(label)
                
                if device_options:
                    selected_device = st.selectbox(
                        "Selecciona el dispositivo a restringir:",
                        ["-- Seleccionar Dispositivo --"] + device_options,
                        key="device_block_select"
                    )
                else:
                    selected_device = "-- Seleccionar Dispositivo --"
                    st.info("No hay dispositivos detectados.")
            
            with col_tipo:
                tipo_restriccion = st.selectbox(
                    "Tipo de Restricción:",
                    ["Bloqueo Total (Internet)", "Bloquear Página/Dominio"]
                )
            
            with col_reason:
                if tipo_restriccion == "Bloquear Página/Dominio":
                    block_target_val = st.text_input("Dominio (Ej: tiktok.com):", placeholder="tiktok.com", key="block_target_val")
                else:
                    block_target_val = st.text_input("Razón:", placeholder="Ej: Uso no autorizado", key="block_reason")
            
            col_info, col_action = st.columns([2, 1])
            with col_info:
                if selected_device != "-- Seleccionar Dispositivo --":
                    parts = selected_device.split(" | ")
                    sel_ip = parts[0].strip() if len(parts) > 0 else ""
                    sel_mac = parts[1].strip() if len(parts) > 1 else ""
                    sel_host_type = parts[2].strip() if len(parts) > 2 else ""
                    sel_conn_type = sel_host_type.split("(")[1].replace(")", "").strip() if "(" in sel_host_type else "LAN"
                    
                    if tipo_restriccion == "Bloqueo Total (Internet)":
                        st.info(f"**Objetivo:** {sel_ip} | **Método:** Bloqueo L2 + L3 + Flush total.")
                    else:
                        st.warning(f"**Objetivo:** {sel_ip} | **Método:** Bloqueo L7/DNS-Trap Web.")
            
            with col_action:
                st.markdown("<br>", unsafe_allow_html=True)
                if st.button("🚫 APLICAR RESTRICCIÓN", type="primary", use_container_width=True, key="btn_block_device"):
                    if selected_device != "-- Seleccionar Dispositivo --":
                        parts = selected_device.split(" | ")
                        sel_ip = parts[0].strip()
                        sel_mac = parts[1].strip()
                        sel_host_type = parts[2].strip() if len(parts) > 2 else ""
                        sel_hostname = sel_host_type.split("(")[0].strip() if "(" in sel_host_type else sel_host_type
                        sel_conn_type = sel_host_type.split("(")[1].replace(")", "").strip() if "(" in sel_host_type else "LAN"
                        
                        router = RouterManager(router_db.ip_address, router_db.api_user, router_db.api_pass_encrypted)
                        if router.connect()[0]:
                            if tipo_restriccion == "Bloqueo Total (Internet)":
                                reason = block_target_val or "Bloqueo Administrativo Total"
                                with st.spinner(f"Inyectando reglas de bloqueo L2/L3..."):
                                    exito, msj, rule_ids = router.block_device(
                                        ip_address=sel_ip,
                                        mac_address=sel_mac,
                                        hostname=sel_hostname,
                                        reason=reason,
                                        connection_type=sel_conn_type
                                    )
                                db_target = f"{sel_ip}/{sel_mac}"
                                db_block_type = 'device'
                            else:
                                if not block_target_val:
                                    st.error("Debes ingresar un dominio o página (ej. youtube.com)")
                                    st.stop()
                                
                                reason = f"Bloqueo Web: {block_target_val}"
                                with st.spinner(f"Inyectando DNS Trap y Address Lists para {block_target_val}..."):
                                    exito, msj = router.block_page_for_device(
                                        device_ip=sel_ip,
                                        domain=block_target_val,
                                        reason=reason
                                    )
                                    # Para desvincular un poco el backend
                                    rule_ids = []  # Necesitarían recolectarse las del firewall de la capa 7 si se quisiera borrar por ID, el backend actual flush/borra a partir de _device logic o ID? Actually we might just put empty and rely on firewall IPs / DNS trap rule IDs.
                                
                                db_target = block_target_val
                                db_block_type = 'web_page'
                                
                            router.disconnect()
                            
                            if exito:
                                st.success(msj)
                                # Persistir en SQLite
                                _save_block_to_db(
                                    router_id=router_db.id,
                                    ip=sel_ip, mac=sel_mac, hostname=sel_hostname,
                                    connection_type=sel_conn_type,
                                    block_type=db_block_type,
                                    target=db_target,
                                    reason=reason,
                                    blocked_by=st.session_state.get('username', 'admin'),
                                    rule_ids=rule_ids
                                )
                                add_log(f"Restricción Aplicada: {sel_ip} - {reason}", "SUCCESS")
                                st.session_state['telemetria'] = None
                                st.rerun()
                            else:
                                st.error(msj)
                                add_log(f"Fallo al restringir: {sel_ip} - {msj}", "ERROR")
                        else:
                            st.error("No se pudo conectar al router.")
                    else:
                        st.error("⚠️ No has seleccionado ningún dispositivo de la lista.")
        
        # ----- SECCIÓN 3: DISPOSITIVOS BLOQUEADOS (PERSISTENTE) -----
        st.markdown("---")
        st.markdown("### 🔴 Dispositivos Bloqueados (Registro Persistente)")
        st.caption("Esta lista se guarda en la base de datos y **NO desaparece al recargar la página**.")
        
        if blocked_db:
            # Tabla de dispositivos bloqueados
            df_blocked = pd.DataFrame(blocked_db)
            cols_blocked = ['ip', 'mac', 'hostname', 'connection_type', 'reason', 'blocked_by', 'created_at']
            cols_avail = [c for c in cols_blocked if c in df_blocked.columns]
            df_bl_show = df_blocked[cols_avail].copy()
            rename_bl = {
                'ip': '🖥️ IP', 'mac': '🔗 MAC', 'hostname': '📛 Hostname',
                'connection_type': '📡 Tipo', 'reason': '📝 Razón', 
                'blocked_by': '👤 Bloqueado por', 'created_at': '🕐 Fecha'
            }
            df_bl_show.rename(columns={k: v for k, v in rename_bl.items() if k in df_bl_show.columns}, inplace=True)
            st.dataframe(df_bl_show, hide_index=True, use_container_width=True)
            
            # Desbloquear dispositivo
            st.markdown("#### 🔓 Restaurar Acceso")
            col_unblock, col_btn_unblock = st.columns([3, 1])
            
            with col_unblock:
                unblock_options = {}
                for b in blocked_db:
                    label = f"{b['ip']} | {b['mac']} | {b['hostname']} — {b['reason']} [{b['created_at']}]"
                    unblock_options[label] = b
                
                selected_unblock = st.selectbox(
                    "Selecciona el dispositivo a desbloquear:",
                    ["-- Seleccionar --"] + list(unblock_options.keys()),
                    key="unblock_select",
                    label_visibility="collapsed"
                )
            
            with col_btn_unblock:
                if st.button("🔓 Desbloquear", type="primary", use_container_width=True, key="btn_unblock"):
                    if selected_unblock != "-- Seleccionar --":
                        block_info = unblock_options[selected_unblock]
                        success_fw = True
                        msj_fw = ""
                        
                        # 1. Eliminar reglas del Firewall si hay IDs
                        if block_info.get('firewall_rule_ids'):
                            router = RouterManager(router_db.ip_address, router_db.api_user, router_db.api_pass_encrypted)
                            if router.connect()[0]:
                                success_fw, msj_fw = router.unblock_device(block_info['firewall_rule_ids'])
                                router.disconnect()
                            else:
                                success_fw = False
                                msj_fw = "No se pudo conectar al router."
                        
                        # 2. Desactivar en DB
                        _deactivate_block_in_db(block_info['id'])
                        
                        if success_fw:
                            st.success(f"✅ Dispositivo {block_info['ip']} / {block_info['mac']} desbloqueado. {msj_fw}")
                            add_log(f"Dispositivo Desbloqueado: {block_info['ip']} / {block_info['mac']}", "SUCCESS")
                        else:
                            st.warning(f"⚠️ Registro eliminado de DB pero hubo un problema con el firewall: {msj_fw}")
                            add_log(f"Desbloqueo parcial: {block_info['ip']} - {msj_fw}", "WARNING")
                        
                        st.session_state['telemetria'] = None
                        st.rerun()
                    else:
                        st.error("⚠️ Debes seleccionar un elemento de la lista para proceder.")
        else:
            st.success("✅ No hay dispositivos bloqueados actualmente. Todos los equipos tienen acceso a la red.")

    # ------------------------------------------
    # 5. MÓDULO BACKUP & RECOVERY
    # ------------------------------------------
    with tab_backup:
        st.markdown("### 🚑 Recuperación ante Desastres")
        st.markdown("Genera y administra copias de seguridad de la configuración del equipo MikroTik.")

        st.markdown("---")
        st.markdown("#### 💾 Generar Nueva Copia")
        
        col_tipo, col_nota, col_crear = st.columns([1, 2, 1])
        
        with col_tipo:
            tipo_backup = st.selectbox(
                "Tipo de Backup:",
                ["🔒 Binario (.backup)", "📄 Export (.rsc)"],
                help="Binario: Restauración completa (solo mismo modelo). Export: Texto plano, portátil entre equipos."
            )
        with col_nota:
            nota_backup = st.text_input(
                "Etiqueta del Backup (Opcional):",
                placeholder="Ej: Antes_de_migrar_ERP",
                max_chars=30,
                label_visibility="collapsed"
            )
        with col_crear:
            crear_backup = st.button("💾 Generar Ahora", type="primary", use_container_width=True)
        
        if crear_backup:
            from core.router_api import RouterManager
            router = RouterManager(router_db.ip_address, router_db.api_user, router_db.api_pass_encrypted)
            if router.connect()[0]:
                with st.spinner("Compilando configuración en el MikroTik..."):
                    if "Binario" in tipo_backup:
                        exito, msj = router.create_router_backup(note=nota_backup.replace(" ", "_") if nota_backup else "")
                    else:
                        exito, msj = router.create_router_export()
                router.disconnect()
                if exito:
                    st.success(msj)
                    add_log(f"Backup creado: {tipo_backup}", "SUCCESS")
                else:
                    st.error(msj)
            else:
                st.error("No se pudo conectar al equipo.")

        st.markdown("---")
        st.markdown("#### 📂 Archivos en el Equipo")
        st.caption("Presiona 'Cargar' para leer los archivos almacenados en el router.")
        
        col_refresh, col_spacer = st.columns([1, 3])
        with col_refresh:
            cargar_archivos = st.button("🔄 Cargar Archivos", use_container_width=True)
        
        if cargar_archivos:
            from core.router_api import RouterManager
            router = RouterManager(router_db.ip_address, router_db.api_user, router_db.api_pass_encrypted)
            if router.connect()[0]:
                archivos = router.get_router_files()
                router.disconnect()
                
                if archivos:
                    st.session_state['backup_files'] = archivos
                else:
                    st.session_state['backup_files'] = []
                    st.info("No hay copias de seguridad almacenadas en este equipo.")
            else:
                st.error("No se pudo conectar al equipo.")
        
        if st.session_state.get('backup_files'):
            archivos = st.session_state['backup_files']
            
            df_archivos = pd.DataFrame(archivos)
            columnas_mostrar = [c for c in ['Nombre', 'Tamaño', 'Fecha', 'Tipo'] if c in df_archivos.columns]
            if columnas_mostrar:
                st.dataframe(df_archivos[columnas_mostrar], hide_index=True, use_container_width=True)
            
            with st.expander("🗑️ Eliminar Archivo del Equipo", expanded=False):
                col_del, col_btn_del = st.columns([3, 1])
                with col_del:
                    nombres_archivos = [a['_name'] for a in archivos if '_name' in a]
                    archivo_eliminar = st.selectbox(
                        "Seleccionar archivo:", 
                        ["-- Seleccionar --"] + nombres_archivos,
                        label_visibility="collapsed"
                    )
                with col_btn_del:
                    if st.button("🗑️ Eliminar", type="primary", use_container_width=True):
                        if archivo_eliminar != "-- Seleccionar --":
                            from core.router_api import RouterManager
                            router = RouterManager(router_db.ip_address, router_db.api_user, router_db.api_pass_encrypted)
                            if router.connect()[0]:
                                exito, msj = router.delete_router_file(archivo_eliminar)
                                router.disconnect()
                                if exito:
                                    st.success(msj)
                                    st.session_state['backup_files'] = None
                                    st.rerun()
                                else:
                                    st.error(msj)

        st.markdown("---")
        with st.expander("📖 Guía de Tipos de Backup", expanded=False):
            st.markdown("""
            | Característica | 🔒 Binario (.backup) | 📄 Export (.rsc) |
            |---|---|---|
            | **Formato** | Archivo binario cifrado | Texto plano (script) |
            | **Restauración** | Solo en el mismo modelo de equipo | Portátil entre modelos |
            | **Contenido** | Configuración completa + certificados | Solo configuración |
            | **Seguridad** | Alta (cifrado nativo) | Media (legible) |
            | **Uso ideal** | Disaster recovery rápido | Migración o auditoría |
            """)

    # ==========================================
    # SOC AUDIT LOGS (PERSISTENTES)
    # ==========================================
    st.markdown("---")
    st.markdown("### 📜 Registro de Auditoría SOC (Logs Persistentes)")
    st.caption("Los logs se guardan en la base de datos y **persisten entre sesiones y recargas**.")
    
    col_logs_session, col_logs_db = st.tabs(["📝 Sesión Actual", "🗄️ Historial Completo (DB)"])
    
    with col_logs_session:
        if st.session_state.get('soc_logs'):
            log_text = "\n".join(st.session_state['soc_logs'])
            st.code(log_text, language="text")
            if st.button("🗑️ Limpiar Logs de Sesión", key="clear_session_logs"):
                st.session_state['soc_logs'] = []
                st.rerun()
        else:
            st.info("No hay acciones tácticas registradas en esta sesión.")
    
    with col_logs_db:
        db_logs = _get_soc_logs(router_db.id, limit=200)
        if db_logs:
            st.markdown(f"**{len(db_logs)}** registros encontrados en la base de datos.")
            log_text_db = "\n".join(db_logs)
            st.code(log_text_db, language="text")
        else:
            st.info("No hay logs persistentes almacenados aún.")