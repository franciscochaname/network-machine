import streamlit as st
import pandas as pd
from core.router_api import RouterManager
from core.network_scanner import detect_arp_anomalies, detect_rogue_dhcp, is_scapy_ready

def render_tactical(router_db):
    if 'soc_logs' not in st.session_state:
        st.session_state['soc_logs'] = []

    def add_log(action, status="INFO"):
        from datetime import datetime
        st.session_state['soc_logs'].insert(0, f"[{datetime.now().strftime('%H:%M:%S')}] [{status}] {action}")

    st.title("⚡ Centro de Control de Emergencias (SOC)")
    st.markdown("Ejecución inmediata de comandos en el núcleo. **Precaución: Las acciones aquí afectan la red en tiempo real.**")
    
    # Creamos un menú de pestañas para organizar las herramientas
    tab_incidencias, tab_vpn, tab_playbooks = st.tabs([
        "🛡️ Firewall - Seguridad de la Red", 
        "🌍 Aprovisionamiento VPN", 
        "⚙️ Playbooks (Mantenimiento)"
    ])
    
    # ==========================================
    # PESTAÑA 1: RESPUESTA A INCIDENTES
    # ==========================================
    with tab_incidencias:
        st.subheader("Acciones de Mitigación Rápida")
        col1, col2 = st.columns(2)
        
        # Módulo QoS (Existente)
        with col1:
            with st.container(border=True):
                st.markdown("<h4 style='color: #FF4B4B;'>🚫 QoS Capa 7 (Bloqueo Multimedia)</h4>", unsafe_allow_html=True)
                st.caption("Activa reglas de Firewall para priorizar tráfico corporativo.")
                c_on, c_off = st.columns(2)
                if c_on.button("🔴 CORTAR TRÁFICO", use_container_width=True, type="primary"):
                    router = RouterManager(router_db.ip_address, router_db.api_user, router_db.api_pass_encrypted)
                    if router.connect()[0]:
                        with st.spinner("Aplicando..."):
                            exito, msj = router.toggle_social_media_block(enable=True)
                            if exito:
                                st.success(msj)
                                add_log("Activación de QoS / Bloqueo L7", "SUCCESS")
                            else:
                                st.error(msj)
                                add_log("Fallo al activar QoS", "ERROR")
                        router.disconnect()
                
                if c_off.button("🟢 LIBERAR TRÁFICO", use_container_width=True):
                    router = RouterManager(router_db.ip_address, router_db.api_user, router_db.api_pass_encrypted)
                    if router.connect()[0]:
                        with st.spinner("Liberando..."):
                            exito, msj = router.toggle_social_media_block(enable=False)
                            if exito: st.success(msj)
                            else: st.error(msj)
                        router.disconnect()

        # Módulo Blacklist (Avanzado multi-vendor)
        with col2:
            with st.container(border=True):
                vendor = getattr(router_db, 'vendor', 'MikroTik').upper()
                st.markdown(f"<h4 style='color: #FF4B4B;'>🧱 Bloqueo Avanzado de Firewall</h4>", unsafe_allow_html=True)
                st.caption(f"Motor activo adaptado para: **{vendor} RouterOS**")
                
                block_type = st.selectbox("Tipo de Restricción", ["IP / Subred (Drop Total)", "Página Web / Dominio (TLS Host)", "Puerto Específico (Ej: 22 SSH)"], label_visibility="collapsed")
                
                placeholder = "Dirección IP o CIDR (Ej: 192.168.1.50 o 10.0.0.0/24)"
                if "Web" in block_type: placeholder = "Escribe el dominio (Ej: facebook.com o netflix)"
                elif "Puerto" in block_type: placeholder = "Número de puerto (Ej: 3389, 445)"
                
                target_bloqueo = st.text_input("Objetivo", placeholder=placeholder, label_visibility="collapsed")
                comentario = st.text_input("Razón del Bloqueo (Opcional)", placeholder="Ej: Ataque DDoS detectado")
                
                if st.button("🔨 Ejecutar Regla de Contención", use_container_width=True, type="primary"):
                    if target_bloqueo:
                        router = RouterManager(router_db.ip_address, router_db.api_user, router_db.api_pass_encrypted)
                        if router.connect()[0]:
                            with st.spinner(f"Compilando regla en código {vendor} e inyectando a la memoria del Firewall..."):
                                exito, msj = router.create_advanced_block(block_type, target_bloqueo, comentario or "Bloqueo Táctico SOC")
                                if exito:
                                    st.success(msj)
                                    add_log(f"Ejecución de Firewall Rule: {msj}", "SUCCESS")
                                else:
                                    st.error(msj)
                                    add_log(f"Fallo al inyectar regla en Firewall: {msj}", "ERROR")
                            router.disconnect()
                    else:
                        st.warning("⚠️ Debes proporcionar el Objetivo (IP, Puerto o Página Web).")

        st.markdown("---")
        # Killswitch (Existente)
        st.markdown("<h4 style='color: #00F0FF;'>🥾 Expulsión de Túnel Activo (Killswitch)</h4>", unsafe_allow_html=True)
        if st.session_state['telemetria'] and st.session_state['telemetria'].get('vpns'):
            vpns = st.session_state['telemetria']['vpns']
            lista_usuarios = [v.get('name') for v in vpns]
            col_k1, col_k2 = st.columns([3, 1])
            with col_k1:
                user_a_expulsar = st.selectbox("Selecciona la sesión a destruir:", lista_usuarios, label_visibility="collapsed")
            with col_k2:
                if st.button("Cortar Sesión", use_container_width=True):
                    router = RouterManager(router_db.ip_address, router_db.api_user, router_db.api_pass_encrypted)
                    if router.connect()[0]:
                        with st.spinner("Cortando..."):
                            exito, msj = router.kick_vpn_user(user_a_expulsar)
                            if exito: st.success(msj)
                            else: st.error(msj)
                        router.disconnect()
        else:
            st.info("No hay usuarios remotos conectados en este momento.")

        # --- ARP Y DHCP ---
        st.markdown("---")
        st.subheader("Auditoría de Capa 2 (Detección Scapy)")
        col_s1, col_s2 = st.columns(2)
        
        with col_s1:
            with st.container(border=True):
                st.markdown("#### 🔍 Monitor Anti-ARP Spoofing")
                if st.session_state.get('telemetria'):
                    current_arp = st.session_state['telemetria'].get('arp_table', {})
                    prev_arp = st.session_state.get('prev_arp_table', {})
                    
                    if prev_arp:
                        anomalies = detect_arp_anomalies(prev_arp, current_arp)
                        if anomalies:
                            criticals = [a for a in anomalies if a['severidad'] == 'CRÍTICO']
                            if criticals:
                                st.error(f"🔴 {len(criticals)} ALERTA(S) CRÍTICA(S) de suplantación MAC detectada.")
                            df_anom = pd.DataFrame(anomalies)
                            st.dataframe(df_anom, hide_index=True, use_container_width=True)
                        else:
                            st.success("✅ Sin anomalías ARP desde la última sincronización.")
                    else:
                        st.info("📋 Se necesita una sincronización adicional para comparar la tabla ARP.")
                    st.session_state['prev_arp_table'] = current_arp.copy()
                else:
                    st.info("Sin telemetría.")

        with col_s2:
            with st.container(border=True):
                st.markdown("#### 🏴‍☠️ Detector de DHCP Rogue (Falso Servidor)")
                st.caption("Envía un paquete Discover de prueba a la red para ver quién responde primero.")
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

        # === SOC AUDIT LOGS ===
        st.markdown("---")
        with st.expander("📜 Registro de Auditoría de Verificaciones (SOC Logs)", expanded=True):
            if st.session_state['soc_logs']:
                log_text = "\n".join(st.session_state['soc_logs'])
                st.code(log_text, language="text")
                if st.button("🗑️ Limpiar Logs"):
                    st.session_state['soc_logs'] = []
                    st.rerun()
            else:
                st.info("No hay verificaciones o bloqueos tácticos registrados en esta sesión.")

    # ==========================================
    # PESTAÑA 2: GESTIÓN DE VPN
    # ==========================================
    with tab_vpn:
        st.subheader("Base de Datos de Usuarios VPN (PPP Secrets)")
        col_list, col_add = st.columns([1.5, 1])
        
        router = RouterManager(router_db.ip_address, router_db.api_user, router_db.api_pass_encrypted)
        
        exito_conexion, msj_conexion = router.connect()
        exito_lectura = False
        users_db = []
        msj_lectura = ""
        
        if exito_conexion:
            exito_lectura, resultado = router.get_all_vpn_users()
            router.disconnect()
            if exito_lectura:
                users_db = resultado
            else:
                msj_lectura = resultado
                
        with col_list:
            if not exito_conexion:
                st.error(f"Error de conexión con el núcleo: {msj_conexion}")
            elif not exito_lectura:
                # AQUÍ SALDRÁ EL ERROR REAL DEL MIKROTIK
                st.error(f"⚠️ **Error del API:** {msj_lectura}")
                st.info("💡 **Solución:** Ve a tu Winbox > System > Users > Groups. Asegúrate de que el grupo de tu usuario tenga activado el check en **'sensitive'**. El router está bloqueando a Python porque esa tabla contiene contraseñas.")
            elif len(users_db) == 0:
                st.info("No hay ningún usuario VPN registrado localmente.")
            else:
                df_users = pd.DataFrame(users_db)
                
                # Formateamos las columnas para que coincida con tu terminal
                cols_utiles = ['name', 'service', 'profile', 'remote-address', 'disabled', 'comment']
                df_mostrar = df_users[[c for c in cols_utiles if c in df_users.columns]].copy()
                df_mostrar.fillna('-', inplace=True) 
                
                # Traducimos los estados visualmente
                if 'disabled' in df_mostrar.columns:
                    df_mostrar['Estado'] = df_mostrar['disabled'].apply(lambda x: '❌ Inactivo' if str(x).lower() == 'true' else '✅ Activo')
                    df_mostrar.drop(columns=['disabled'], inplace=True)
                
                st.dataframe(df_mostrar, use_container_width=True, hide_index=True)
                
                st.markdown("**Eliminar Usuario Permanente:**")
                del_user = st.selectbox("Seleccionar credencial a destruir", [u['name'] for u in users_db], label_visibility="collapsed")
                if st.button("🗑️ Eliminar Credencial", type="primary"):
                    if router.connect()[0]:
                        exito, msj = router.delete_vpn_user(del_user)
                        router.disconnect()
                        if exito: 
                            st.success(msj)
                            st.rerun()
                        else: st.error(msj)

        with col_add:
            with st.container(border=True):
                st.markdown("<h4 style='color: #00F0FF; margin-top:0;'>➕ Nuevo Usuario VPN</h4>", unsafe_allow_html=True)
                with st.form("new_vpn_form"):
                    new_name = st.text_input("Nombre de Usuario (Sin espacios)")
                    new_pass = st.text_input("Contraseña", type="password")
                    new_proto = st.selectbox("Protocolo", ["any", "pptp", "l2tp", "sstp", "ovpn"])
                    # Agregamos campo para IP Remota ya que lo usas en tu red
                    new_ip = st.text_input("Remote Address (Opcional, Ej: 172.16.20.100)")
                    
                    if st.form_submit_button("Generar Credencial", use_container_width=True):
                        if new_name and new_pass:
                            if router.connect()[0]:
                                # Si pusiste IP, la mandamos al router
                                extra_params = {'remote-address': new_ip} if new_ip else {}
                                try:
                                    router.api.get_resource('/ppp/secret').add(
                                        name=new_name, password=new_pass, service=new_proto, profile="default", **extra_params
                                    )
                                    st.success(f"✅ Credencial para '{new_name}' generada.")
                                    st.rerun()
                                except Exception as e:
                                    st.error(f"Error al crear: {e}")
                                router.disconnect()
                        else:
                            st.warning("Completa usuario y contraseña.")

    # ==========================================
    # PESTAÑA 3: PLAYBOOKS
    # ==========================================
    with tab_playbooks:
        st.subheader("Operaciones Críticas de Infraestructura")
        st.markdown("Rutinas automatizadas para mantenimiento preventivo o correctivo.")
        
        with st.container(border=True):
            st.markdown("### ⚡ Reinicio Físico (Soft Reboot)")
            st.warning("⚠️ **ATENCIÓN:** Esto apagará el equipo. Todos los túneles VPN se caerán y la red local perderá conexión a internet por aproximadamente 2 minutos.")
            
            # Verificación en dos pasos para evitar accidentes
            confirmar = st.checkbox("Entiendo los riesgos y confirmo que deseo reiniciar el nodo.")
            if st.button("🚀 INICIAR SECUENCIA DE REINICIO", type="primary", disabled=not confirmar):
                router = RouterManager(router_db.ip_address, router_db.api_user, router_db.api_pass_encrypted)
                if router.connect()[0]:
                    with st.spinner("Enviando señal de apagado al núcleo..."):
                        exito, msj = router.reboot_router()
                        st.success(msj)
                        st.session_state['telemetria'] = None # Vaciamos datos porque el router ya no está
                else:
                    st.error("No se pudo conectar al router para enviar el comando.")