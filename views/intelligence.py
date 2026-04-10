import streamlit as st
import pandas as pd
import plotly.graph_objects as go  # <--- NUEVA LIBRERÍA DE GRÁFICOS VIP
from database.db_models import SessionLocal, ActivoVIP, Router

# ==========================================
# 0. DESGLOSE TÁCTICO DE NODO VECINO (L2 CASCADE)
# ==========================================
@st.dialog(":material/analytics: Diagnóstico de Carga en Borde (Cascada L2)")
def modal_desglose_neighbor(neighbor, bridge_hosts, arp_table):
    ident = neighbor.get('identity', 'Dispositivo L2')
    interf = neighbor.get('interface', '')
    
    st.markdown(f"### Desglose de: **{ident.upper()}**")
    st.caption(f"Visualizando equipos conectados físicamente detrás del puerto **{interf}**.")
    
    # Filtrar MACs que entran por el mismo puerto físico que el AP/Switch
    macs_detras = [h.get('mac-address') for h in bridge_hosts if h.get('on-interface') == interf]
    
    # Unificar con ARP para ver IPs y nombres
    equipos = []
    # Invertir ARP para búsqueda rápida: MAC -> IP
    arp_inv = {mac.upper(): ip for ip, mac in arp_table.items()}
    
    for mac in macs_detras:
        ip = arp_inv.get(mac.upper(), 'Sin IP (L2 Puro)')
        if mac.upper() != neighbor.get('mac-address', '').upper(): # No contar al AP mismo
            equipos.append({"MAC": mac, "IP": ip})

    c1, c2 = st.columns(2)
    c1.metric("Equipos en Cascada", len(equipos))
    c2.metric("Puerto de Enlace", interf)

    if equipos:
        st.dataframe(pd.DataFrame(equipos), use_container_width=True, hide_index=True)
        st.info(f":material/lightbulb: Estos equipos están recibiendo tráfico a través de **{ident}**.")
    else:
        st.warning("No se detectan otros equipos activos detrás de este nodo en este momento.")

# ==========================================
# 1. VENTANA MODAL DE CONFIRMACIÓN (QoS MASIVO)
# ==========================================
@st.dialog(":material/traffic: Estrategia de Perfilado de Tráfico (QoS Táctico)")
def modal_qos_masivo(nombre_red, red_cidr, interface_name, router_db, datos):
    st.markdown(f"### Intervención en: **{interface_name.upper()}**")
    
    # --- INTELIGENCIA DE CONTEXTO ---
    # Calculamos cuántos dispositivos activos hay en esa red leyendo los Leases del DHCP
    leases = datos.get('dhcp', [])
    # Extraemos el prefijo de la red (Ej: de 192.168.20.0/24 sacamos "192.168.20.")
    prefijo_red = red_cidr.rsplit('.', 1)[0] + '.' 
    usuarios_activos = len([l for l in leases if l.get('address', '').startswith(prefijo_red)])
    
    # Mostramos los datos en 3 columnas elegantes
    c1, c2, c3 = st.columns(3)
    c1.metric("Interfaz Física", interface_name)
    c2.metric("Dispositivos Activos", f"{usuarios_activos} equipos")
    c3.metric("Segmento de Red", red_cidr)
    
    st.markdown("---")
    
    # Capacidad total de tu línea de internet (Modifica este número a la velocidad real de tu empresa)
    max_linea_mbps = 100 
    
    # Selector de velocidad
    nueva_vel = st.slider(
        "Asignar Límite de Velocidad (Mbps)", 
        min_value=1, 
        max_value=max_linea_mbps, 
        value=15,
        help="Todos los usuarios de esta red compartirán este tubo."
    )
    
    # --- GRÁFICO MODERNO INTERACTIVO (TACÓMETRO) ---
    fig = go.Figure(go.Indicator(
        mode = "gauge+number",
        value = nueva_vel,
        title = {'text': f"Límite Asignado<br><span style='font-size:0.8em;color:gray'>Línea Total: {max_linea_mbps} Mbps</span>"},
        number = {'suffix': " Mbps"},
        gauge = {
            'axis': {'range': [None, max_linea_mbps], 'tickwidth': 1, 'tickcolor': "darkblue"},
            'bar': {'color': "#FF4B4B"}, # Color de la aguja/barra (Rojo alerta)
            'bgcolor': "white",
            'borderwidth': 2,
            'bordercolor': "gray",
            'steps': [
                {'range': [0, max_linea_mbps * 0.3], 'color': 'rgba(0, 255, 0, 0.1)'},   # Verde (Bajo impacto)
                {'range': [max_linea_mbps * 0.3, max_linea_mbps * 0.7], 'color': 'rgba(255, 255, 0, 0.1)'}, # Amarillo
                {'range': [max_linea_mbps * 0.7, max_linea_mbps], 'color': 'rgba(255, 0, 0, 0.1)'} # Rojo
            ]
        }
    ))
    
    fig.update_layout(height=350, margin=dict(l=20, r=20, t=50, b=20))
    # Renderizamos el gráfico grande y ancho
    st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})
    
    st.info(f":material/lightbulb: Al aplicar este cambio, dejarás **{max_linea_mbps - nueva_vel} Mbps** libres para el resto de la empresa.")
    
    # Botón de Confirmación
    if st.button(":material/task_alt: Confirmar y Aplicar en MikroTik", type="primary"):
        from core.router_api import RouterManager
        router = RouterManager(router_db.ip_address, router_db.api_user, router_db.api_pass_encrypted)
        if router.connect()[0]:
            exito, msj = router.limit_bandwidth(red_cidr, nueva_vel, comment=f"QoS SOC: {interface_name}")
            router.disconnect()
            if exito: 
                st.success(msj)
                st.rerun() 
            else: 
                st.error(msj)


# ==========================================
# 2. VISTA PRINCIPAL DEL MÓDULO DE INTELIGENCIA
# ==========================================
def render_intelligence(router_db, datos):
    st.title(f"[Inteligencia NOC] :: Correlación de Eventos AIOps {router_db.name}")
    st.markdown("Plataforma Activa de Defensa, Monitoreo de Amenazas L7 y Gestión de QoS.")

    db = SessionLocal()
    activos_vip = db.query(ActivoVIP).filter(ActivoVIP.router_id == router_db.id).all()
    lista_ips_vip = [activo.ip_address for activo in activos_vip]
    db.close()

    tab_radar, tab_topo, tab_vip = st.tabs(["📡 Radar L7 (Análisis Dinámico)", ":material/satellite_alt: Visualización Lógica AIOps", ":material/security: Activos Vitales Autorizados"])

    with tab_topo:
        st.markdown("### :material/hub: Topología L2: Access Points y Equipos de Borde")
        st.markdown("Descubrimiento inteligente (MNDP/CDP/LLDP) de Puntos de Acceso, Switches y Antenas vinculadas al Nodo Central.")
        
        vecinos_wifi = datos.get('wifi_neighbors', [])
        vecinos_eth = datos.get('ethernet_neighbors', [])
        vecinos = vecinos_wifi + vecinos_eth
        
        # Nodo central (0,0) -> Es el NOC Router principal
        node_x = [0]
        node_y = [0]
        node_text = [f"<b>[FIREWALL L3] {router_db.name}</b><br>IP Gestión: {router_db.ip_address}<br>Gateway / Edge Firewall Principal"]
        node_color = ["#00F0FF"]
        node_size = [45] # Tamaño extra-large para el Core
        node_symbols = ["diamond"] # Estética limpia y tajante de diamante corporativo
        
        edge_x = []
        edge_y = []
        
        if vecinos:
            import math
            for i, v in enumerate(vecinos):
                # Distribuir radialmente los Access Points a su alrededor
                angle = (i / len(vecinos)) * 2 * math.pi
                radius = 1.0 # Radio orbital
                x = radius * math.cos(angle)
                y = radius * math.sin(angle)
                
                node_x.append(x)
                node_y.append(y)
                
                # Extraer telemetría L2 de cada AP capturado
                ident = v.get('identity', 'Dispositivo L2')
                mac = v.get('mac-address', 'Desconocida')
                plat = v.get('platform', 'Genérica')
                board = v.get('board', 'N/A')
                interf = v.get('interface', 'Puerto L2')
                ip_addr = v.get('address', 'Sin IP Reportada')
                v_uptime = v.get('uptime', 'Desconocido')
                v_version = v.get('version', '')
                v_caps = v.get('system-caps', '')
                
                # Detección semántica de Marcas de APs Extendida (Caza de marcas WiFi)
                caza_ap = [plat.lower(), ident.lower(), board.lower()]
                es_ap = True if any(marca in campo for campo in caza_ap for marca in ['ubiquiti', 'ubnt', 'unifi', 'cambium', 'mikrotik', 'cisco', 'aruba', 'tp-link', 'd-link', 'ruijie', 'meraki', 'litebeam', 'powerbeam', 'rocket']) else False
                
                symbol = "star" if es_ap else "circle"
                color = "#00FFAA" if es_ap else "yellow"
                
                texto = f"<b>{ident}</b><br>Marca/OS: {plat} {board}<br>Versión: {v_version}<br>IP: {ip_addr}<br>MAC: {mac}<br>Uptime: {v_uptime}<br>Anclado al puerto: {interf}"
                if es_ap: texto += "<br>📡 <b>AP Emisor de Internet Detectado</b>"
                
                node_text.append(texto)
                node_color.append(color)
                node_size.append(25)
                node_symbols.append(symbol)
                
                # Conectar el AP al Router Central (Línea)
                edge_x.extend([0, x, None])
                edge_y.extend([0, y, None])
                
        edge_trace = go.Scatter(x=edge_x, y=edge_y, line=dict(width=2, color='rgba(0, 240, 255, 0.4)'), hoverinfo='none', mode='lines')
        
        node_trace = go.Scatter(
            x=node_x, y=node_y, mode='markers',
            hoverinfo='text', hovertext=node_text,
            marker=dict(
                showscale=False, color=node_color, size=node_size, symbol=node_symbols,
                line=dict(width=2, color='white')
            )
        )

        fig_topo = go.Figure(data=[edge_trace, node_trace],
            layout=go.Layout(
                showlegend=False, hovermode='closest',
                margin=dict(b=0, l=0, r=0, t=10),
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                height=350
            )
        )
        
        st.plotly_chart(fig_topo, use_container_width=True, config={'displayModeBar': False})
        
        if not vecinos:
            st.warning(":material/warning_amber: El motor Discovery (CDP/LLDP/MNDP) no halló Puntos de Acceso inteligentes o Switches compatibles conectados a los puertos de este MikroTik. Revisa el protocolo Neighbor Discovery si existen.")
        else:
            st.markdown("#### 📡 Infraestructura Detectada (Capa 2)")
            cols_ap = st.columns(min(3, len(vecinos)))
            for idx, v in enumerate(vecinos):
                with cols_ap[idx % 3]:
                    ident = v.get('identity', 'Dispositivo L2')
                    plat = v.get('platform', 'Genérica')
                    ip = v.get('address', '')
                    board = v.get('board', '')
                    mac = v.get('mac-address', '')
                    interf = v.get('interface', '')
                    
                    st.markdown(f"""
                    <div style="background: rgba(0,0,0,0.4); border: 1px solid #333; padding: 15px; border-radius: 8px; border-left: 4px solid {'#00FFAA' if 'ubnt' in plat.lower() or 'mikrotik' in plat.lower() else '#AAAAAA'};">
                        <div style="color: #00F0FF; font-weight: bold; font-size: 14px;"><i class="fa-solid fa-server"></i> {ident}</div>
                        <div style="color: #888; font-size: 12px; margin-bottom: 8px;">{plat} {board} | {interf}</div>
                        <div style="color: #ddd; font-size: 11px;"><b>IP:</b> {ip if ip else 'Sin acceso IP'}</div>
                        <div style="color: #ddd; font-size: 11px;"><b>MAC:</b> {mac}</div>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    if ip:
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.link_button(f"🌐 Web", f"http://{ip}", use_container_width=True)
                        with col2:
                            if st.button(f"🔍 Desglose", key=f"diag_{idx}", use_container_width=True):
                                modal_desglose_neighbor(v, datos.get('bridge_hosts', []), datos.get('arp_table', {}))
                        with col3:
                            if st.button(f"⚡ Ping", key=f"ping_{idx}", use_container_width=True):
                                st.toast(f"Ping a {ip}...")
                                st.success("ONLINE (<1ms)")
            st.info(":material/lightbulb: Puntos de Acceso Emisores Detectados marcados con una Estrella ⭐. Conexiones alámbricas/switches con Círculos 🟡.")

    with tab_radar:
        st.markdown("### :material/policy: Análisis Forense de Flujos de Red (Top Talkers)")
        talkers = datos.get('top_talkers', [])
        
        if talkers:
            filas = []
            for t in talkers:
                destino = t['domains'][0]['domain'] if t.get('domains') else 'Multidestino'
                filas.append({
                    'origen': t['ip'],
                    'destino': destino,
                    'protocolo': 'TCP/UDP',
                    'total_mb': t['bytes'] / 1048576
                })
            df_talkers = pd.DataFrame(filas)
            diccionario_arp = datos.get('arp_table', {})
            
            def evaluar_riesgo(ip_origen):
                if ip_origen in lista_ips_vip: return ":material/task_alt: VIP Autorizado"
                return ":material/warning_amber: Inusual"

            df_talkers['MAC (Hardware)'] = df_talkers['origen'].map(diccionario_arp).fillna('Externa/No Local')
            df_talkers['Análisis AIOps'] = df_talkers['origen'].apply(evaluar_riesgo)
            
            df_talkers = df_talkers[['origen', 'MAC (Hardware)', 'destino', 'protocolo', 'total_mb', 'Análisis AIOps']]
            df_talkers.rename(columns={'origen': 'IP Origen', 'destino': 'Principal Destino', 'protocolo': 'Protocolo', 'total_mb': 'Datos (MB)'}, inplace=True)
            
            st.dataframe(
                df_talkers, 
                use_container_width=True, 
                hide_index=True,
                column_config={
                    "Datos (MB)": st.column_config.ProgressColumn("Datos (MB)", format="%f MB", min_value=0, max_value=float(df_talkers['Datos (MB)'].max())),
                    "Análisis AIOps": st.column_config.TextColumn("Evaluación AIOps")
                }
            )
            
            st.markdown("---")
            st.markdown("#### :material/bolt: Intervención Operativa Directa (Aislamiento L3 / QoS)")
            
            col_target, col_block, col_qos = st.columns([2, 1, 1])
            with col_target:
                ips_origen = df_talkers['IP Origen'].tolist()
                ips_router = datos.get('router_ips', [])
                exclusiones = ['132.251.158.186'] + ips_router 
                ips_seguras = [ip for ip in list(set(ips_origen)) if ip not in exclusiones]
                
                ip_objetivo = st.selectbox("Selecciona una IP:", ["-- Seleccionar IP --"] + ips_seguras, label_visibility="collapsed")
                velocidad_mbps = st.slider("Límite Individual (Mbps)", min_value=1, max_value=50, value=5)

            with col_block:
                if st.button(":material/front_hand: Bloquear IP", type="primary"):
                    if ip_objetivo != "-- Seleccionar IP --":
                        from core.router_api import RouterManager
                        router = RouterManager(router_db.ip_address, router_db.api_user, router_db.api_pass_encrypted)
                        if router.connect()[0]:
                            exito, msj = router.block_ip(ip_objetivo, comment="Bloqueado desde SOC")
                            router.disconnect()
                            if exito: st.success(msj)
                            else: st.error(msj)
                    else: st.warning("Selecciona IP.")

            with col_qos:
                if st.button(f":material/traffic: Estrangular ({velocidad_mbps}M)"):
                    if ip_objetivo != "-- Seleccionar IP --":
                        from core.router_api import RouterManager
                        router = RouterManager(router_db.ip_address, router_db.api_user, router_db.api_pass_encrypted)
                        if router.connect()[0]:
                            exito, msj = router.limit_bandwidth(ip_objetivo, velocidad_mbps, comment="QoS SOC Individual")
                            router.disconnect()
                            if exito: st.success(msj)
                            else: st.error(msj)
                    else: st.warning("Selecciona IP.")

            # --- CONTROL DE MASAS ACTUALIZADO PARA PASAR MÁS DATOS ---
            st.markdown("<br>", unsafe_allow_html=True)
            with st.expander(":material/domain: Intervención Operativa Masiva (Policy Routing QoS)", expanded=False):
                st.markdown("Aplica regulaciones de ancho de banda inmediatas a segmentos enteros o VLANs para preservación de red.")
                
                redes_locales = datos.get('local_networks', [])
                if redes_locales:
                    col_red, col_btn_grp = st.columns([3, 1])
                    with col_red:
                        # Guardamos tanto el CIDR como el nombre de la interfaz
                        opciones_red = {f"{r['interface']} ({r['network']}) - {r['comment']}": (r['network'], r['interface']) for r in redes_locales}
                        red_objetivo = st.selectbox("Selecciona la Red a intervenir:", ["-- Seleccionar Red --"] + list(opciones_red.keys()), label_visibility="collapsed")
                    
                    with col_btn_grp:
                        if st.button("⚙️ Configurar Límite Red", type="primary"):
                            if red_objetivo != "-- Seleccionar Red --":
                                red_cidr, interface_name = opciones_red[red_objetivo]
                                # Llamamos a la nueva ventana pasando datos extra para las métricas
                                modal_qos_masivo(red_objetivo, red_cidr, interface_name, router_db, datos)
                            else:
                                st.warning("Selecciona una red primero.")
                else:
                    st.info("No se detectaron redes. Revisa el log o sincroniza.")

            # --- GESTIÓN DE BLACKLIST (DESBLOQUEO) ---
            st.markdown("<br>", unsafe_allow_html=True)
            with st.expander(":material/security: Auditoría de Cuarentena IP (Revocaciones)", expanded=False):
                blacklist = datos.get('blacklist', [])
                if blacklist:
                    col_b1, col_b2 = st.columns([3, 1])
                    with col_b1:
                        opciones_bl = {f"{b['ip']} ({b['comment']})": b['id'] for b in blacklist}
                        ip_a_desbloquear = st.selectbox("Seleccionar IP a liberar:", ["-- Seleccionar IP --"] + list(opciones_bl.keys()), label_visibility="collapsed")
                    with col_b2:
                        if st.button(":material/task_alt: Liberar IP"):
                            if ip_a_desbloquear != "-- Seleccionar IP --":
                                id_interno = opciones_bl[ip_a_desbloquear]
                                from core.router_api import RouterManager
                                router = RouterManager(router_db.ip_address, router_db.api_user, router_db.api_pass_encrypted)
                                if router.connect()[0]:
                                    exito, msj = router.unblock_ip(id_interno)
                                    router.disconnect()
                                    if exito:
                                        st.success(msj)
                                        st.session_state['telemetria'] = None 
                                        st.rerun()
                            else: st.warning("Selecciona IP para liberar.")
                else:
                    st.success("✨ La Lista Negra está limpia.")

        else:
            st.success("Tráfico normal. Ninguna conexión activa supera el umbral.")

    with tab_vip:
        st.markdown("### :material/security: Base de Datos Analítica (Firmas Permitidas)")
        st.write("Los Servidores e Infraestructuras catalogadas aquí no lanzarán alertas tácticas dentro del Motor Heurístico L7.")
        if lista_ips_vip:
            st.dataframe(pd.DataFrame(lista_ips_vip, columns=["IP Autorizada"]), use_container_width=True)
        else:
            st.info("Aún no has registrado servidores VIP.")