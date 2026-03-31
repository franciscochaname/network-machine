import streamlit as st
import pandas as pd
from core.network_analysis import (
    build_topology_graph, calculate_network_metrics, generate_topology_figure,
    simulate_node_failure, find_spof, find_shortest_path, generate_traffic_sankey
)
from core.network_scanner import detect_arp_anomalies, detect_rogue_dhcp, is_scapy_ready

@st.dialog("📊 Análisis Forense de Nodo", width="large")
def node_details_dialog(node_id, data, router_db):
    st.markdown(f"### Nodo Seleccionado: {data.get('label', node_id)}")
    
    col1, col2 = st.columns(2)
    col1.metric("Clasificación de Capa", data.get('node_type', 'Desconocido').upper())
    
    st.markdown("#### 📝 Perfil Operativo Extraído de Telemetría")
    detalles = data.get('detail', 'Sin datos operativos adicionales.')
    st.info(detalles)
    
    pure_target = str(node_id).replace('net:', '').replace('vpn:', '').replace('iface:', '').split('/')[0]
    
    st.markdown("#### ⚙️ Motor de Auditoría Inteligente (AIOps)")
    st.caption("Esta herramienta conectará módulos de bajo nivel y bloqueará la pantalla visualmente mientras inyecta paquetes para extraer toda la verdad del nodo.")
    
    if st.button("🚀 INICIAR ESCANEO PROFUNDO Y REVISIÓN MULTICAPA", type="primary", use_container_width=True):
        with st.status("Preparando inyección de paquetes y aislando nodo...", expanded=True) as status:
            import time
            from core.network_scanner import system_ping, tcp_port_scan, system_traceroute
            
            # PASO 1: PING
            st.write("📡 **Fase 1:** Test de Vida y Latencia Crítica (ICMP)...")
            ping_out = system_ping(pure_target)
            st.code(ping_out, language="text")
            
            # PASO 2: TCP PORT SCAN
            st.write("🚪 **Fase 2:** Auditoría de Vulnerabilidades y Puertos Abiertos (TCP SYN)...")
            res_tcp = tcp_port_scan(pure_target)
            if res_tcp:
                st.warning(f"⚠️ ¡Atención! Se han detectado {len(res_tcp)} puerto(s) activos.")
                st.dataframe(pd.DataFrame(res_tcp), hide_index=True)
            else:
                st.success("✅ Protocolos Blindados. Ningún puerto TCP o servicio común fue vulnerado ni expuesto en esta pasada.")
                
            # PASO 3: TRACEROUTE
            st.write("🛤️ **Fase 3:** Rastreo de Saltos y Firewalls intermedios (Traceroute Forense)...")
            st.info("Obteniendo topología real del salto hacia la IP (Puede tomar de 15 a 45 seg)...")
            tr_out = system_traceroute(pure_target)
            st.code(tr_out, language="text")
            
            status.update(label="✅ Escaneo Profundo y Verificación Completada Satisfactoriamente", state="complete", expanded=True)
            
        st.error("💡 **Dictamen:** Tras revisar los puertos abiertos, la latencia y la ruta mostrada arriba, si consideras que el dispositivo es una amenaza o no autorizado, dirígete a la pestaña 'Centro Táctico' y procede con un Baneo de Capa 3 (IP/MAC) Inmediato.")

@st.dialog("🔍 Inspección Forense de Flujo L4-L7", width="large")
def show_flow_dialog(flow):
    st.markdown(f"### Detalles del Enlace: `Prioridad {flow.get('Rank', '#0')}`")
    st.caption("Visor de Capa de Transporte (Intercepción Activa)")
    
    col1, col2 = st.columns(2)
    col1.metric("📡 IP Origen (Atacante/Cliente)", flow.get('IP Origen', 'N/A'))
    col2.metric("🌍 IP Destino (Servidor WAN/LAN)", flow.get('IP Destino (WAN/LAN)', 'N/A'))
    
    st.markdown("---")
    col3, col4, col5 = st.columns(3)
    col3.metric("Protocolo Base", flow.get('L4 Protocolo', 'N/A'))
    col4.metric("Deducción de Tráfico", flow.get('L7 Deducción', 'N/A'))
    col5.metric("Consumo Detectado", flow.get('Transferencia', 'N/A'))
    
    st.info("💡 **Sugerencia AIOps:** Si este tráfico parece ilegítimo, puedes aplicar una cuarentena.")
    c_btn1, c_btn2 = st.columns(2)
    if c_btn1.button("📡 Rastrear Intermediarios (Trace)", use_container_width=True):
        from core.network_scanner import system_traceroute
        st.code(system_traceroute(flow.get('IP Destino (WAN/LAN)', '').split(':')[0]), language="text")
    if c_btn2.button("🚫 Bloquear Conexión (Drop)", type="primary", use_container_width=True):
        st.error("La orden DROP (Baneo Firewall) se ha encolado en el Centro Táctico.")

def render_topology(router_db, datos):
    st.title(f"🔗 Topología de Red — {router_db.name}")
    
    # CSS injection para cambiar la cruz (crosshair) de Plotly por una mano (pointer) al interactuar
    st.markdown("""
    <style>
    .js-plotly-plot .plotly .cursor-crosshair {
        cursor: pointer !important;
    }
    </style>
    """, unsafe_allow_html=True)

    # === CONSTRUIR GRAFO ===
    G = build_topology_graph(router_db, datos)
    metrics = calculate_network_metrics(G)

    # === TABS ===
    tab_graph, tab_resilience, tab_sankey, tab_wifi = st.tabs([
        "🔗 Grafo Topológico", "🛡️ Análisis de Resiliencia",
        "📊 Flujos de Tráfico", "📡 Wi-Fi Intelligence"
    ])

    # ==========================================
    # TAB 1: GRAFO TOPOLÓGICO
    # ==========================================
    with tab_graph:
        type_counts = metrics.get('type_counts', {})
        c1, c2, c3, c4, c5, c6 = st.columns(6)
        c1.metric("📊 Nodos", metrics.get('total_nodes', 0))
        c2.metric("🔗 Enlaces", metrics.get('total_edges', 0))
        c3.metric("💻 Dispositivos", type_counts.get('device', 0))
        c4.metric("🌍 VPN", type_counts.get('vpn', 0))
        c5.metric("📐 Densidad", f"{metrics.get('density', 0):.3f}")
        c6.metric("🔄 Clustering", f"{metrics.get('avg_clustering', 0):.3f}")

        col_graph, col_analysis = st.columns([3, 1])

        with col_graph:
            fig = generate_topology_figure(G)
            event = st.plotly_chart(fig, use_container_width=True, on_select="rerun", selection_mode="points", key="topo_graph", config={
                'displayModeBar': True, 'displaylogo': False,
                'modeBarButtonsToRemove': ['lasso2d', 'select2d'],
            })
            
            # Action upon graph node interaction
            if event and event.get("selection", {}).get("points"):
                punto = event["selection"]["points"][0]
                node_id = punto.get("customdata")
                if node_id and node_id in G.nodes:
                    node_details_dialog(node_id, G.nodes[node_id], router_db)

        with col_analysis:
            st.markdown("#### 🎯 Nodos Críticos")
            st.caption("Betweenness Centrality")
            critical = metrics.get('critical_nodes', [])
            if critical:
                for node in critical:
                    imp = node['centrality']
                    bar_w = min(imp * 500, 100)
                    bar_c = "#FF4B4B" if imp > 0.5 else "#FFAA00" if imp > 0.2 else "#00FFAA"
                    st.markdown(f"""
                    <div style="margin-bottom: 8px;">
                        <div style="display: flex; justify-content: space-between;">
                            <span style="color: #ccc; font-size: 12px;">{node['node']}</span>
                            <span style="color: {bar_c}; font-size: 11px; font-family: 'JetBrains Mono';">{imp:.4f}</span>
                        </div>
                        <div class="kpi-bar" style="margin-top: 3px;"><div class="kpi-fill" style="width: {bar_w}%; background: {bar_c};"></div></div>
                    </div>""", unsafe_allow_html=True)
            else:
                st.info("Red simple.")

            st.markdown("---")
            st.markdown("#### 📐 Propiedades")
            st.dataframe(pd.DataFrame({
                "Métrica": ["Componentes", "Diámetro", "Grado Prom.", "Subredes", "Interfaces"],
                "Valor": [metrics.get('components', 0), metrics.get('diameter', 'N/A'),
                          metrics.get('avg_degree', 0), type_counts.get('subnet', 0),
                          type_counts.get('interface', 0)]
            }), hide_index=True, use_container_width=True)

            st.markdown("---")
            st.markdown("""
            <div style="font-size: 12px; line-height: 2.2;">
                <span style="color: #00F0FF;">━━━</span> Físico &nbsp;
                <span style="color: #FFAA00;">┈┈┈</span> Lógico &nbsp;
                <span style="color: #00FFAA;">━━━</span> DHCP<br>
                <span style="color: #FF007F;">╌╌╌</span> VPN &nbsp;
                <span style="color: #FF6B35;">┈┈┈</span> WAN
            </div>""", unsafe_allow_html=True)

    # ==========================================
    # TAB 2: ANÁLISIS DE RESILIENCIA
    # ==========================================
    with tab_resilience:
        st.markdown("### 🛡️ Análisis Forense de Resiliencia de Red")
        st.caption("Auditoría geométrica de puntos únicos de fallo y simulación táctica de contingencias (What-If).")

        spof = find_spof(G)
        
        # AIOPS BLOQUE INTELIGENTE
        if not st.session_state.get('hide_resilience_aiops', False):
            with st.container(border=True):
                c_title, c_close = st.columns([9, 1])
                c_title.markdown("#### 🤖 AIOps: Evaluación Matemática de Tolerancia a Fallos")
                if c_close.button("✖️ Cerrar", key="btn_close_resil"):
                    st.session_state['hide_resilience_aiops'] = True
                    st.rerun()
                
                redundancy = spof['redundancy_score']
                if redundancy > 0.8:
                    st.success(f"✅ **Red Multicamino (Alta Disponibilidad):** Tu índice de redundancia es del **{redundancy:.1%}**. Es geométricamente complicado que la falla de un solo router o switch aísle la red completa, tienes excelentes rutas redundantes.")
                elif redundancy > 0.4:
                    st.warning(f"⚠️ **Debilidad Estructural Media:** Índice del **{redundancy:.1%}**. El análisis de grafos encontró un diseño híbrido. Ojo con los 'Puntos de Fallo' (nodos obligatorios), porque si se apagan, dividirán temporalmente la red.")
                else:
                    st.error(f"🚨 **Arquitectura Centralizada (Estrella Pura):** Índice peligrosamente bajo de **{redundancy:.1%}**. Existen demasiados 'Single Points of Failure' (SPOF). Si el punto central falla por corte eléctrico, la red morirá de inmediato.")
                
                st.info("💡 **Gota de Conocimiento:** Los _Articulation Points_ son los cuellos de botella forzosos. Intenta cruzar más cables (rutas OSPF) hacia otros repetidores para evadir estas caídas y elevar la redundancia garantizando túneles secundarios.")

        st.markdown("---")
        c1, c2, c3 = st.columns(3)
        score_color = "#00FFAA" if spof['redundancy_score'] > 0.7 else "#FFAA00" if spof['redundancy_score'] > 0.4 else "#FF4B4B"
        c1.metric("🔑 Puntos Únicos de Fallo", spof['total_spof'])
        c2.metric("🌉 Enlaces de Cristal (Puentes)", spof['total_bridges'])
        c3.markdown(f"""
        <div class="health-gauge" style="border-top: 3px solid {score_color}; padding: 15px;">
            <p class="kpi-label">Factor de Resiliencia</p>
            <p class="health-grade" style="color: {score_color}; font-size: 36px;">{spof['redundancy_score']:.1%}</p>
        </div>""", unsafe_allow_html=True)

        if spof['spof_nodes']:
            st.markdown("#### 🔴 Lista de Puntos de Fallo Críticos (Articulation Points)")
            st.caption("Si cualquiera de estos componentes principales se apaga, la red se parte en pedazos.")
            df_spof = pd.DataFrame(spof['spof_nodes'])
            st.dataframe(df_spof, hide_index=True, use_container_width=True)
        else:
            st.success("✅ **Red Blindada:** No se detectaron routers o switches aislantes.")

        if spof['bridges']:
            # st.markdown("#### 🌉 Enlaces Físicos de Alta Necesidad (Bridges)")
            # st.caption("Cables exactos que conectan áreas sin soporte adicional.")
            with st.expander("🌉 Ver Enlaces Físicos sin Respaldo (Bridges)"):
                st.dataframe(pd.DataFrame(spof['bridges']), hide_index=True, use_container_width=True)

        # --- WHAT-IF ---
        st.markdown("---")
        st.markdown("#### 🔬 Simulación Táctica de Impacto Colateral (What-If)")
        st.caption("Selecciona cualquier equipo virtual de la red. El AIOps lo apagará de la matriz para calcular algorítmicamente cuántos host morirían en caso de accidente.")

        node_options = {}
        for n, data in G.nodes(data=True):
            label = data.get('label', n)
            ntype = data.get('node_type', '')
            if ntype in ('router', 'interface', 'subnet'):
                node_options[f"[{ntype.upper()}] {label}"] = n

        if node_options:
            col_target, col_btn = st.columns([3, 1])
            with col_target:
                selected = st.selectbox("🎯 Nodo Foco (Objetivo):", list(node_options.keys()), label_visibility="collapsed")
            with col_btn:
                run_sim = st.button("⚡ Ejecutar Catástrofe", type="primary", use_container_width=True)
                
            if run_sim:
                with st.status("💥 Abatiendo nodo. Recalculando ruta en la matriz Spanning Tree...", expanded=True) as status:
                    node_id = node_options[selected]
                    result = simulate_node_failure(G, node_id)
                    import time; time.sleep(0.4) # Dramatic rendering delay

                    sev_colors = {'CRÍTICO': '🔴', 'MODERADO': '🟡', 'BAJO': '🟢'}
                    sev_icon = sev_colors.get(result['severity'], '⚪')
                    
                    st.write(f"Evaluando matriz de propagación de impacto...")
                    time.sleep(0.3)

                    st.markdown(f"##### {sev_icon} Perfil de Destrucción: Severidad {result['severity']}")
                    
                    col_r1, col_r2, col_r3 = st.columns(3)
                    col_r1.metric("Impacto Directo (Rutas)", result['direct_impact'])
                    col_r2.metric("☠️ Usuarios Huérfanos", result['isolated_nodes'])
                    col_r3.metric("Clústers Fragmentados", result['network_fragments'])

                    if result['affected_devices']:
                        st.markdown(f"**Host Terminales Offline si apagas el nodo `{result['removed']}`:**")
                        st.dataframe(pd.DataFrame(result['affected_devices']), hide_index=True, use_container_width=True)
                    else:
                        st.success("✅ **Costo Cero.** Su pérdida no afecta a ningún host terminal, se redigiría correctamente.")
                        
                    status.update(label="✅ Simulación What-If Exitosamente Finalizada", state="complete", expanded=True)

        # --- SHORTEST PATH ---
        st.markdown("---")
        st.markdown("#### 🛤️ Trazado OSPF de Emergencia (Route Analytics)")
        st.caption("Encuentra la ruta más corta entre dos nodos y mide la redundancia.")

        all_nodes = {G.nodes[n].get('label', n): n for n in G.nodes()}
        node_names = list(all_nodes.keys())

        if len(node_names) >= 2:
            col_src, col_dst = st.columns(2)
            src_label = col_src.selectbox("Origen:", node_names, index=0)
            dst_label = col_dst.selectbox("Destino:", node_names, index=min(1, len(node_names) - 1))

            if st.button("🔍 Calcular Ruta"):
                path_result = find_shortest_path(G, all_nodes[src_label], all_nodes[dst_label])
                if 'error' in path_result:
                    st.error(path_result['error'])
                else:
                    col_p1, col_p2, col_p3 = st.columns(3)
                    col_p1.metric("Hops", path_result['hops'])
                    col_p2.metric("Rutas Alternativas", path_result['alternative_routes'])
                    col_p3.metric("Redundancia", path_result['redundancy'])

                    path_html = " → ".join([f"<span style='color: #00F0FF; font-family: JetBrains Mono;'>{p}</span>" for p in path_result['path']])
                    st.markdown(f"**Ruta:** {path_html}", unsafe_allow_html=True)

    # ==========================================
    # TAB 3: FLUJOS DE TRÁFICO (SANKEY)
    # ==========================================
    with tab_sankey:
        st.markdown("### 📊 Topología de Flujos de Tráfico L4/L7")
        st.caption("Mapeo Dinámico Sankey — Visualización Termal de Consumo de Ancho de Banda (Top Talkers)")

        # Filtrar talkers fantasma (conexiones inactivas o con 0 MB)
        raw_talkers = datos.get('flujos_sankey', [])
        top_talkers = [t for t in raw_talkers if t.get('total_mb', 0) > 0]

        if top_talkers:
            # 1. Gráfica Sankey
            fig_sankey = generate_traffic_sankey(top_talkers)
            st.plotly_chart(fig_sankey, use_container_width=True, config={'displayModeBar': False})

            # 2. Análisis AIOps (Comentarios Inteligentes con opción de cerrado)
            if not st.session_state.get('hide_sankey_aiops', False):
                with st.container(border=True):
                    c_title, c_close = st.columns([9, 1])
                    c_title.markdown("#### 🤖 AIOps: Análisis Operativo de Patrones")
                    if c_close.button("✖️ Cerrar", key="btn_close_sankey_aiops"):
                        st.session_state['hide_sankey_aiops'] = True
                        st.rerun()

                    # Lógica de Inteligencia Artificial Básica
                    total_vol = sum(t.get('total_mb', 0) for t in top_talkers)
                    if top_talkers:
                        heavy_hitter = top_talkers[0]
                        hh_ip = heavy_hitter.get('origen', 'N/A')
                        hh_mb = heavy_hitter.get('total_mb', 0)
                        pct = (hh_mb / total_vol * 100) if total_vol > 0 else 0
                        
                        puertos_inseguros = [t for t in top_talkers if str(t.get('puerto')) in ['80', '21', '23']]
                        
                        st.markdown(f"""
                        - **Concentración de Carga:** El nodo `{hh_ip}` está monopolizando el **{pct:.1f}%** del tráfico total listado ({hh_mb:.1f} MB). Si esto no es un servidor o un equipo de backup, podría indicar descarga masiva o exfiltración.
                        - **Volumen Global Analizado:** **{total_vol:.1f} MB** transfiriéndose activamente en la matriz de ruteo.
                        """)
                        
                        if puertos_inseguros:
                            st.error(f"⚠️ **Vulnerabilidad Activa Detectada:** Hay {len(puertos_inseguros)} flujo(s) viajando por puertos no encriptados (80/HTTP, 21/FTP, 23/Telnet). El tráfico puede ser interceptado en texto plano.")
                        else:
                            st.success("✅ **Cifrado Fuerte:** Todos los flujos principales detectados utilizan puertos estándar de encriptación (443/HTTPS, etc).")
                        
                        st.info("💡 **Recomendación NOC:** Si detectas un hilo asimétrico masivo hacia un servidor desconocido en el gráfico de arriba, aplica una cola (QoS Queue) temporal al Origen para destapar el embudo.")

            # 3. Datos Tabulares Advanced
            st.markdown("---")
            st.markdown("#### 📋 Matriz Forense de Top Talkers (Lista de Prioridad)")
            st.caption("Tráfico exportado bajo inspección de Capa 4 a Capa 7")
            
            talker_data = []
            for i, t in enumerate(top_talkers[:50]): # Hasta 50 flujos
                t_mb = t.get('total_mb', 0)
                puerto = str(t.get('puerto', ''))
                
                # Clasificador de Severidad (Puramente Visual)
                sev = "🟢 Normal"
                if t_mb > 500: sev = "🔴 Crítico"
                elif t_mb > 50: sev = "🟡 Elevado"
                
                # Clasificador de Protocolo Capa 7
                l7_tag = "Web/SSL" if puerto == '443' else "Texto Plano (HTTP)" if puerto == '80' else "Gestión SSH" if puerto == '22' else "Base de Datos" if puerto in ['3306', '5432'] else "Personalizado"
                
                talker_data.append({
                    'Rank': f"#{i+1}",
                    'Severidad': sev,
                    'IP Origen': t.get('origen', ''),
                    'IP Destino (WAN/LAN)': t.get('destino', ''),
                    'L4 Protocolo': f"{t.get('protocolo', '').upper()} / {puerto}",
                    'L7 Deducción': l7_tag,
                    'Transferencia': f"{t_mb:.2f} MB"
                })
                
            event_flow = st.dataframe(pd.DataFrame(talker_data), hide_index=True, use_container_width=True, on_select="rerun", selection_mode="single-row")
            if event_flow and event_flow.selection.rows:
                idx = event_flow.selection.rows[0]
                show_flow_dialog(talker_data[idx])
            
        else:
            st.info("📡 No hay suficientes datos encolados en el procesador. El tráfico actual de la red es demasiado bajo o el sensor Netflow/Sniffer está recopilando paquetes iniciales.")



    # ==========================================
    # TAB 5: WI-FI INTELLIGENCE
    # ==========================================
    with tab_wifi:
        st.markdown("### 📡 Wi-Fi Intelligence — Tabla de Vecindad BSSID")
        st.caption("Interfaces wireless, clientes conectados y redes vecinas para geolocalización por BSSID.")

        wifi_ifaces = datos.get('wifi_interfaces', [])
        wifi_neighbors = datos.get('wifi_neighbors', [])

        if wifi_ifaces:
            st.markdown("#### 📶 Interfaces Wireless del Router")
            df_ifaces = pd.DataFrame(wifi_ifaces)
            st.dataframe(df_ifaces, hide_index=True, use_container_width=True)
        else:
            st.info("Este router no tiene interfaces wireless detectadas, o no es un modelo con Wi-Fi.")

        if wifi_neighbors:
            st.markdown("---")
            st.markdown("#### 👥 Clientes Wi-Fi Conectados (Registration Table)")
            st.caption("Dispositivos conectados al AP del router con métricas de señal.")

            for client in wifi_neighbors:
                if not isinstance(client, dict):
                    continue
                signal = str(client.get('signal', ''))
                signal_val = 0
                try:
                    # Protegemos el string split logic en caso de datos vacíos
                    if signal:
                        signal_val = abs(int(signal.replace('dBm', '').replace('@', '').split('/')[0].strip()))
                except Exception:
                    pass

                signal_color = "#00FFAA" if signal_val < 60 else "#FFAA00" if signal_val < 75 else "#FF4B4B"
                signal_label = "Excelente" if signal_val < 50 else "Buena" if signal_val < 65 else "Débil" if signal_val < 80 else "Crítica"

                st.markdown(f"""
                <div class="map-router-card" style="border-left: 3px solid {signal_color};">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <span class="map-router-name">📱 {client.get('mac', 'N/A')}</span>
                            <div class="map-router-ip">{client.get('hostname', client.get('interface', ''))}</div>
                        </div>
                        <div style="text-align: right;">
                            <span style="color: {signal_color}; font-family: 'JetBrains Mono'; font-weight: 700;">{signal}</span>
                            <div style="font-size: 10px; color: #666;">{signal_label}</div>
                            <div class="map-router-location">TX: {client.get('tx_rate', 'N/A')} | RX: {client.get('rx_rate', 'N/A')}</div>
                        </div>
                    </div>
                </div>""", unsafe_allow_html=True)
        elif wifi_ifaces:
            st.info("No hay clientes Wi-Fi conectados actualmente.")

        # --- BSSID SCAN ---
        st.markdown("---")
        st.markdown("#### 🗺️ Escaneo de Redes Vecinas (BSSID Geolocation)")
        st.caption("Escanea redes Wi-Fi cercanas para obtener BSSIDs que pueden usarse para geolocalización.")

        st.warning("""⚠️ **Advertencia:** El escaneo Wi-Fi pone la interfaz temporalmente en modo scan. 
        Esto puede interrumpir la conexión de los clientes Wi-Fi durante unos segundos.""")

        col_scan_iface, col_scan_dur, col_scan_btn = st.columns([2, 1, 1])
        with col_scan_iface:
            scan_iface = st.text_input("Interfaz wireless:", value="wlan1", key="wifi_scan_iface")
        with col_scan_dur:
            scan_dur = st.number_input("Duración (seg):", value=5, min_value=2, max_value=30, key="wifi_scan_dur")
        with col_scan_btn:
            st.markdown("<br>", unsafe_allow_html=True)
            do_scan = st.button("📡 Escanear", type="primary", key="btn_wifi_scan")

        if do_scan:
            from core.router_api import RouterManager
            router = RouterManager(router_db.ip_address, router_db.api_user, router_db.api_pass_encrypted)
            ok, _ = router.connect()
            if ok:
                with st.spinner(f"Escaneando redes Wi-Fi en {scan_iface} ({scan_dur}s)..."):
                    scan_results = router.get_wifi_scan(interface=scan_iface, duration=scan_dur)
                router.disconnect()

                if scan_results:
                    st.success(f"📡 {len(scan_results)} red(es) Wi-Fi detectada(s)")

                    def parse_signal(x):
                        try:
                            if not isinstance(x, dict): return -100
                            sig = str(x.get('signal', '-100'))
                            if not sig: return -100
                            return int(sig.replace('dBm', '').replace('@', '').split('/')[0].strip())
                        except:
                            return -100

                    for ap in sorted(scan_results, key=parse_signal, reverse=True):
                        signal = str(ap.get('signal', 'N/A'))
                        
                        sig_val = parse_signal(ap)
                        signal_color = "#00FFAA" if sig_val > -60 else "#FFAA00" if sig_val > -75 else "#FF4B4B"
                        
                        st.markdown(f"""
                        <div class="map-router-card" style="border-left: 3px solid {signal_color};">
                            <div style="display: flex; justify-content: space-between; align-items: center;">
                                <div>
                                    <span class="map-router-name">📶 {ap.get('ssid', 'Red Oculta')}</span>
                                    <div class="map-router-ip">MAC Vecina (BSSID): {ap.get('bssid', 'N/A')}</div>
                                    <div class="map-router-location" style="color:#FFF;">
                                        🕒 Radio: {ap.get('band', '')} | 📺 Frecuencia: {ap.get('frequency', 'N/A')} MHz (Canal {ap.get('channel', 'N/A')})
                                    </div>
                                </div>
                                <div style="text-align: right;">
                                    <span style="color: {signal_color}; font-size: 20px; font-family: 'JetBrains Mono'; font-weight: 700;">{signal}</span>
                                    <div class="map-router-location" style="margin-top:4px;">🔑 Seg: {ap.get('security', 'Abierta (Insegura)')}</div>
                                </div>
                            </div>
                        </div>""", unsafe_allow_html=True)

                    st.markdown("---")
                    st.markdown("##### 📋 Tabla BSSID Cruda (exportable a herramientas OSINT)")
                    st.dataframe(pd.DataFrame(scan_results), hide_index=True, use_container_width=True)
                else:
                    st.info("No se encontraron redes espectrales. Verifica que la antena esté prendida, el interfaz no esté deshabilitado o estés en zona ciega (Sótano de Farad).")
            else:
                st.error("No se pudo conectar al router para ejecutar el escaneo.")

    # === TABLA DE NODOS ===
    with st.expander("📋 Tabla Completa de Nodos del Grafo", expanded=False):
        node_data = []
        for node, data in G.nodes(data=True):
            node_data.append({
                'ID': str(node)[:30],
                'Tipo': data.get('node_type', 'N/A'),
                'Etiqueta': data.get('label', 'N/A'),
                'Detalle': data.get('detail', ''),
                'Conexiones': G.degree(node),
            })
        df_nodes = pd.DataFrame(node_data).sort_values('Conexiones', ascending=False)
        st.dataframe(df_nodes, hide_index=True, use_container_width=True)
