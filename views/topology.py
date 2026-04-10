import streamlit as st
import streamlit.components.v1 as components
import pandas as pd
from core.network_analysis import (
    build_topology_graph, calculate_network_metrics, generate_topology_html,
    classify_network_topology,
    simulate_node_failure, find_spof, find_shortest_path, generate_traffic_sankey,
    generate_bandwidth_sunburst
)
from core.network_scanner import detect_arp_anomalies, detect_rogue_dhcp, is_scapy_ready

@st.dialog(":material/bar_chart: Análisis Forense de Nodo", width="large")
def node_details_dialog(node_id, data, router_db):
    st.markdown(f"### Nodo Seleccionado: {data.get('label', node_id)}")
    
    col1, col2 = st.columns(2)
    col1.metric("Clasificación de Capa", data.get('node_type', 'Desconocido').upper())
    layer = data.get('layer', 'N/A')
    layer_names = {0: "WAN/ISP", 1: "Router Core", 2: "Interfaz L2", 3: "Subred L3", 4: "Endpoint", 5: "Destino WAN"}
    col2.metric("Capa Jerárquica", layer_names.get(layer, f"Capa {layer}"))
    
    st.markdown("#### 📝 Perfil Operativo Extraído de Telemetría")
    detalles = data.get('detail', 'Sin datos operativos adicionales.')
    st.info(detalles)
    
    pure_target = str(node_id).replace('net:', '').replace('vpn:', '').replace('iface:', '').replace('gw:', '').replace('ext:', '').replace('gw:fo_', '').split('/')[0]
    
    st.markdown("#### ⚙️ Motor de Auditoría Inteligente (AIOps)")
    st.caption("Conecta módulos de bajo nivel para extraer toda la verdad del nodo.")
    
    if st.button(":material/rocket_launch: INICIAR ESCANEO PROFUNDO", type="primary", use_container_width=True):
        with st.status("Escaneando nodo...", expanded=True) as status:
            import time
            from core.network_scanner import system_ping, tcp_port_scan, system_traceroute
            
            st.write("📡 **Fase 1:** Test de Vida (ICMP)...")
            ping_out = system_ping(pure_target, count=4)
            st.code(ping_out, language="text")
            
            st.write(":material/door_open: **Fase 2:** Puertos Abiertos (TCP)...")
            res_tcp = tcp_port_scan(pure_target)
            if res_tcp:
                st.warning(f":material/warning_amber: {len(res_tcp)} puerto(s) activos.")
                st.dataframe(pd.DataFrame(res_tcp), hide_index=True)
            else:
                st.success(":material/task_alt: Ningún puerto expuesto.")
                
            st.write(":material/alt_route: **Fase 3:** Traceroute Forense...")
            tr_out = system_traceroute(pure_target)
            st.code(tr_out, language="text")
            
            status.update(label=":material/task_alt: Escaneo Completado", state="complete", expanded=True)

@st.dialog(":material/search: Inspección Forense de Flujo L4-L7", width="large")
def show_flow_dialog(flow):
    st.markdown(f"### Detalles del Enlace: `Prioridad {flow.get('Rank', '#0')}`")
    
    col1, col2 = st.columns(2)
    col1.metric("📡 IP Origen", flow.get('IP Origen', 'N/A'))
    col2.metric(":material/public: IP Destino", flow.get('IP Destino (WAN/LAN)', 'N/A'))
    
    st.markdown("---")
    col3, col4, col5 = st.columns(3)
    col3.metric("Protocolo", flow.get('L4 Protocolo', 'N/A'))
    col4.metric("Deducción L7", flow.get('L7 Deducción', 'N/A'))
    col5.metric("Consumo", flow.get('Transferencia', 'N/A'))
    
    c_btn1, c_btn2 = st.columns(2)
    if c_btn1.button("📡 Traceroute", use_container_width=True):
        from core.network_scanner import system_traceroute
        st.code(system_traceroute(flow.get('IP Destino (WAN/LAN)', '').split(':')[0]), language="text")
    if c_btn2.button(":material/block: Bloquear (Drop)", type="primary", use_container_width=True):
        st.error("Orden DROP encolada en el Centro Táctico.")

@st.dialog(":material/map: Explorador de Arquitectura", width="large")
def _show_map_dialog(G, router_db, topo_class):
    st.markdown(f"### Mapa Interactivo — {router_db.name}")
    st.caption("Usa la rueda del ratón para hacer zoom. Arrastra los nodos para reacomodar la topología.")
    st.markdown("""
        <style>
            div[data-testid="stDialog"] div[role="dialog"] {
                width: 92vw !important;
                max-width: 92vw !important;
            }
        </style>
    """, unsafe_allow_html=True)
    
    html_content = generate_topology_html(G, height="850px")
    components.html(html_content, height=870, scrolling=False)
    
    top_cols = st.columns(3)
    top_cols[0].metric("Clasificación", topo_class.get('type', '?'))
    top_cols[1].metric("Riesgo Estructural", topo_class.get('risk', '?').split('—')[0].strip())
    top_cols[2].metric("Total Nodos Activos", G.number_of_nodes())
    
    if st.button("Cerrar Mapa"):
        st.session_state['show_topology_map'] = False
        st.rerun()

def render_topology(router_db, datos):
    st.title(f"[Topología L2/L3] :: {router_db.name}")

    # === CONSTRUIR GRAFO ===
    G = build_topology_graph(router_db, datos)
    metrics = calculate_network_metrics(G)
    topo_class = classify_network_topology(G)

    # === TABS ===
    tab_graph, tab_bw, tab_resilience, tab_sankey, tab_wifi = st.tabs([
        ":material/link: Diagrama Interactivo", 
        ":material/pie_chart: Distribución de Ancho de Banda",
        ":material/security: Resiliencia (SPOF)",
        ":material/bar_chart: Flujos Sankey", 
        "📡 WiFi Intelligence"
    ])

    # ==========================================
    # TAB 1: DATOS DETALLADOS + MAPA
    # ==========================================
    with tab_graph:
        # ── Clasificación de Topología con Evidencia ──
        topo_color = topo_class.get('color', '#00F0FF')
        topo_risk = topo_class.get('risk', 'N/A')
        risk_color = '#FF4B4B' if 'ALTO' in str(topo_risk) else '#FFAA00' if 'MEDIO' in str(topo_risk) else '#00FFAA'
        topo_metrics = topo_class.get('metrics', {})
        evidence = topo_class.get('evidence', [])
        
        # Banner de clasificación
        st.markdown(f"""
        <div style="background:rgba(0,0,0,0.3);border:1px solid {topo_color}40;border-radius:10px;padding:14px 20px;margin-bottom:14px;">
            <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px;">
                <div style="display:flex;align-items:center;gap:14px;">
                    <span style="font-size:34px;">{topo_class.get('icon', '?')}</span>
                    <div>
                        <div style="color:{topo_color};font-size:18px;font-weight:700;font-family:JetBrains Mono;">{topo_class.get('type', 'Desconocida')}</div>
                        <div style="color:#aaa;font-size:12px;">{topo_class.get('description', '')}</div>
                    </div>
                </div>
                <div style="text-align:right;">
                    <div style="color:{risk_color};font-size:12px;font-weight:700;font-family:JetBrains Mono;">⚠ {topo_risk}</div>
                    <div style="color:#555;font-size:10px;">Confianza: {topo_class.get('confidence', 0)}%</div>
                </div>
            </div>
            <div style="border-top:1px solid rgba(255,255,255,0.06);padding-top:8px;">
                <div style="color:#666;font-size:10px;font-weight:700;margin-bottom:4px;text-transform:uppercase;letter-spacing:1px;">¿Por qué esta clasificación?</div>
                {''.join(f'<div style="color:#999;font-size:11px;padding:2px 0;"><span style="color:{topo_color};margin-right:6px;">▸</span>{ev}</div>' for ev in evidence)}
            </div>
        </div>""", unsafe_allow_html=True)

        # ── Métricas KPI ──
        wan_info = datos.get('wan_status', {})
        conn_method = wan_info.get('connection_method', '?')
        has_fo = wan_info.get('has_failover', False)
        type_counts = metrics.get('type_counts', {})
        
        c1, c2, c3 = st.columns(3)
        c1.metric(":material/bar_chart: Nodos Totales", metrics.get('total_nodes', 0))
        c2.metric(":material/link: Enlaces Activos", metrics.get('total_edges', 0))
        c3.metric("🌐 Conectividad WAN", conn_method, delta="Failover Activo" if has_fo else "Sin respaldo", delta_color="normal" if has_fo else "off")

        # ── Botón abrir mapa ──
        if st.button(":material/map: Abrir Mapa Interactivo de Red (Packet Tracer)", type="primary", use_container_width=True, key="btn_open_map"):
            st.session_state['show_topology_map'] = True
            st.rerun()
        
        if st.session_state.get('show_topology_map', False):
            _show_map_dialog(G, router_db, topo_class)

        # ── Datos Detallados: 2 columnas ──
        col_left, col_right = st.columns([2, 1])
        
        with col_left:
            # Tabla de todos los nodos por capa
            st.markdown("#### 📋 Inventario Completo de Nodos")
            
            node_rows = []
            layer_names = {0: "WAN/ISP", 1: "Core", 2: "Interfaz L2", 3: "Subred L3", 4: "Endpoint", 5: "Destino WAN"}
            for node, data in G.nodes(data=True):
                layer = data.get('layer', 3)
                nt = data.get('node_type', '?')
                detail_raw = data.get('detail', '')
                first_line = detail_raw.split('\n')[0] if detail_raw else ''
                
                node_rows.append({
                    'Capa': f"L{layer} — {layer_names.get(layer, '?')}",
                    'Tipo': nt.replace('_', ' ').title(),
                    'Nombre': data.get('label', str(node)).replace('\n', ' '),
                    'Conexiones': G.degree(node),
                    'Detalle': first_line,
                })
            
            df_nodes = pd.DataFrame(node_rows).sort_values(['Capa', 'Conexiones'], ascending=[True, False])
            
            event_node = st.dataframe(df_nodes, hide_index=True, use_container_width=True, 
                                       on_select="rerun", selection_mode="single-row", key="node_table")
            
            if event_node and event_node.selection.rows:
                idx = event_node.selection.rows[0]
                selected_row = df_nodes.iloc[idx]
                # Buscar nodo original
                sel_label = selected_row['Nombre']
                for n, d in G.nodes(data=True):
                    if d.get('label', '').replace('\n', ' ') == sel_label:
                        node_details_dialog(n, d, router_db)
                        break

            # Tabla de enlaces
            st.markdown("#### 🔗 Enlaces de Red")
            edge_rows = []
            for u, v, data in G.edges(data=True):
                u_label = G.nodes[u].get('label', str(u)).replace('\n', ' ')
                v_label = G.nodes[v].get('label', str(v)).replace('\n', ' ')
                etype = data.get('edge_type', '?')
                bw = data.get('bandwidth', data.get('weight', 0))
                detail = data.get('detail', '')
                edge_rows.append({
                    'Desde': u_label[:25],
                    'Hacia': v_label[:25],
                    'Tipo': etype.replace('_', ' ').title(),
                    'Peso/BW': f"{bw:.2f}",
                    'Info': detail[:40] if detail else '',
                })
            
            df_edges = pd.DataFrame(edge_rows).sort_values('Peso/BW', ascending=False)
            st.dataframe(df_edges, hide_index=True, use_container_width=True)
        
        with col_right:
            # Composición por tipo
            st.markdown("#### :material/architecture: Composición")
            type_icons = {
                'internet': '☁', 'gateway': '🏢', 'router': '🔲',
                'wan_iface': '🌐', 'bridge': '🔀', 'wireless': '📡',
                'ethernet': '🔌', 'vpn_iface': '🔒', 'vlan': '🏷',
                'subnet': '🌐', 'device': '💻', 'vpn': '🔐', 'external': '☁'
            }
            for t, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
                icon = type_icons.get(t, '•')
                st.markdown(f"""<div style="display:flex;justify-content:space-between;padding:3px 0;border-bottom:1px solid rgba(255,255,255,0.04);">
                    <span style="color:#bbb;font-size:12px;">{icon} {t.replace('_', ' ').title()}</span>
                    <span style="color:#00F0FF;font-family:JetBrains Mono;font-size:12px;font-weight:700;">{count}</span>
                </div>""", unsafe_allow_html=True)
            
            st.markdown("---")
            
            # Nodos Críticos
            st.markdown("#### :material/api: Nodos Críticos")
            st.caption("Betweenness Centrality")
            critical = metrics.get('critical_nodes', [])
            if critical:
                for node in critical[:5]:
                    imp = node['centrality']
                    bar_w = min(imp * 500, 100)
                    bar_c = "#FF4B4B" if imp > 0.5 else "#FFAA00" if imp > 0.2 else "#00FFAA"
                    st.markdown(f"""
                    <div style="margin-bottom:5px;">
                        <div style="display:flex;justify-content:space-between;">
                            <span style="color:#ccc;font-size:11px;">{node['node'][:22]}</span>
                            <span style="color:{bar_c};font-size:10px;font-family:JetBrains Mono;">{imp:.4f}</span>
                        </div>
                        <div class="kpi-bar" style="margin-top:2px;"><div class="kpi-fill" style="width:{bar_w}%;background:{bar_c};"></div></div>
                    </div>""", unsafe_allow_html=True)
            else:
                st.caption("Sin cuellos de botella detectados.")
            
            st.markdown("---")
            
            # Propiedades del grafo
            st.markdown("#### 📊 Propiedades del Grafo")
            props = {
                'Componentes': metrics.get('components', 0),
                'Diámetro': metrics.get('diameter', 'N/A'),
                'Densidad': f"{metrics.get('density', 0):.4f}",
                'Grado Promedio': metrics.get('avg_degree', 0),
                'Clustering': f"{metrics.get('avg_clustering', 0):.4f}",
            }
            for k, v in props.items():
                st.markdown(f"""<div style="display:flex;justify-content:space-between;padding:2px 0;">
                    <span style="color:#888;font-size:11px;">{k}</span>
                    <span style="color:#ccc;font-family:JetBrains Mono;font-size:11px;">{v}</span>
                </div>""", unsafe_allow_html=True)
            
            st.markdown("---")
            
            # Métricas de clasificación crudas
            if topo_metrics:
                with st.expander("🔬 Métricas de Clasificación (raw)"):
                    for k, v in topo_metrics.items():
                        st.caption(f"`{k}`: {v}")

    # ==========================================
    # TAB 2: DISTRIBUCIÓN DE ANCHO DE BANDA
    # ==========================================
    with tab_bw:
        st.markdown("### :material/pie_chart: Distribución de Ancho de Banda por Segmento")
        st.caption("Visualización jerárquica: Router → Interfaces → Subredes → Dispositivos")
        
        col_sun, col_table = st.columns([2, 1])
        
        with col_sun:
            fig_sun = generate_bandwidth_sunburst(datos)
            st.plotly_chart(fig_sun, use_container_width=True, config={'displayModeBar': False})
        
        with col_table:
            st.markdown("#### 📊 Tráfico por Interfaz")
            traffic = datos.get('traffic_list', [])
            if traffic:
                iface_data = []
                for t in sorted(traffic, key=lambda x: x.get('rx', 0) + x.get('tx', 0), reverse=True):
                    bw = t.get('rx', 0) + t.get('tx', 0)
                    iface_data.append({
                        'Interfaz': t.get('name', '?'),
                        '↓ Rx': f"{t.get('rx', 0):.2f} M",
                        '↑ Tx': f"{t.get('tx', 0):.2f} M",
                        'Total': f"{bw:.2f} M",
                    })
                st.dataframe(pd.DataFrame(iface_data), hide_index=True, use_container_width=True)
            
            st.markdown("---")
            st.markdown("#### 🌐 Consumo por Subred")
            subnet_bw = datos.get('bandwidth_by_subnet', [])
            if subnet_bw:
                sb_data = []
                for sb in subnet_bw[:10]:
                    sb_data.append({
                        'Subred': sb.get('subnet', '?'),
                        'MB Total': f"{sb.get('total_mb', 0):.1f}",
                        'Devices': sb.get('device_count', 0),
                        'Top Device': sb.get('top_device', 'N/A'),
                    })
                st.dataframe(pd.DataFrame(sb_data), hide_index=True, use_container_width=True)
            else:
                st.info("Active el modo L7 (análisis profundo) para ver consumo por subred.")

    # ==========================================
    # TAB 2: ANÁLISIS DE RESILIENCIA
    # ==========================================
    with tab_resilience:
        st.markdown("### :material/security: Análisis Forense de Resiliencia de Red")
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
                    st.success(f":material/task_alt: **Red Multicamino (Alta Disponibilidad):** Tu índice de redundancia es del **{redundancy:.1%}**. Es geométricamente complicado que la falla de un solo router o switch aísle la red completa, tienes excelentes rutas redundantes.")
                elif redundancy > 0.4:
                    st.warning(f":material/warning_amber: **Debilidad Estructural Media:** Índice del **{redundancy:.1%}**. El análisis de grafos encontró un diseño híbrido. Ojo con los 'Puntos de Fallo' (nodos obligatorios), porque si se apagan, dividirán temporalmente la red.")
                else:
                    st.error(f":material/emergency: **Arquitectura Centralizada (Estrella Pura):** Índice peligrosamente bajo de **{redundancy:.1%}**. Existen demasiados 'Single Points of Failure' (SPOF). Si el punto central falla por corte eléctrico, la red morirá de inmediato.")
                
                st.info(":material/lightbulb: **Gota de Conocimiento:** Los _Articulation Points_ son los cuellos de botella forzosos. Intenta cruzar más cables (rutas OSPF) hacia otros repetidores para evadir estas caídas y elevar la redundancia garantizando túneles secundarios.")

        st.markdown("---")
        c1, c2, c3 = st.columns(3)
        score_color = "#00FFAA" if spof['redundancy_score'] > 0.7 else "#FFAA00" if spof['redundancy_score'] > 0.4 else "#FF4B4B"
        c1.metric(":material/key: Puntos Únicos de Fallo", spof['total_spof'])
        c2.metric("🌉 Enlaces de Cristal (Puentes)", spof['total_bridges'])
        c3.markdown(f"""
        <div class="health-gauge" style="border-top: 3px solid {score_color}; padding: 15px;">
            <p class="kpi-label">Factor de Resiliencia</p>
            <p class="health-grade" style="color: {score_color}; font-size: 36px;">{spof['redundancy_score']:.1%}</p>
        </div>""", unsafe_allow_html=True)

        if spof['spof_nodes']:
            st.markdown("#### :material/error: Lista de Puntos de Fallo Críticos (Articulation Points)")
            st.caption("Si cualquiera de estos componentes principales se apaga, la red se parte en pedazos.")
            df_spof = pd.DataFrame(spof['spof_nodes'])
            st.dataframe(df_spof, hide_index=True, use_container_width=True)
        else:
            st.success(":material/task_alt: **Red Blindada:** No se detectaron routers o switches aislantes.")

        if spof['bridges']:
            # st.markdown("#### 🌉 Enlaces Físicos de Alta Necesidad (Bridges)")
            # st.caption("Cables exactos que conectan áreas sin soporte adicional.")
            with st.expander("🌉 Ver Enlaces Físicos sin Respaldo (Bridges)"):
                st.dataframe(pd.DataFrame(spof['bridges']), hide_index=True, use_container_width=True)

        # --- WHAT-IF ---
        st.markdown("---")
        st.markdown("#### :material/science: Modelo Táctico de Propagación de Fallos (What-If Analysis)")
        st.caption("Aislar algorítmicamente un Switch/Enrutador del árbol Spanning Tree (STP) para evaluar la criticidad perimetral.")

        node_options = {}
        for n, data in G.nodes(data=True):
            label = data.get('label', n)
            ntype = data.get('node_type', '')
            if ntype in ('router', 'interface', 'subnet'):
                node_options[f"[{ntype.upper()}] {label}"] = n

        if node_options:
            col_target, col_btn = st.columns([3, 1])
            with col_target:
                selected = st.selectbox(":material/api: Nodo Foco (Objetivo):", list(node_options.keys()), label_visibility="collapsed")
            with col_btn:
                run_sim = st.button(":material/bolt: Ejecutar Catástrofe", type="primary", use_container_width=True)
                
            if run_sim:
                with st.status("💥 Abatiendo nodo. Recalculando ruta en la matriz Spanning Tree...", expanded=True) as status:
                    node_id = node_options[selected]
                    result = simulate_node_failure(G, node_id)
                    import time; time.sleep(0.4) # Dramatic rendering delay

                    sev_colors = {'CRÍTICO': ':material/error:', 'MODERADO': ':material/warning:', 'BAJO': ':material/check_circle:'}
                    sev_icon = sev_colors.get(result['severity'], '⚪')
                    
                    st.write(f"Evaluando matriz de propagación de impacto...")
                    time.sleep(0.3)

                    st.markdown(f"##### {sev_icon} Perfil de Falla en Topología: Nivel {result['severity']}")
                    
                    col_r1, col_r2, col_r3 = st.columns(3)
                    col_r1.metric("Impacto Directo (Rutas)", result['direct_impact'])
                    col_r2.metric("☠️ Usuarios Huérfanos", result['isolated_nodes'])
                    col_r3.metric("Clústers Fragmentados", result['network_fragments'])

                    if result['affected_devices']:
                        st.markdown(f"**Host Terminales Offline si apagas el nodo `{result['removed']}`:**")
                        st.dataframe(pd.DataFrame(result['affected_devices']), hide_index=True, use_container_width=True)
                    else:
                        st.success(":material/task_alt: **Costo Cero.** Su pérdida no afecta a ningún host terminal, se redigiría correctamente.")
                        
                    status.update(label=":material/task_alt: Simulación What-If Exitosamente Finalizada", state="complete", expanded=True)

        # --- SHORTEST PATH ---
        st.markdown("---")
        st.markdown("#### :material/alt_route: Enrutamiento Dinámico Simulativo (OSPF / BGP)")
        st.caption("Encuentra la ruta más corta entre dos nodos y mide la redundancia.")

        all_nodes = {G.nodes[n].get('label', n): n for n in G.nodes()}
        node_names = list(all_nodes.keys())

        if len(node_names) >= 2:
            col_src, col_dst = st.columns(2)
            src_label = col_src.selectbox("Origen:", node_names, index=0)
            dst_label = col_dst.selectbox("Destino:", node_names, index=min(1, len(node_names) - 1))

            if st.button(":material/search: Calcular Ruta"):
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
        st.markdown("### :material/bar_chart: Topología L7 y Mapeo Sankey de Transferencia")
        st.caption("Mapeo Dinámico Heurístico — Consumo de Ancho de Banda (Deep Packet Inspection / Top Talkers)")

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
                            st.error(f":material/warning_amber: **Vulnerabilidad Activa Detectada:** Hay {len(puertos_inseguros)} flujo(s) viajando por puertos no encriptados (80/HTTP, 21/FTP, 23/Telnet). El tráfico puede ser interceptado en texto plano.")
                        else:
                            st.success(":material/task_alt: **Cifrado Fuerte:** Todos los flujos principales detectados utilizan puertos estándar de encriptación (443/HTTPS, etc).")
                        
                        st.info(":material/lightbulb: **Recomendación NOC:** Si detectas un hilo asimétrico masivo hacia un servidor desconocido en el gráfico de arriba, aplica una cola (QoS Queue) temporal al Origen para destapar el embudo.")

            # 3. Datos Tabulares Advanced
            st.markdown("---")
            st.markdown("#### 📋 Matriz Forense de Top Talkers (Lista de Prioridad)")
            st.caption("Tráfico exportado bajo inspección de Capa 4 a Capa 7")
            
            talker_data = []
            for i, t in enumerate(top_talkers[:50]): # Hasta 50 flujos
                t_mb = t.get('total_mb', 0)
                puerto = str(t.get('puerto', ''))
                
                # Clasificador de Severidad (Puramente Visual)
                sev = ":material/check_circle: Normal"
                if t_mb > 500: sev = ":material/error: Crítico"
                elif t_mb > 50: sev = ":material/warning: Elevado"
                
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
        st.markdown("### 📡 Plataforma de Inteligencia Inalámbrica (RF)")
        st.caption("Supervisión de espectro RF, terminales L2 asociadas y huella del contorno BSSID.")

        wifi_ifaces = datos.get('wifi_interfaces', [])
        wifi_neighbors = datos.get('wifi_neighbors', [])

        if wifi_ifaces:
            st.markdown("#### :material/wifi_tethering: Interfaces Wireless del Router")
            df_ifaces = pd.DataFrame(wifi_ifaces)
            st.dataframe(df_ifaces, hide_index=True, use_container_width=True)
        else:
            st.info("Este router no tiene interfaces wireless detectadas, o no es un modelo con Wi-Fi.")

        if wifi_neighbors:
            st.markdown("---")
            st.markdown("#### :material/group: Clientes Wi-Fi Conectados (Registration Table)")
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
                            <span class="map-router-name">:material/smartphone: {client.get('mac', 'N/A')}</span>
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

        st.warning(""":material/warning_amber: **Advertencia:** El escaneo Wi-Fi pone la interfaz temporalmente en modo scan. 
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
                                    <span class="map-router-name">:material/wifi_tethering: {ap.get('ssid', 'Red Oculta')}</span>
                                    <div class="map-router-ip">MAC Vecina (BSSID): {ap.get('bssid', 'N/A')}</div>
                                    <div class="map-router-location" style="color:#FFF;">
                                        :material/schedule: Radio: {ap.get('band', '')} | :material/tv: Frecuencia: {ap.get('frequency', 'N/A')} MHz (Canal {ap.get('channel', 'N/A')})
                                    </div>
                                </div>
                                <div style="text-align: right;">
                                    <span style="color: {signal_color}; font-size: 20px; font-family: 'JetBrains Mono'; font-weight: 700;">{signal}</span>
                                    <div class="map-router-location" style="margin-top:4px;">:material/key: Seg: {ap.get('security', 'Abierta (Insegura)')}</div>
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
