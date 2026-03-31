import streamlit as st
import pandas as pd
import plotly.graph_objects as go  # <--- NUEVA LIBRERÍA DE GRÁFICOS VIP
from database.db_models import SessionLocal, ActivoVIP, Router

# ==========================================
# 1. VENTANA MODAL DE CONFIRMACIÓN (QoS MASIVO)
# ==========================================
@st.dialog("🚦 Panel Táctico de QoS (Control de Masas)")
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
    
    st.info(f"💡 Al aplicar este cambio, dejarás **{max_linea_mbps - nueva_vel} Mbps** libres para el resto de la empresa.")
    
    # Botón de Confirmación
    if st.button("✅ Confirmar y Aplicar en MikroTik", type="primary"):
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
    st.title(f"🧠 Inteligencia AIOps - {router_db.name}")
    st.markdown("Centro de Operaciones de Seguridad (SOC) y Análisis de Tráfico")

    db = SessionLocal()
    activos_vip = db.query(ActivoVIP).filter(ActivoVIP.router_id == router_db.id).all()
    lista_ips_vip = [activo.ip_address for activo in activos_vip]
    db.close()

    tab_radar, tab_topo, tab_vip = st.tabs(["📡 Radar de Anomalías", "🛰️ Topología Lógica", "💎 Gestión de Activos VIP"])

    with tab_topo:
        st.markdown("### 🕸️ Arquitectura Lógica de la Infraestructura")
        st.markdown("Esta vista representa las conexiones entre tus equipos y sus capacidades de hardware.")
        
        # 1. Recolección de Nodos
        db_topo = SessionLocal()
        routers_topo = db_topo.query(Router).all()
        db_topo.close()
        
        if routers_topo:
            # Creamos el gráfico con Plotly
            edge_x = []
            edge_y = []
            node_x = []
            node_y = []
            node_text = []
            node_color = []
            node_size = []
            node_symbols = []

            # Simulamos un layout circular o aleatorio basado en el ID
            import math
            for i, r in enumerate(routers_topo):
                angle = (i / len(routers_topo)) * 2 * math.pi
                radius = 1 # Radio
                x = radius * math.cos(angle)
                y = radius * math.sin(angle)
                
                # Nodos
                node_x.append(x)
                node_y.append(y)
                
                # Propiedades dinámicas
                is_connected = (st.session_state.get('nodo_actual') == r.ip_address)
                # Si el router tiene AP (usamos info de la telemetría si está conectada)
                has_ap = False
                if is_connected and st.session_state.get('telemetria'):
                     has_ap = st.session_state['telemetria']['info'].get('has_ap', False)
                
                color = "#00FFAA" if is_connected else "#00F0FF"
                symbol = "square" if not has_ap else "star" # Diferenciamos APs con Estrellas
                
                node_color.append(color)
                node_symbols.append(symbol)
                node_size.append(30 if is_connected else 20)
                
                ap_tag = "(Access Point 📶)" if has_ap else ""
                node_text.append(f"<b>{r.name}</b><br>{r.ip_address}<br>{ap_tag}<br>📍 {r.location}")

            # Enlaces (Simulamos enlaces VPN estrella a un hub si existe, o mesh)
            # Para la representación, conectamos todos al primero o en cadena
            if len(node_x) > 1:
                for i in range(len(node_x) - 1):
                    edge_x.extend([node_x[i], node_x[i+1], None])
                    edge_y.extend([node_y[i], node_y[i+1], None])

            edge_trace = go.Scatter(x=edge_x, y=edge_y, line=dict(width=1, color='rgba(255,255,255,0.2)'), hoverinfo='none', mode='lines')
            
            node_trace = go.Scatter(
                x=node_x, y=node_y, mode='markers+text',
                text=[r.name for r in routers_topo], textposition="bottom center",
                hoverinfo='text', hovertext=node_text,
                marker=dict(
                    showscale=False, color=node_color, size=node_size, symbol=node_symbols,
                    line=dict(width=2, color='white')
                )
            )

            fig_topo = go.Figure(data=[edge_trace, node_trace],
                layout=go.Layout(
                    showlegend=False, hovermode='closest',
                    margin=dict(b=0, l=0, r=0, t=0),
                    xaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                    yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)"
                )
            )
            
            st.plotly_chart(fig_topo, use_container_width=True, config={'displayModeBar': False})
            
            st.info("💡 **Guía Rápida:** Los nodos en forma de **Estrella (⭐)** son Access Points. El nodo resaltado es tu conexión actual. Mantén el mouse encima para ver detalles.")
        else:
            st.warning("No hay equipos registrados para construir la topología.")

    with tab_radar:
        st.markdown("### 🕵️‍♂️ Análisis de Tráfico en Tiempo Real")
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
                if ip_origen in lista_ips_vip: return "✅ VIP Autorizado"
                return "⚠️ Inusual"

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
            st.markdown("#### ⚡ Acciones Tácticas Individuales (LAN IP)")
            
            col_target, col_block, col_qos = st.columns([2, 1, 1])
            with col_target:
                ips_origen = df_talkers['IP Origen'].tolist()
                ips_router = datos.get('router_ips', [])
                exclusiones = ['132.251.158.186'] + ips_router 
                ips_seguras = [ip for ip in list(set(ips_origen)) if ip not in exclusiones]
                
                ip_objetivo = st.selectbox("Selecciona una IP:", ["-- Seleccionar IP --"] + ips_seguras, label_visibility="collapsed")
                velocidad_mbps = st.slider("Límite Individual (Mbps)", min_value=1, max_value=50, value=5)

            with col_block:
                if st.button("⛔ Bloquear IP", type="primary"):
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
                if st.button(f"🚦 Estrangular ({velocidad_mbps}M)"):
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
            with st.expander("🏢 Control de Masas (Estrangular Redes o WiFi)", expanded=False):
                st.markdown("Aplica límites de velocidad a toda una sucursal, VLAN o red WiFi de forma segura.")
                
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
            with st.expander("🛡️ Gestionar Lista Negra (Desbloqueo de IPs)", expanded=False):
                blacklist = datos.get('blacklist', [])
                if blacklist:
                    col_b1, col_b2 = st.columns([3, 1])
                    with col_b1:
                        opciones_bl = {f"{b['ip']} ({b['comment']})": b['id'] for b in blacklist}
                        ip_a_desbloquear = st.selectbox("Seleccionar IP a liberar:", ["-- Seleccionar IP --"] + list(opciones_bl.keys()), label_visibility="collapsed")
                    with col_b2:
                        if st.button("✅ Liberar IP"):
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
        st.markdown("### 💎 Base de Datos de Servidores Confiables")
        st.write("Las IPs registradas aquí no serán marcadas como anomalías en el Radar.")
        if lista_ips_vip:
            st.dataframe(pd.DataFrame(lista_ips_vip, columns=["IP Autorizada"]), use_container_width=True)
        else:
            st.info("Aún no has registrado servidores VIP.")