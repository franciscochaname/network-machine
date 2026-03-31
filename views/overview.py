import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime, timedelta
from database.db_models import SessionLocal, TrafficSnapshot

def render_overview(router_db, datos):
    st.title(f"Vista General — {router_db.name}")

    info = datos.get('info', {})
    cpu = info.get('cpu_load', 0)
    ram_libre = int(info.get('free_memory', 0)) / 1048576
    ram_total = int(info.get('total_memory', 0)) / 1048576 if info.get('total_memory') else ram_libre + 256
    ram_pct = ((ram_total - ram_libre) / ram_total) * 100 if ram_total > 0 else 0
    total_rx = datos.get('total_rx', 0)
    total_tx = datos.get('total_tx', 0)
    conn_act = datos.get('sec', {}).get('conexiones_activas', 0)
    max_conn = datos.get('sec', {}).get('max_conexiones', 300000)
    conn_pct = (conn_act / max_conn) * 100
    temp = info.get('temperature', 'N/A')
    uptime = info.get('uptime', '0s')
    version = info.get('version', 'N/A')
    board = info.get('board_name', 'N/A')
    arch = info.get('architecture_name', 'N/A')

    # === ROW 0: HEALTH SCORE + STATUS BAR ===
    hs = st.session_state.get('health_score')
    col_health, col_status = st.columns([1, 3])

    with col_health:
        if hs:
            # Health Score compacto con desglose
            breakdown_html = ""
            for k, v in hs['breakdown'].items():
                bar_color = "#00FFAA" if v >= 80 else "#FFAA00" if v >= 50 else "#FF4B4B"
                breakdown_html += f"""
                <div class="health-item">
                    <span class="health-item-label">{k}</span>
                    <span class="health-item-value" style="color: {bar_color};">{v:.0f}</span>
                </div>"""

            st.markdown(f"""
            <div class="health-gauge" style="border-top: 3px solid {hs['color']};">
                <p class="kpi-label">Network Health</p>
                <p class="health-grade" style="color: {hs['color']};">{hs['grade']}</p>
                <p style="color: {hs['color']}; font-size: 22px; font-family: 'JetBrains Mono', monospace; margin: 0;">
                    {hs['total']}<span style="font-size: 14px; color: #555;">/100</span>
                </p>
                <p class="health-label">{hs['label']}</p>
                <div class="health-breakdown">{breakdown_html}</div>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.info("Sincronizando...")

    with col_status:
        # Formatear temperatura para evitar N/A°C
        temp_disp = f"{temp}°C" if temp != "N/A" else "N/A"
        reboot_disp = info.get('last_reboot', '---')

        st.markdown(f"""
        <div class="status-bar">
            <div style="display: flex; align-items: center; gap: 6px;">
                <div class="status-dot-online"></div>
                <span class="status-label">ONLINE</span>
            </div>
            <span class="status-sep">|</span>
            <span class="status-label">⏱️ Uptime: <strong class="status-value">{uptime}</strong></span>
            <span class="status-sep">|</span>
            <span class="status-label">🔧 RouterOS <strong class="status-value">{version}</strong></span>
            <span class="status-sep">|</span>
            <span class="status-label">🌡️ <strong class="status-value">{temp_disp}</strong></span>
            <span class="status-sep">|</span>
            <span class="status-label">🕒 Reinicio: <strong class="status-value">{reboot_disp}</strong></span>
            <span class="status-sep">|</span>
            <span class="status-label">🖥️ <strong class="status-value">{board}</strong></span>
        </div>
        """, unsafe_allow_html=True)

        # KPI Cards dentro de la columna de status
        def crear_kpi(titulo, valor, sufijo, pct, color):
            return f"""
            <div class="kpi-card" style="border-top: 3px solid {color};">
                <p class="kpi-label">{titulo}</p>
                <p class="kpi-value">{valor} <span class="kpi-suffix">{sufijo}</span></p>
                <div class="kpi-bar">
                    <div class="kpi-fill" style="width: {min(pct, 100)}%; background: {color};"></div>
                </div>
            </div>"""

        color_cpu = "#FF4B4B" if cpu > 80 else "#00FFAA" if cpu < 50 else "#FFAA00"
        color_ram = "#FF4B4B" if ram_pct > 80 else "#FFAA00" if ram_pct > 50 else "#00FFAA"

        c1, c2, c3, c4 = st.columns(4)
        with c1: st.markdown(crear_kpi("Carga CPU", f"{cpu}", "%", cpu, color_cpu), unsafe_allow_html=True)
        with c2: st.markdown(crear_kpi("Uso RAM", f"{ram_pct:.1f}", "%", ram_pct, color_ram), unsafe_allow_html=True)
        with c3: st.markdown(crear_kpi("Descarga", f"{total_rx:.1f}", "Mbps", min((total_rx / 100) * 100, 100), "#00F0FF"), unsafe_allow_html=True)
        with c4: st.markdown(crear_kpi("Firewall", f"{conn_act:,}", "Conn", conn_pct, "#B100FF"), unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # === ROW 1: GRÁFICO EN VIVO + APPS + USUARIOS ===
    col_grafico, col_apps, col_usuarios = st.columns([2.6, 1.4, 1.2])

    with col_grafico:
        col_title, col_chart_type = st.columns([2, 1])
        col_title.markdown("<h4 style='color: #ddd; margin-bottom: 5px;'>🚀 Tráfico en Vivo</h4>", unsafe_allow_html=True)
        chart_type_live = col_chart_type.radio("Gráfico en vivo:", ["Líneas", "Áreas", "Barras"], index=1, key="live_chart_type", horizontal=True, label_visibility="collapsed")
        
        fig = go.Figure()
        
        if chart_type_live == "Barras":
            fig.add_trace(go.Bar(
                x=st.session_state['hist_time'], y=st.session_state['hist_rx'],
                name='⬇ Rx Total', marker_color='#00F0FF'
            ))
            fig.add_trace(go.Bar(
                x=st.session_state['hist_time'], y=st.session_state['hist_tx'],
                name='⬆ Tx Total', marker_color='#FF007F'
            ))
        else:
            fill_mode = 'tozeroy' if chart_type_live == "Áreas" else 'none'
            fig.add_trace(go.Scatter(
                x=st.session_state['hist_time'], y=st.session_state['hist_rx'],
                mode='lines+markers', name='⬇ Rx Total',
                line=dict(color='#00F0FF', width=3, shape='spline'),
                fill=fill_mode, fillcolor='rgba(0, 240, 255, 0.08)' if fill_mode == 'tozeroy' else 'rgba(0,0,0,0)',
                marker=dict(size=6, color='#00F0FF', line=dict(width=1, color='#0D0F14'))
            ))
            fig.add_trace(go.Scatter(
                x=st.session_state['hist_time'], y=st.session_state['hist_tx'],
                mode='lines+markers', name='⬆ Tx Total',
                line=dict(color='#FF007F', width=3, shape='spline'),
                fill=fill_mode, fillcolor='rgba(255, 0, 127, 0.08)' if fill_mode == 'tozeroy' else 'rgba(0,0,0,0)',
                marker=dict(size=6, color='#FF007F', line=dict(width=1, color='#0D0F14'))
            ))

        fig.update_layout(
            template='plotly_dark', height=300,
            margin=dict(l=10, r=10, t=10, b=10),
            xaxis=dict(showgrid=False, color='#555'),
            yaxis=dict(showgrid=True, gridcolor='rgba(255,255,255,0.03)', title="Mbps", color='#555'),
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1, font=dict(size=11, color='#888')),
            barmode='group' if chart_type_live == "Barras" else None
        )
        st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})

    with col_apps:
        st.markdown("<h4 style='color: #ddd; margin-bottom: 5px;'>🚦 Actividad L7 (Top)</h4>", unsafe_allow_html=True)
        
        # Carga MANUAL de L7 para no frenar la vista principal
        talkers = datos.get('top_talkers', [])
        
        if not talkers:
            st.info("💡 Análisis L7 en espera para optimizar carga.")
            if st.button("🔍 Escanear Actividad L7 (DNS/Host)", use_container_width=True):
                # Usar el RouterManager directamente o forzar refresco
                st.session_state['force_l7'] = True
                st.rerun()
            apps = []
        else:
            # Calcular suma total de bytes de los top talkers para sacar porcentajes
            suma_bytes = sum([t['bytes'] for t in talkers]) or 1 # Evitar div by 0
            
            from core.ip_tools import classify_ip
            apps = []
            for i, t in enumerate(talkers):
                ip_src = t['ip']
                bytes_t = t['bytes']
                mb_t = bytes_t / (1024 * 1024)
                pct = (bytes_t / suma_bytes) * 100
                icon = "💻"
                color = ["#FF0000", "#E50914", "#1877F2", "#00F0FF", "#2D8CFF"][i % 5]
                name = f"Host {ip_src.split('.')[-1]}"
                
                apps.append({
                    "name": name, "icon": icon, "color": color, "pct": pct,
                    "time": f"{int(mb_t * 2) or 1} mins", "ip": ip_src
                })
        
        def generar_desglose_app(app_name, icon, color, pct_total):
            st.markdown(f"<h3 style='color: {color}; margin-top:0;'>{icon} Top Talker: {app_name}</h3>", unsafe_allow_html=True)
            st.caption(f"Este dispositivo está consumiendo el {pct_total}% del tráfico activo de la red.")
            
            import pandas as pd
            
            mac = "Desconocida"
            host = "Host Estático / Oculto"
            tipo_conn = "🔌 Ethernet"
            encontrado = False
            
            # Buscar cliente en DHCP (dinámico)
            if 'dhcp' in datos and len(datos['dhcp']) > 0:
                for u in datos['dhcp']:
                    if u.get('address') == app_name or u.get('active-address') == app_name:
                        mac = u.get('mac-address', u.get('active-mac-address', 'Desconocida')).upper()
                        host = u.get('host-name', 'Sin Nombre (Oculto)')
                        srv = str(u.get('server', '')).lower()
                        if 'wifi' in srv or 'wlan' in srv:
                            tipo_conn = "🛜 Wi-Fi"
                        encontrado = True
                        break
                        
            # Si no se encontró (es estático), buscar su MAC en la tabla ARP
            if not encontrado and 'arp_table' in datos:
                mac_arp = datos['arp_table'].get(app_name, "Desconocida").upper()
                if mac_arp != "DESCONOCIDA":
                    mac = mac_arp
                    if host == "Host Estático / Oculto":
                        host = "Dispositivo Estático"
                    encontrado = True

            # Detección definitiva de Medio (Wi-Fi vs LAN) cruzando con clientes Wireless Registrados
            if not tipo_conn.startswith("🛜") and 'wifi_neighbors' in datos:
                macs_wifi = [w.get('mac', '') for w in datos['wifi_neighbors'] if 'mac' in w]
                if mac in macs_wifi:
                    tipo_conn = "🛜 Wi-Fi (Detectado)"
                        
            desglose = [{
                "Host (Equipo)": host,
                "MAC Address": mac,
                "IP Cliente": app_name,
                "Conexión": tipo_conn,
                "Status": "🟢 Descargando Tráfico (Ráfaga)"
            }]
                
            # Desglose L7
            dominios = []
            if talkers:
                 for t in talkers:
                      if t.get('ip') == app_name and 'domains' in t:
                           dominios = t['domains']
                           break

            df_g = pd.DataFrame(desglose)
            st.dataframe(df_g, hide_index=True, use_container_width=True)
            
            def traducir_dominio(url):
                import re, socket
                if re.match(r'^\d+\.\d+\.\d+\.\d+$', url):
                    try:
                        socket.setdefaulttimeout(0.3)
                        url = socket.gethostbyaddr(url)[0]
                    except Exception:
                        pass
                url_b = url.lower()
                mapa = {
                    'googlevideo': 'YouTube 🟥', 'youtube': 'YouTube 🟥', 'ytimg': 'YouTube 🟥',
                    'nflx': 'Netflix 🎬', 'netflix': 'Netflix 🎬',
                    'fbcdn': 'Facebook 🟦', 'facebook': 'Facebook 🟦',
                    'instagram': 'Instagram 📸', 'cdninstagram': 'Instagram 📸',
                    'whatsapp': 'WhatsApp 🟩', 'wa.net': 'WhatsApp 🟩',
                    'tiktok': 'TikTok 🎵', 'ttvnw': 'TikTok 🎵', 'byteoversea': 'TikTok 🎵', 'tiktokcdn': 'TikTok 🎵',
                    'zoom': 'Zoom 💼', 'office': 'Microsoft Office 🪟', 'microsoft': 'Microsoft 🪟', 'live': 'Microsoft 🪟',
                    'apple': 'Apple 🍏', 'icloud': 'Apple iCloud ☁️',
                    'spotify': 'Spotify 🟢', 'steam': 'Steam Games 🎮', 'epicgames': 'Epic Games 🎮',
                    'twitch': 'Twitch 🟪', 'discord': 'Discord 👾',
                    'twitter': 'Twitter / X 🐦', 'twimg': 'Twitter / X 🐦',
                    'google': 'Google 🔍', 'gstatic': 'Google Services 🧩', '1e100': 'Google Services 🧩',
                    'cloudflare': 'Cloudflare CDN 🌩️', 'akamai': 'Akamai CDN 🌍', 'fastly': 'Fastly CDN ⚡',
                    'amazon': 'Amazon 🛒', 'aws': 'AWS Cloud ☁️',
                    'xvideos': 'Adult 🔞', 'pornhub': 'Adult 🔞'
                }
                for key, val in mapa.items():
                    if key in url_b:
                        return f"{val} ({url})"
                return f"Servidor Web 🌐 ({url})"

            if dominios:
                 st.markdown("<h5 style='color:#ccc; margin-top: 15px;'>🌐 Páginas y Servicios Visitados</h5>", unsafe_allow_html=True)
                 with st.spinner("⏳ Analizando e interpretando paquetes de Capa 7 (Tráfico Web)..."):
                     df_dom = pd.DataFrame([{
                         "Página/Servicio Detectado": traducir_dominio(d['domain']), 
                         "Tiempo Estimado": f"⏱️ {d.get('mins_est', 1)} min(s)"
                     } for d in dominios])
                 
                 st.dataframe(df_dom, hide_index=True, use_container_width=True)
                 st.info("💡 Info: Traducción de CDNs y Dominios enrutados mediante Caché DNS del dispositivo.")
            else:
                 st.info("💡 Info: Este dispositivo no tiene páginas web resueltas en la Caché actualmente.")

        if apps:
            apps = sorted(apps, key=lambda x: x['pct'], reverse=True)
            for a in apps:
                btn_label = f"{a['icon']} \u2001 {a['name'].ljust(15)} \u2001 {a['pct']:.1f}% \u2001 ⏬ {a['time']}"
                with st.popover(btn_label, use_container_width=True):
                    generar_desglose_app(a['ip'], a['icon'], a['color'], f"{a['pct']:.1f}")


    with col_usuarios:
        st.markdown("<h4 style='color: #ddd; margin-bottom: 5px;'>👥 Usuarios</h4>", unsafe_allow_html=True)
        usuarios_lan = len(datos.get('dhcp', []))
        usuarios_vpn = len(datos.get('vpns', []))
        total_usuarios = usuarios_lan + usuarios_vpn

        fig_users = go.Figure(data=[go.Pie(
            labels=['LAN', 'VPN'], values=[usuarios_lan, usuarios_vpn],
            hole=.65, marker=dict(colors=['#00FFAA', '#B100FF'], line=dict(color='#0D0F14', width=2))
        )])
        fig_users.update_layout(
            showlegend=False, height=180, margin=dict(l=0, r=0, t=10, b=10),
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            annotations=[dict(text=f"{total_usuarios}<br><span style='font-size:12px;color:#666;'>Total</span>",
                              x=0.5, y=0.5, font_size=20, showarrow=False, font_color="white")]
        )
        st.plotly_chart(fig_users, use_container_width=True, config={'displayModeBar': False})
        st.markdown(f"""
        <div style="background: rgba(0, 255, 170, 0.05); padding: 8px; border-radius: 6px; text-align: center; border: 1px solid rgba(0, 255, 170, 0.2); margin-top: 10px;">
            <span style="color: #00FFAA; font-weight: bold; font-size: 14px;">LAN: {usuarios_lan} activos</span><br>
            <span style="color: #B100FF; font-weight: bold; font-size: 14px;">VPN: {usuarios_vpn} conectados</span>
        </div>
        """, unsafe_allow_html=True)

    # === ROW 2: HISTORIAL PERSISTENTE (desde SQLite) ===
    st.markdown("---")
    st.markdown("<h4 style='color: #ddd;'>📊 Historial de Rendimiento (Persistente)</h4>", unsafe_allow_html=True)

    c_rango, c_tipo = st.columns([2, 1])
    rango = c_rango.radio("Período:", ["Última Hora", "Últimas 6 Horas", "Últimas 24 Horas", "Últimos 7 Días"], index=0, horizontal=True, label_visibility="collapsed")
    chart_type_hist = c_tipo.radio("Tipo de Gráfico:", ["Líneas", "Áreas", "Barras"], index=1, key="hist_chart_type", horizontal=True, label_visibility="collapsed")

    rangos_map = {
        "Última Hora": timedelta(hours=1),
        "Últimas 6 Horas": timedelta(hours=6),
        "Últimas 24 Horas": timedelta(hours=24),
        "Últimos 7 Días": timedelta(days=7)
    }
    desde = datetime.now() - rangos_map[rango]

    try:
        db_hist = SessionLocal()
        snapshots = db_hist.query(TrafficSnapshot).filter(
            TrafficSnapshot.router_id == router_db.id,
            TrafficSnapshot.timestamp >= desde
        ).order_by(TrafficSnapshot.timestamp.asc()).all()
        db_hist.close()

        if snapshots and len(snapshots) >= 1:
            times = [s.timestamp.strftime("%H:%M") if rangos_map[rango] <= timedelta(hours=6)
                     else s.timestamp.strftime("%d/%m %H:%M") for s in snapshots]
            rxs = [s.total_rx for s in snapshots]
            txs = [s.total_tx for s in snapshots]
            cpus = [s.cpu_load for s in snapshots]
            healths = [s.health_score for s in snapshots]

            col_g1, col_g2 = st.columns(2)

            with col_g1:
                fig_h = go.Figure()
                if chart_type_hist == "Barras":
                    fig_h.add_trace(go.Bar(x=times, y=rxs, name='Rx', marker_color='#00F0FF'))
                    fig_h.add_trace(go.Bar(x=times, y=txs, name='Tx', marker_color='#FF007F'))
                else:
                    fill_m = 'tozeroy' if chart_type_hist == "Áreas" else 'none'
                    fig_h.add_trace(go.Scatter(x=times, y=rxs, name='Rx', line=dict(color='#00F0FF', width=2, shape='spline'), fill=fill_m, fillcolor='rgba(0,240,255,0.05)' if fill_m == 'tozeroy' else 'rgba(0,0,0,0)'))
                    fig_h.add_trace(go.Scatter(x=times, y=txs, name='Tx', line=dict(color='#FF007F', width=2, shape='spline'), fill=fill_m, fillcolor='rgba(255,0,127,0.05)' if fill_m == 'tozeroy' else 'rgba(0,0,0,0)'))
                
                fig_h.update_layout(template='plotly_dark', height=220, margin=dict(l=10, r=10, t=10, b=10),
                                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                                    yaxis=dict(title="Mbps", gridcolor='rgba(255,255,255,0.03)'),
                                    xaxis=dict(showgrid=False),
                                    legend=dict(orientation="h", y=1.1, font=dict(size=10, color='#888')),
                                    barmode='group' if chart_type_hist == "Barras" else None)
                st.plotly_chart(fig_h, use_container_width=True, config={'displayModeBar': False})

            with col_g2:
                fig_c = go.Figure()
                if chart_type_hist == "Barras":
                    fig_c.add_trace(go.Bar(x=times, y=cpus, name='CPU %', marker_color='#FFAA00'))
                    fig_c.add_trace(go.Bar(x=times, y=healths, name='Health Score', marker_color='#00FFAA'))
                else:
                    fill_m = 'tozeroy' if chart_type_hist == "Áreas" else 'none'
                    fig_c.add_trace(go.Scatter(x=times, y=cpus, name='CPU %', line=dict(color='#FFAA00', width=2, shape='spline'), fill=fill_m, fillcolor='rgba(255,170,0,0.05)' if fill_m == 'tozeroy' else 'rgba(0,0,0,0)'))
                    fig_c.add_trace(go.Scatter(x=times, y=healths, name='Health Score', line=dict(color='#00FFAA', width=2, shape='spline'), fill=fill_m, fillcolor='rgba(0,255,170,0.05)' if fill_m == 'tozeroy' else 'rgba(0,0,0,0)'))

                fig_c.update_layout(template='plotly_dark', height=220, margin=dict(l=10, r=10, t=10, b=10),
                                    paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                                    yaxis=dict(title="Valor", gridcolor='rgba(255,255,255,0.03)'),
                                    xaxis=dict(showgrid=False),
                                    legend=dict(orientation="h", y=1.1, font=dict(size=10, color='#888')),
                                    barmode='group' if chart_type_hist == "Barras" else None)
                st.plotly_chart(fig_c, use_container_width=True, config={'displayModeBar': False})
        else:
            st.info("📊 Aún no hay suficientes datos históricos. Se acumularán con cada sincronización automática.")
    except Exception as e:
        st.info(f"📊 El historial se construirá con cada sincronización.")

    # === ROW 3: INTERFACES ACTIVAS ===
    st.markdown("---")
    st.markdown("<h4 style='color: #ddd;'>📡 Interfaces Activas (Auto-Detectadas)</h4>", unsafe_allow_html=True)

    traffic_list = datos.get('traffic_list', [])
    if traffic_list:
        cols = st.columns(min(len(traffic_list), 6))
        for idx, iface in enumerate(traffic_list):
            with cols[idx % len(cols)]:
                rx_val = iface['rx']
                border_color = "#FF4B4B" if rx_val > 20 else "#FFAA00" if rx_val > 5 else "#B100FF"
                st.markdown(f"""
                <div class="iface-card" style="border-top: 3px solid {border_color};">
                    <h4 class="iface-name">{iface['name']}</h4>
                    <div class="iface-rx">⬇ {iface['rx']} <span class="iface-unit">Mbps</span></div>
                    <div class="iface-tx">⬆ {iface['tx']} <span class="iface-unit">Mbps</span></div>
                </div>
                """, unsafe_allow_html=True)
    else:
        st.info("No se detectó tráfico significativo (> 50 kbps) en ningún puerto en este instante.")

    # === ROW 4: DIAGNÓSTICO ÓPTICO / SEÑAL (NUEVO) ===
    sfp_data = datos.get('sfp_diagnostics', [])
    if sfp_data:
        st.markdown("---")
        st.markdown("<h4 style='color: #ddd;'>🔦 Diagnóstico de Enlace Físico (SFP / LTE)</h4>", unsafe_allow_html=True)
        df_sfp = pd.DataFrame(sfp_data)
        st.dataframe(df_sfp, use_container_width=True, hide_index=True)