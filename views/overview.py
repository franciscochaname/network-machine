import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime, timedelta
from database.db_models import SessionLocal, TrafficSnapshot

# ──────────────────────────────────────────────
# HELPERS
# ──────────────────────────────────────────────

def _alert_register(severity: str, msg: str):
    if 'alert_history' not in st.session_state:
        st.session_state['alert_history'] = []
    ts = datetime.now().strftime("%H:%M:%S")
    last = st.session_state['alert_history'][0]['msg'] if st.session_state['alert_history'] else ""
    if msg != last:
        st.session_state['alert_history'].insert(0, {'severity': severity, 'msg': msg, 'time': ts})
    st.session_state['alert_history'] = st.session_state['alert_history'][:20]


def _render_alert_panel():
    alerts = st.session_state.get('alert_history', [])
    if not alerts:
        return
    n = len(alerts)
    n_critical = sum(1 for a in alerts if a['severity'] == 'critical')
    badge_icon = "🚨" if n_critical > 0 else "⚠️"
    with st.expander(f"{badge_icon} **ALERTAS ACTIVAS** — {n} evento(s) | {n_critical} crítico(s)", expanded=(n_critical > 0)):
        for a in alerts:
            icon = "🔴" if a['severity'] == 'critical' else "🟡" if a['severity'] == 'warning' else "🔵"
            st.markdown(f"<div class='alert-item'><div class='alert-item-dot {a['severity']}'></div><div class='alert-item-text'><div class='alert-item-msg'>{icon} {a['msg']}</div><div class='alert-item-time'>{a['time']}</div></div></div>", unsafe_allow_html=True)
        if st.button("🗑️ Limpiar historial", use_container_width=True):
            st.session_state['alert_history'] = []
            st.rerun()


def _kpi_card(titulo, valor, sufijo, pct, color, icon, alerta_clase=""):
    css_class = f"kpi-card {alerta_clase}"
    return f"""
    <div class="{css_class}" style="border-top: 3px solid {color}; height: 100%; transition: transform 0.2s ease; padding-bottom:30px;">
        <p class="kpi-label"><span class="live-dot"></span>{titulo}</p>
        <p class="kpi-value">{valor} <span class="kpi-suffix">{sufijo}</span></p>
        <div class="kpi-bar"><div class="kpi-fill" style="width: {min(pct, 100)}%; background: {color};"></div></div>
    </div>"""


def _gauge_health_score(hs: dict) -> go.Figure:
    score = hs['total']
    color = hs['color']
    fig = go.Figure(go.Indicator(
        mode="gauge+number+delta", value=score,
        number={'font': {'size': 36, 'color': color, 'family': 'JetBrains Mono'}, 'suffix': '/100'},
        delta={'reference': 70, 'increasing': {'color': '#00FFAA'}, 'decreasing': {'color': '#FF4B4B'}, 'font': {'size': 12}},
        gauge={
            'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': '#333', 'tickvals': [0, 25, 50, 75, 100], 'tickfont': {'size': 9, 'color': '#555'}},
            'bar': {'color': color, 'thickness': 0.25}, 'bgcolor': 'rgba(0,0,0,0)', 'borderwidth': 0,
            'steps': [{'range': [0, 30], 'color': 'rgba(255,75,75,0.12)'}, {'range': [30, 50], 'color': 'rgba(255,107,53,0.10)'},
                      {'range': [50, 70], 'color': 'rgba(255,170,0,0.10)'}, {'range': [70, 85], 'color': 'rgba(0,240,255,0.08)'},
                      {'range': [85, 100], 'color': 'rgba(0,255,170,0.10)'}],
            'threshold': {'line': {'color': color, 'width': 3}, 'thickness': 0.8, 'value': score}
        },
        title={'text': f"<b>{hs['grade']}</b> · {hs['label']}", 'font': {'size': 13, 'color': '#888'}}
    ))
    fig.update_layout(height=190, margin=dict(l=15, r=15, t=30, b=10), paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font={'family': 'Inter, sans-serif'})
    return fig


def _get_history(router_id, limit=30):
    """Lee historial desde SQLite."""
    try:
        db = SessionLocal()
        snaps = db.query(TrafficSnapshot).filter(TrafficSnapshot.router_id == router_id).order_by(TrafficSnapshot.timestamp.desc()).limit(limit).all()
        db.close()
        return list(reversed(snaps))
    except Exception:
        return []


# ──────────────────────────────────────────────
# DIALOGS (Ventanas emergentes profesionales)
# ──────────────────────────────────────────────

@st.dialog("⚙️ Historial de CPU — Análisis Detallado", width="large")
def _dialog_cpu(router_id, cpu_actual, board, uptime):
    snaps = _get_history(router_id)
    cpu_vals = [s.cpu_load for s in snaps]
    cpu_times = [s.timestamp.strftime("%H:%M") for s in snaps]

    c1, c2, c3 = st.columns(3)
    c1.metric("CPU Actual", f"{cpu_actual}%")
    if cpu_vals:
        c2.metric("Promedio", f"{sum(cpu_vals)/len(cpu_vals):.1f}%")
        c3.metric("Pico Máximo", f"{max(cpu_vals)}%")
    else:
        c2.metric("Promedio", "---")
        c3.metric("Pico", "---")

    if cpu_vals and len(cpu_vals) >= 2:
        color = "#FF4B4B" if cpu_actual > 80 else "#FFAA00" if cpu_actual > 60 else "#00FFAA"
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=cpu_times, y=cpu_vals, mode='lines+markers', name='CPU %',
            line=dict(color=color, width=2, shape='spline'), fill='tozeroy', fillcolor=f'rgba(0,240,255,0.06)',
            marker=dict(size=5, color=color)))
        avg = sum(cpu_vals) / len(cpu_vals)
        fig.add_hline(y=avg, line_dash='dot', annotation_text=f'Avg {avg:.1f}%', line_color='rgba(255,255,255,0.2)', annotation_font_color='#888')
        fig.add_hline(y=80, line_dash='dash', annotation_text='Crítico 80%', line_color='rgba(255,75,75,0.4)', annotation_font_color='#FF4B4B')
        fig.update_layout(template='plotly_dark', height=250, margin=dict(l=10, r=10, t=10, b=10),
            paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', showlegend=False, yaxis=dict(range=[0, 105]))
        st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})
    else:
        st.info("Acumulando datos históricos... Se registra con cada sincronización.")

    st.markdown("---")
    st.caption(f"📋 Board: **{board}** | Uptime: **{uptime}** | Muestras: **{len(cpu_vals)}**")
    if cpu_actual > 80:
        st.error("🚨 CPU en estado CRÍTICO — Verificar procesos y reglas de firewall pesadas.")
    elif cpu_actual > 60:
        st.warning("⚠️ CPU en carga elevada.")
    else:
        st.success("✅ CPU en rango operativo normal.")


@st.dialog("🧠 Historial de Memoria RAM — Análisis Detallado", width="large")
def _dialog_ram(router_id, ram_pct, ram_libre, ram_total):
    snaps = _get_history(router_id)
    ram_vals = [s.ram_pct for s in snaps]
    ram_times = [s.timestamp.strftime("%H:%M") for s in snaps]

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("RAM Usada", f"{ram_pct:.1f}%")
    c2.metric("Libre", f"{ram_libre:.0f} MB")
    c3.metric("Total", f"{ram_total:.0f} MB")
    if ram_vals:
        c4.metric("Pico", f"{max(ram_vals):.1f}%")

    if ram_vals and len(ram_vals) >= 2:
        color = "#FF4B4B" if ram_pct > 80 else "#FFAA00" if ram_pct > 60 else "#00FFAA"
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=ram_times, y=ram_vals, mode='lines+markers', name='RAM %',
            line=dict(color=color, width=2, shape='spline'), fill='tozeroy', fillcolor='rgba(255,170,0,0.06)',
            marker=dict(size=5, color=color)))
        fig.add_hline(y=80, line_dash='dash', annotation_text='Umbral 80%', line_color='rgba(255,75,75,0.4)', annotation_font_color='#FF4B4B')
        fig.update_layout(template='plotly_dark', height=250, margin=dict(l=10, r=10, t=10, b=10),
            paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', showlegend=False, yaxis=dict(range=[0, 105]))
        st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})
    else:
        st.info("Acumulando datos históricos...")

    st.markdown("---")
    st.caption("Los datos persisten en SQLite. Una RAM saturada >90% causará dropped packets.")
    if ram_pct > 80:
        st.error("🚨 RAM CRÍTICA — Considerar reinicio o liberación de caché.")
    elif ram_pct > 60:
        st.warning("⚠️ Consumo de memoria elevado.")
    else:
        st.success("✅ Memoria en rango saludable.")

@st.dialog("📈 Historial de Tráfico (Interface Principal)", width="large")
def _dialog_traffic(router_id, traffic_list, total_rx, total_tx):
    import time
    c1, c2, c3 = st.columns(3)
    c1.metric("Descarga Total", f"{total_rx:.1f} Mbps")
    c2.metric("Subida Total", f"{total_tx:.1f} Mbps")
    c3.metric("Ancho de Banda Máx", "No especificado")
    st.markdown("---")
    
    hist_time = st.session_state.get('hist_time', [])
    hist_rx = st.session_state.get('hist_rx', [])
    hist_tx = st.session_state.get('hist_tx', [])
    
    if len(hist_rx) > 2:
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=hist_time, y=hist_rx, mode='lines', name='Descarga (Rx)', fill='tozeroy', line=dict(color='#00F0FF')))
        fig.add_trace(go.Scatter(x=hist_time, y=hist_tx, mode='lines', name='Subida (Tx)', fill='tozeroy', line=dict(color='#FF007F')))
        fig.update_layout(template='plotly_dark', height=250, margin=dict(l=10,r=10,t=10,b=10), paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)')
        st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})
    else:
        st.info("Acumulando métricas de paso de datos históricos...")

@st.dialog("🛡️ Análisis Táctico Firewall L4/L7", width="large")
def _dialog_firewall(router_id, conn_act, conn_pct, max_conn, datos):
    c1, c2, c3 = st.columns(3)
    c1.metric("Conexiones Activas", f"{conn_act:,}")
    c2.metric("Límite Teórico", f"{max_conn:,}")
    c3.metric("Saturación NAT", f"{conn_pct:.1f}%")
    st.markdown("---")
    
    snaps = _get_history(router_id)
    if len(snaps) > 2:
        conn_vals = [s.connections for s in snaps]
        conn_times = [s.timestamp.strftime("%H:%M") for s in snaps]
        fig = go.Figure()
        fig.add_trace(go.Scatter(x=conn_times, y=conn_vals, mode='lines', name='Conn/s', line=dict(color='#B100FF')))
        fig.update_layout(template='plotly_dark', height=250, margin=dict(l=10,r=10,t=10,b=10), paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)')
        st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})
    
    if st.button("🔴 Ejecutar Purga de Conexiones (Drop All Unestablished)"):
        st.warning("Comando táctico emitido. Se purgarán flujos UDP muertos.")

@st.dialog("📡 Detalles de Interfaz Física L1", width="small")
def _dialog_trunk_details(iface):
    st.markdown(f"### Interfaz: {iface.get('name', 'N/A')}")
    col1, col2 = st.columns(2)
    rx = iface.get('rx', 0)
    tx = iface.get('tx', 0)
    col1.metric("⬇️ Descarga Actual", f"{rx} Mbps")
    col2.metric("⬆️ Subida Actual", f"{tx} Mbps")
    st.info("El tráfico dinámico es el flujo instantáneo cruzando este puerto físico.")

@st.dialog("🛡️ Detalles de Túnel VPN (L3)", width="small")
def _dialog_vpn_details(v_data):
    st.markdown(f"### Túnel: {v_data.get('name', v_data.get('user', 'Desconocido'))}")
    col1, col2 = st.columns(2)
    col1.metric("Endpoint", v_data.get('address', v_data.get('caller-id', 'N/A')))
    col2.metric("Estado", v_data.get('uptime', 'Activo'))
    st.success("Canal Seguro Establecido (Cifrado Point-to-Point).")

@st.dialog("🔴 Detalles del Vecino de Red L2", width="small")
def _dialog_ap_details(w_data):
    st.markdown(f"### Nodo L2: {w_data.get('identity', 'Dispositivo')}")
    st.caption(f"Hardware: {w_data.get('platform', 'Genérico')} {w_data.get('board', '')}")
    col1, col2 = st.columns(2)
    col1.metric("IP de Gestión", w_data.get('address', 'Sin IP'))
    col2.metric("Puerto LAN", w_data.get('interface', 'N/A'))
    st.info("Punto de puente u Host detectado vía descubrimiento CDP/MNDP/LLDP.")


@st.dialog("📥 Tráfico L3 por Interfaz — Troncales Físicas", width="large")
def _dialog_traffic(router_id, traffic_list, total_rx, total_tx):
    c1, c2 = st.columns(2)
    c1.metric("⬇️ Descarga Total", f"{total_rx:.2f} Mbps")
    c2.metric("⬆️ Subida Total", f"{total_tx:.2f} Mbps")

    if traffic_list:
        chart_sel = st.radio("Tipo de gráfico:", ["Barras", "Líneas", "Pastel"], horizontal=True, label_visibility="collapsed")
        names = [i['name'] for i in traffic_list]
        rx = [i['rx'] for i in traffic_list]
        tx = [i['tx'] for i in traffic_list]
        fig = go.Figure()

        if chart_sel == "Barras":
            fig.add_trace(go.Bar(name='Rx (↓)', x=names, y=rx, marker_color='#00F0FF', opacity=0.85))
            fig.add_trace(go.Bar(name='Tx (↑)', x=names, y=tx, marker_color='#FF007F', opacity=0.85))
            fig.update_layout(barmode='group')
        elif chart_sel == "Líneas":
            fig.add_trace(go.Scatter(name='Rx (↓)', x=names, y=rx, mode='lines+markers', line=dict(color='#00F0FF', width=3)))
            fig.add_trace(go.Scatter(name='Tx (↑)', x=names, y=tx, mode='lines+markers', line=dict(color='#FF007F', width=3)))
        else:
            vol = [a + b for a, b in zip(rx, tx)]
            fig.add_trace(go.Pie(labels=names, values=vol, hole=0.5, textinfo='percent', textposition='inside',
                marker=dict(colors=['#00F0FF', '#FF007F', '#B100FF', '#FFAA00', '#00FFAA', '#FF6B35'], line=dict(color='#0D0F14', width=2))))

        fig.update_layout(template='plotly_dark', height=300, margin=dict(l=10, r=10, t=10, b=10),
            paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
            yaxis=dict(title='Mbps') if chart_sel != "Pastel" else None,
            showlegend=True, legend=dict(orientation='h', y=1.1, font=dict(size=10)))
        st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})

        st.markdown("---")
        st.markdown("##### 📊 Detalle por Troncal")
        df = pd.DataFrame([{"Interfaz": i['name'], "Rx (Mbps)": f"{i['rx']:.2f}", "Tx (Mbps)": f"{i['tx']:.2f}",
            "Total": f"{i['rx']+i['tx']:.2f}", "Estado": "🟢 Activa" if i['rx'] > 0.05 else "⚪ Idle"} for i in traffic_list])
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("No se detectaron interfaces activas.")

    # Historial persistente de tráfico
    snaps = _get_history(router_id)
    if snaps and len(snaps) >= 2:
        st.markdown("---")
        st.markdown("##### 📈 Historial de Tráfico (SQLite)")
        t_times = [s.timestamp.strftime("%H:%M") for s in snaps]
        t_rx = [s.total_rx for s in snaps]
        t_tx = [s.total_tx for s in snaps]
        fig2 = go.Figure()
        fig2.add_trace(go.Scatter(x=t_times, y=t_rx, name='Rx', mode='lines', line=dict(color='#00F0FF', width=2, shape='spline'), fill='tozeroy', fillcolor='rgba(0,240,255,0.06)'))
        fig2.add_trace(go.Scatter(x=t_times, y=t_tx, name='Tx', mode='lines', line=dict(color='#FF007F', width=2, shape='spline'), fill='tozeroy', fillcolor='rgba(255,0,127,0.06)'))
        fig2.update_layout(template='plotly_dark', height=200, margin=dict(l=10, r=10, t=10, b=10),
            paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', showlegend=True,
            legend=dict(orientation='h', y=1.1, font=dict(size=10)), hovermode='x unified')
        st.plotly_chart(fig2, use_container_width=True, config={'displayModeBar': False})


@st.dialog("🛡️ Firewall — Conexiones y Reglas Activas", width="large")
def _dialog_firewall(router_id, conn_act, conn_pct, max_conn, datos):
    c1, c2, c3 = st.columns(3)
    c1.metric("Conexiones Activas", f"{conn_act:,}")
    c2.metric("Capacidad Usada", f"{conn_pct:.1f}%")
    c3.metric("Límite Sistema", f"{max_conn:,}")

    connections = datos.get('connections', [])
    proto_counts = {}
    for conn in connections:
        proto = conn.get('protocol', 'other')
        proto_counts[proto] = proto_counts.get(proto, 0) + 1

    if proto_counts:
        fig = go.Figure(data=[go.Pie(labels=list(proto_counts.keys()), values=list(proto_counts.values()), hole=0.5,
            marker=dict(colors=['#00F0FF', '#FF007F', '#B100FF', '#FFAA00', '#00FFAA'], line=dict(color='#0D0F14', width=2)),
            textinfo='label+percent', textfont=dict(size=10, color='#ccc'))])
        fig.update_layout(template='plotly_dark', height=250, margin=dict(l=5, r=5, t=5, b=5),
            paper_bgcolor='rgba(0,0,0,0)', showlegend=False,
            annotations=[dict(text=f"<b>{conn_act:,}</b>", font_size=16, showarrow=False, font_color='white')])
        st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})

    st.markdown("---")
    bl = datos.get('blacklist', [])
    if bl:
        st.warning(f"🚫 **{len(bl)}** reglas DROP activas en el firewall.")
    else:
        st.success("✅ Sin bloqueos activos.")

    if conn_pct > 70:
        st.error("🚨 Saturación de firewall — Revisar reglas de NAT.")
    elif conn_pct > 40:
        st.warning("⚠️ Carga media-alta en el connection tracking.")
    else:
        st.success("✅ Firewall en capacidad normal.")

    # Historial conexiones
    snaps = _get_history(router_id)
    if snaps and len(snaps) >= 2:
        st.markdown("##### 📈 Historial de Conexiones")
        c_times = [s.timestamp.strftime("%H:%M") for s in snaps]
        c_vals = [s.connections for s in snaps]
        fig2 = go.Figure()
        fig2.add_trace(go.Scatter(x=c_times, y=c_vals, mode='lines+markers', name='Conexiones',
            line=dict(color='#B100FF', width=2, shape='spline'), fill='tozeroy', fillcolor='rgba(177,0,255,0.06)'))
        fig2.update_layout(template='plotly_dark', height=180, margin=dict(l=10, r=10, t=10, b=10),
            paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', showlegend=False)
        st.plotly_chart(fig2, use_container_width=True, config={'displayModeBar': False})


# ──────────────────────────────────────────────
# VISTA PRINCIPAL
# ──────────────────────────────────────────────

def render_overview(router_db, datos):
    st.markdown("""
    <style>
    /* Diseño perfecto: hacer que los botones "tertiary" se metan visualmente dentro de la tarjeta HTML base */
    div.stButton > button[kind="tertiary"] {
        background: transparent !important;
        border: none !important;
        box-shadow: none !important;
        color: #888 !important;
        padding-top: 0 !important;
        margin-top: -38px !important; /* Levantar para que el botón esté sobre el espaciado interno de .kpi-card y .iface-card */
        display: flex !important;
        justify-content: center !important;
    }
    div.stButton > button[kind="tertiary"] p {
        font-size: 11px !important;
        margin: 0 !important;
        text-align: right !important;
        width: 100%;
        padding-right: 15px;
    }
    div.stButton > button[kind="tertiary"] p:hover {
        color: #00F0FF !important;
    }
    /* Estética al hacer hover en la card entera */
    .kpi-card:hover {
        transform: scale(1.02);
        box-shadow: 0 4px 15px rgba(0,0,0,0.5);
    }
    </style>
    """, unsafe_allow_html=True)
    st.markdown(f"<h1 style='margin-bottom:12px; margin-top:-40px;'>Router {router_db.name}</h1>", unsafe_allow_html=True)

    # ── Datos base ──────────────────────────────
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

    # ── Alertas automáticas ───────────
    for srv in datos.get('latencia', []):
        if str(srv.get('status', '')).lower() == 'down':
            _alert_register('critical', f"Servidor CAÍDO: {srv.get('comment', srv.get('host', '?'))}")
    try:
        temp_f = float(temp)
        if temp_f > 75: _alert_register('critical', f"🔥 Temperatura crítica: {temp_f}°C")
        elif temp_f > 60: _alert_register('warning', f"🌡️ Temperatura alta: {temp_f}°C")
    except Exception: pass
    if cpu > 85: _alert_register('critical', f"CPU sobrecargada: {cpu}%")
    elif cpu > 70: _alert_register('warning', f"CPU elevada: {cpu}%")
    if ram_pct > 85: _alert_register('critical', f"RAM crítica: {ram_pct:.1f}%")
    elif ram_pct > 70: _alert_register('warning', f"RAM alta: {ram_pct:.1f}%")

    _render_alert_panel()

    # ══════════════════════════════════════════════
    # ROW 0: HEALTH SCORE + STATUS BAR + KPIs
    # ══════════════════════════════════════════════
    hs = st.session_state.get('health_score')
    col_health, col_status = st.columns([1.2, 2.8])

    with col_health:
        if hs:
            fig_gauge = _gauge_health_score(hs)
            st.plotly_chart(fig_gauge, use_container_width=True, config={'displayModeBar': False})
            breakdown_html = ""
            for k, v in hs['breakdown'].items():
                bar_color = "#00FFAA" if v >= 80 else "#FFAA00" if v >= 50 else "#FF4B4B"
                breakdown_html += f'<div class="health-item"><span class="health-item-label">{k}</span><span class="health-item-value" style="color:{bar_color};">{v:.0f}</span></div>'
            st.markdown(f'<div class="health-gauge" style="border-top:3px solid {hs["color"]};"><p class="kpi-label">Desglose de Indicadores</p><div class="health-breakdown">{breakdown_html}</div></div>', unsafe_allow_html=True)
        else:
            st.info("Sincronizando Health Score...")

        # Nodos Activos compacto debajo del "Desglose de Indicadores"
        st.markdown("<h4 style='color:#ddd;margin:20px 0 5px 0;'><i class='fa-solid fa-network-wired'></i> Nodos Activos</h4>", unsafe_allow_html=True)
        usuarios_lan = len(datos.get('dhcp', []))
        usuarios_vpn = len(datos.get('vpns', []))
        total_usuarios = usuarios_lan + usuarios_vpn
        wifi_count = len(datos.get('wifi_neighbors', []))

        fig_users = go.Figure(data=[go.Pie(labels=['LAN', 'VPN'], values=[max(usuarios_lan, 0.1), max(usuarios_vpn, 0.1)],
            hole=.68, marker=dict(colors=['#00FFAA', '#B100FF'], line=dict(color='#0D0F14', width=2)), textinfo='none')])
        fig_users.update_layout(showlegend=False, height=140, margin=dict(l=0, r=0, t=5, b=5),
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            annotations=[dict(text=f"<b>{total_usuarios}</b><br><span style='font-size:11px;color:#555;'>Nodos</span>", x=0.5, y=0.5, font_size=18, showarrow=False, font_color="white")])
        st.plotly_chart(fig_users, use_container_width=True, config={'displayModeBar': False})
        st.markdown(f"""
        <div style="background:rgba(0,0,0,0.25);padding:8px 10px;border-radius:8px;border:1px solid rgba(255,255,255,0.05);font-size:12px;">
            <div style="display:flex;justify-content:space-between;margin-bottom:4px;"><span style="color:#00FFAA;"><i class="fa-solid fa-desktop"></i> LAN</span><strong style="color:#00FFAA;font-family:JetBrains Mono">{usuarios_lan}</strong></div>
            <div style="display:flex;justify-content:space-between;margin-bottom:4px;"><span style="color:#B100FF;"><i class="fa-solid fa-globe"></i> VPN</span><strong style="color:#B100FF;font-family:JetBrains Mono">{usuarios_vpn}</strong></div>
            <div style="display:flex;justify-content:space-between;"><span style="color:#00F0FF;"><i class="fa-solid fa-wifi"></i> WiFi</span><strong style="color:#00F0FF;font-family:JetBrains Mono">{wifi_count}</strong></div>
        </div>""", unsafe_allow_html=True)

    with col_status:
        temp_disp = f"{temp}°C" if temp != "N/A" else "N/A"
        
        wan_st = datos.get('wan_status', {})
        wan_info = ""
        if wan_st:
            wip = wan_st.get('wan_ip', 'N/A')
            cm = wan_st.get('connection_method', 'Desconocido')
            fo = "🛡️ Failover Configurado" if wan_st.get('has_failover') else "⚠️ Sin Respaldo"
            wan_info = f"<div style='margin-top:10px; background:rgba(0,180,255,0.05); border:1px solid rgba(0,180,255,0.2); padding:8px 12px; border-radius:6px; font-size:12px;display:flex; justify-content:space-between; align-items:center;'><span style='color:#00F0FF;'><i class='fa-solid fa-globe'></i> Red Pública (WAN): <strong style='font-family:JetBrains Mono;'>{wip}</strong></span><span style='color:#ccc;'><i class='fa-solid fa-network-wired'></i> {cm}</span><span style='color:#B100FF;'>{fo}</span></div>"

        st.markdown(f"""
        <div class="status-bar">
            <div style="display:flex;align-items:center;gap:6px;"><div class="status-dot-online"></div><span class="status-label">SYS_ONLINE</span></div>
            <span class="status-sep">|</span><span class="status-label"><i class="fa-solid fa-clock"></i> Uptime: <strong class="status-value">{uptime}</strong></span>
            <span class="status-sep">|</span><span class="status-label"><i class="fa-solid fa-microchip"></i> RouterOS <strong class="status-value">{version}</strong></span>
            <span class="status-sep">|</span><span class="status-label"><i class="fa-solid fa-temperature-half"></i> <strong class="status-value">{temp_disp}</strong></span>
            <span class="status-sep">|</span><span class="status-label"><i class="fa-solid fa-server"></i> <strong class="status-value">{board}</strong></span>
        </div>
        {wan_info}
        """, unsafe_allow_html=True)

        # KPI Cards + Botones de diálogo
        color_cpu = "#FF4B4B" if cpu > 80 else "#FFAA00" if cpu > 60 else "#00FFAA"
        color_ram = "#FF4B4B" if ram_pct > 80 else "#FFAA00" if ram_pct > 60 else "#00FFAA"
        color_conn = "#FF4B4B" if conn_pct > 70 else "#FFAA00" if conn_pct > 40 else "#B100FF"
        clase_cpu = "kpi-critical" if cpu > 80 else "kpi-warning" if cpu > 60 else ""
        clase_ram = "kpi-critical" if ram_pct > 80 else "kpi-warning" if ram_pct > 60 else ""
        clase_conn = "kpi-critical" if conn_pct > 70 else "kpi-warning" if conn_pct > 40 else ""

        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.markdown(_kpi_card("Carga CPU", f"{cpu}", "%", cpu, color_cpu, "⚙️", clase_cpu), unsafe_allow_html=True)
            if st.button("Ver Detalles ↗", key="dlg_cpu", type="tertiary", use_container_width=True):
                _dialog_cpu(router_db.id, cpu, board, uptime)
        with c2:
            st.markdown(_kpi_card("Uso RAM", f"{ram_pct:.1f}", "%", ram_pct, color_ram, "🧠", clase_ram), unsafe_allow_html=True)
            if st.button("Ver Detalles ↗", key="dlg_ram", type="tertiary", use_container_width=True):
                _dialog_ram(router_db.id, ram_pct, ram_libre, ram_total)
        with c3:
            rx_pct = min((total_rx / 100) * 100, 100)
            st.markdown(_kpi_card("Descarga", f"{total_rx:.1f}", "Mbps", rx_pct, "#00F0FF", "📥"), unsafe_allow_html=True)
            if st.button("Ver Detalles ↗", key="dlg_traffic", type="tertiary", use_container_width=True):
                _dialog_traffic(router_db.id, datos.get('traffic_list', []), total_rx, total_tx)
        with c4:
            st.markdown(_kpi_card("Firewall", f"{conn_act:,}", "Conn", conn_pct, color_conn, "🛡️", clase_conn), unsafe_allow_html=True)
            if st.button("Ver Detalles ↗", key="dlg_fw", type="tertiary", use_container_width=True):
                _dialog_firewall(router_db.id, conn_act, conn_pct, max_conn, datos)

        # ── TRONCALES FÍSICAS, TÚNELES (VPN) Y ACCESS POINTS (Alineadas a la derecha) ──
        st.markdown("<h4 style='color:#ddd;margin:15px 0 8px 0;'><i class='fa-solid fa-network-wired'></i> Enlaces Físicos, VPNs y Puntos de Acceso</h4>", unsafe_allow_html=True)
        
        traffic_list = datos.get('traffic_list', [])
        vpns = datos.get('vpns', [])
        vecinos_wifi = datos.get('wifi_neighbors', [])
        
        totales = len(traffic_list) + len(vpns) + len(vecinos_wifi)
        
        if totales > 0:
            trunk_cols = st.columns(min(totales, 5) if totales < 5 else 5)
            idx = 0
            
            # 1. Tráfico Interfaces
            for iface in traffic_list:
                with trunk_cols[idx % 5]:
                    rx_val, tx_val = iface['rx'], iface['tx']
                    border_color = "#FF4B4B" if rx_val > 20 else "#FFAA00" if rx_val > 5 else "#00FFAA"
                    badge_class = "device-badge-offline" if rx_val > 20 else "device-badge-standby" if rx_val > 5 else "device-badge-online"
                    badge_text = "SAT" if rx_val > 20 else "ACT" if rx_val > 5 else "IDLE"
                    st.markdown(f"""
                    <div class="iface-card" style="border-top:3px solid {border_color}; text-align:center; padding-bottom: 25px;">
                        <h5 style="margin:0;font-size:12px;color:#00F0FF;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">{iface['name']}</h5>
                        <div class="iface-rx" style="font-size:11px;"><i class="fa-solid fa-arrow-down"></i> {rx_val} Mbps</div>
                        <div class="iface-tx" style="font-size:11px;"><i class="fa-solid fa-arrow-up"></i> {tx_val} Mbps</div>
                        <div style="margin-top:6px;"><span class="device-badge {badge_class}" style="font-size:9px;">{badge_text}</span></div>
                    </div>""", unsafe_allow_html=True)
                    if st.button("⚙️", key=f"btn_iface_{idx}", type="tertiary", use_container_width=True):
                        _dialog_trunk_details(iface)
                idx += 1
                
            # 2. Túneles VPN
            for v in vpns:
                with trunk_cols[idx % 5]:
                    v_name = v.get('name', v.get('user', 'Túnel'))
                    v_ip = v.get('address', v.get('caller-id', 'IP'))
                    st.markdown(f"""
                    <div class="iface-card" style="border-top:3px solid #B100FF; text-align:center; padding-bottom: 25px;">
                        <h5 style="margin:0;font-size:12px;color:#B100FF;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;"><i class="fa-solid fa-shield-halved"></i> {v_name}</h5>
                        <div style="font-size:11px;color:#ddd;margin-top:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">{v_ip}</div>
                        <div style="margin-top:10px;"><span class="device-badge device-badge-online" style="font-size:9px;">ACTIVO</span></div>
                    </div>""", unsafe_allow_html=True)
                    if st.button("⚙️", key=f"btn_vpn_{idx}", type="tertiary", use_container_width=True):
                        _dialog_vpn_details(v)
                idx += 1
                
            # 3. APs WiFi Detectados L2
            for w in vecinos_wifi:
                with trunk_cols[idx % 5]:
                    w_name = w.get('identity', 'AP')
                    w_plat = w.get('platform', 'Wifi')
                    st.markdown(f"""
                    <div class="iface-card" style="border-top:3px solid #E50914; text-align:center; padding-bottom: 25px;">
                        <h5 style="margin:0;font-size:12px;color:#E50914;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;"><i class="fa-solid fa-wifi"></i> {w_name}</h5>
                        <div style="font-size:11px;color:#ddd;margin-top:3px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">{w_plat}</div>
                        <div style="margin-top:10px;"><span class="device-badge device-badge-online" style="font-size:9px;background:rgba(229,9,20,0.15);color:#E50914;">AP L2</span></div>
                    </div>""", unsafe_allow_html=True)
                    if st.button("⚙️", key=f"btn_ap_{idx}", type="tertiary", use_container_width=True):
                        _dialog_ap_details(w)
                idx += 1
                
        else:
            st.info("No se detectó tráfico significativo, túneles VPN ni Puntos de Acceso locales.")

    # ══════════════════════════════════════════════
    # ROW 2: GRÁFICO EN VIVO + ANÁLISIS L7
    # ══════════════════════════════════════════════
    col_grafico, col_apps = st.columns([3, 1.2])

    with col_grafico:
        col_title, col_chart_type = st.columns([2, 1])
        col_title.markdown("<h4 style='color:#ddd;margin-bottom:5px;'><span class='live-dot'></span><i class='fa-solid fa-bolt'></i> Telemetría L2/L3</h4>", unsafe_allow_html=True)
        chart_type_live = col_chart_type.radio("Tipo:", ["Líneas", "Áreas", "Barras"], index=1, key="live_chart_type", horizontal=True, label_visibility="collapsed")

        hist_time = st.session_state.get('hist_time', [])
        hist_rx = st.session_state.get('hist_rx', [])
        hist_tx = st.session_state.get('hist_tx', [])
        fig = go.Figure()

        if len(hist_rx) > 2:
            avg_rx = sum(hist_rx) / len(hist_rx)
            avg_tx = sum(hist_tx) / len(hist_tx)
            fig.add_trace(go.Scatter(x=hist_time, y=[avg_rx]*len(hist_time), mode='lines', name='Avg Rx', line=dict(color='rgba(0,240,255,0.25)', width=1, dash='dot'), hoverinfo='skip'))
            fig.add_trace(go.Scatter(x=hist_time, y=[avg_tx]*len(hist_time), mode='lines', name='Avg Tx', line=dict(color='rgba(255,0,127,0.25)', width=1, dash='dot'), hoverinfo='skip'))

        if chart_type_live == "Barras":
            fig.add_trace(go.Bar(x=hist_time, y=hist_rx, name='Rx', marker_color='#00F0FF'))
            fig.add_trace(go.Bar(x=hist_time, y=hist_tx, name='Tx', marker_color='#FF007F'))
        else:
            fill_mode = 'tozeroy' if chart_type_live == "Áreas" else 'none'
            fc_rx = 'rgba(0,240,255,0.08)' if fill_mode == 'tozeroy' else 'rgba(0,0,0,0)'
            fc_tx = 'rgba(255,0,127,0.08)' if fill_mode == 'tozeroy' else 'rgba(0,0,0,0)'
            fig.add_trace(go.Scatter(x=hist_time, y=hist_rx, mode='lines+markers', name='Rx Total', line=dict(color='#00F0FF', width=3, shape='spline'), fill=fill_mode, fillcolor=fc_rx, marker=dict(size=5, color='#00F0FF')))
            fig.add_trace(go.Scatter(x=hist_time, y=hist_tx, mode='lines+markers', name='Tx Total', line=dict(color='#FF007F', width=3, shape='spline'), fill=fill_mode, fillcolor=fc_tx, marker=dict(size=5, color='#FF007F')))

        fig.update_layout(template='plotly_dark', height=280, margin=dict(l=10, r=10, t=10, b=10),
            xaxis=dict(showgrid=False, color='#555'), yaxis=dict(showgrid=True, gridcolor='rgba(255,255,255,0.03)', title="Mbps", color='#555'),
            paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1, font=dict(size=10, color='#888')),
            barmode='group' if chart_type_live == "Barras" else None, hovermode='x unified')
        st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})

    with col_apps:
        st.markdown("<h4 style='color:#ddd;margin-bottom:5px;'><i class='fa-solid fa-shield-halved'></i> Análisis L7</h4>", unsafe_allow_html=True)
        talkers = datos.get('top_talkers', [])
        if not talkers:
            st.info(":material/lightbulb: L7 en espera.")
            if st.button(":material/search: Escanear L7", use_container_width=True):
                st.session_state['force_l7'] = True
                st.rerun()
        else:
            suma_bytes = sum([t['bytes'] for t in talkers]) or 1
            for i, t in enumerate(talkers):
                pct = (t['bytes'] / suma_bytes) * 100
                mb = t['bytes'] / (1024*1024)
                color = ["#FF0000", "#E50914", "#1877F2", "#00F0FF", "#2D8CFF"][i % 5]
                btn_label = f":material/computer:  Host {t['ip'].split('.')[-1]}  {pct:.1f}%"
                with st.popover(btn_label, use_container_width=True):
                    st.markdown(f"<h3 style='color:{color};margin-top:0;'>Top Talker: {t['ip']}</h3>", unsafe_allow_html=True)
                    st.caption(f"Consume el {pct:.1f}% del tráfico — {mb:.1f} MB")

    # ══════════════════════════════════════════════
    # ROW 3: HISTORIAL PERSISTENTE SQLite
    # ══════════════════════════════════════════════
    st.markdown("---")
    st.markdown("<h4 style='color:#ddd;'><i class='fa-solid fa-chart-simple'></i> Análisis Histórico (Persistencia AIOps)</h4>", unsafe_allow_html=True)

    c_rango, c_tipo = st.columns([2, 1])
    rango = c_rango.radio("Período:", ["Última Hora", "Últimas 6 Horas", "Últimas 24 Horas", "Últimos 7 Días"], index=0, horizontal=True, label_visibility="collapsed")
    chart_type_hist = c_tipo.radio("Tipo:", ["Líneas", "Áreas", "Barras"], index=1, key="hist_chart_type", horizontal=True, label_visibility="collapsed")

    rangos_map = {"Última Hora": timedelta(hours=1), "Últimas 6 Horas": timedelta(hours=6), "Últimas 24 Horas": timedelta(hours=24), "Últimos 7 Días": timedelta(days=7)}
    desde = datetime.now() - rangos_map[rango]

    try:
        db_hist = SessionLocal()
        snapshots = db_hist.query(TrafficSnapshot).filter(TrafficSnapshot.router_id == router_db.id, TrafficSnapshot.timestamp >= desde).order_by(TrafficSnapshot.timestamp.asc()).all()
        db_hist.close()

        if snapshots and len(snapshots) >= 1:
            times = [s.timestamp.strftime("%H:%M") if rangos_map[rango] <= timedelta(hours=6) else s.timestamp.strftime("%d/%m %H:%M") for s in snapshots]
            rxs, txs, cpus, healths = [s.total_rx for s in snapshots], [s.total_tx for s in snapshots], [s.cpu_load for s in snapshots], [s.health_score for s in snapshots]
            avg_rx_h = sum(rxs) / len(rxs) if rxs else 0

            col_g1, col_g2 = st.columns(2)
            with col_g1:
                fig_h = go.Figure()
                fill_m = 'tozeroy' if chart_type_hist == "Áreas" else 'none'
                if chart_type_hist == "Barras":
                    fig_h.add_trace(go.Bar(x=times, y=rxs, name='Rx', marker_color='#00F0FF'))
                    fig_h.add_trace(go.Bar(x=times, y=txs, name='Tx', marker_color='#FF007F'))
                else:
                    fig_h.add_trace(go.Scatter(x=times, y=rxs, name='Rx', line=dict(color='#00F0FF', width=2, shape='spline'), fill=fill_m, fillcolor='rgba(0,240,255,0.05)'))
                    fig_h.add_trace(go.Scatter(x=times, y=txs, name='Tx', line=dict(color='#FF007F', width=2, shape='spline'), fill=fill_m, fillcolor='rgba(255,0,127,0.05)'))
                fig_h.update_layout(template='plotly_dark', height=220, margin=dict(l=10, r=10, t=10, b=10), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                    yaxis=dict(title="Mbps", gridcolor='rgba(255,255,255,0.03)'), xaxis=dict(showgrid=False),
                    legend=dict(orientation="h", y=1.1, font=dict(size=10, color='#888')), barmode='group' if chart_type_hist == "Barras" else None, hovermode='x unified')
                st.plotly_chart(fig_h, use_container_width=True, config={'displayModeBar': False})

            with col_g2:
                fig_c = go.Figure()
                if chart_type_hist == "Barras":
                    fig_c.add_trace(go.Bar(x=times, y=cpus, name='CPU %', marker_color='#FFAA00'))
                    fig_c.add_trace(go.Bar(x=times, y=healths, name='Health', marker_color='#00FFAA'))
                else:
                    fig_c.add_trace(go.Scatter(x=times, y=cpus, name='CPU %', line=dict(color='#FFAA00', width=2, shape='spline'), fill=fill_m, fillcolor='rgba(255,170,0,0.05)'))
                    fig_c.add_trace(go.Scatter(x=times, y=healths, name='Health', line=dict(color='#00FFAA', width=2, shape='spline'), fill=fill_m, fillcolor='rgba(0,255,170,0.05)'))
                fig_c.update_layout(template='plotly_dark', height=220, margin=dict(l=10, r=10, t=10, b=10), paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
                    yaxis=dict(title="Valor", gridcolor='rgba(255,255,255,0.03)'), xaxis=dict(showgrid=False),
                    legend=dict(orientation="h", y=1.1, font=dict(size=10, color='#888')), barmode='group' if chart_type_hist == "Barras" else None, hovermode='x unified')
                st.plotly_chart(fig_c, use_container_width=True, config={'displayModeBar': False})

            if len(rxs) > 3:
                max_rx = max(rxs)
                if max_rx > avg_rx_h * 2.5:
                    st.markdown(f'<div class="alert-banner alert-banner-warning"><span class="alert-banner-icon">📈</span><div class="alert-banner-text"><div class="alert-banner-title warning">ANOMALÍA DE TRÁFICO</div><div class="alert-banner-body">Pico {max_rx:.1f} Mbps supera 2.5x promedio ({avg_rx_h:.1f} Mbps).</div></div></div>', unsafe_allow_html=True)
        else:
            st.info(":material/bar_chart: Aún no hay datos históricos suficientes. Se acumularán con cada sincronización.")
    except Exception:
        st.info(":material/bar_chart: El historial se construirá con cada sincronización.")

    # ══════════════════════════════════════════════
    # ROW 4: SERVICIOS MONITOREADOS (Netwatch)
    # ══════════════════════════════════════════════
    latencia_data = datos.get('latencia', [])
    if latencia_data:
        st.markdown("---")
        st.markdown("<h4 style='color:#ddd;'>:material/monitor_heart: Servicios Monitoreados (Netwatch)</h4>", unsafe_allow_html=True)
        online = [s for s in latencia_data if str(s.get('status', '')).lower() == 'up']
        offline = [s for s in latencia_data if str(s.get('status', '')).lower() == 'down']
        mc1, mc2, mc3 = st.columns(3)
        mc1.metric("Total", len(latencia_data))
        mc2.metric("🟢 Online", len(online))
        mc3.metric("🔴 Caídos", len(offline), delta=f"-{len(offline)}" if offline else None, delta_color="inverse")

        rows_html = ""
        for srv in latencia_data:
            is_up = str(srv.get('status', '')).lower() == 'up'
            dot_color = "#00FFAA" if is_up else "#FF4B4B"
            dot_anim = "pulse-green" if is_up else "pulse-red"
            status_text = "ONLINE" if is_up else "⚠️ CAÍDO"
            comment = srv.get('comment', srv.get('host', '?'))
            host_ip = srv.get('host', '')
            rows_html += f'<div class="live-row"><div style="display:flex;align-items:center;gap:10px;"><div style="width:8px;height:8px;border-radius:50%;background:{dot_color};animation:{dot_anim} 1.5s infinite;flex-shrink:0;"></div><div><div class="live-row-ip">{comment}</div><div style="color:#444;font-size:10px;font-family:JetBrains Mono">{host_ip}</div></div></div><div style="color:{"#00FFAA" if is_up else "#FF4B4B"};font-size:11px;font-family:JetBrains Mono;font-weight:700;">{status_text}</div></div>'
        st.markdown(rows_html, unsafe_allow_html=True)

    # ══════════════════════════════════════════════
    # ROW 5: INFRAESTRUCTURA AVANZADA (Routing + DNS + Storage + QoS)
    # ══════════════════════════════════════════════
    routing = datos.get('routing_health', {})
    dns_cfg = datos.get('dns_config', {})
    storage = datos.get('storage_info', {})
    queues = datos.get('active_queues', [])

    # Solo mostrar si hay datos interesantes
    has_infra = routing or dns_cfg or storage or queues
    if has_infra:
        st.markdown("---")
        st.markdown("<h4 style='color:#ddd;'><i class='fa-solid fa-layer-group'></i> Infraestructura de Red Avanzada</h4>", unsafe_allow_html=True)

        ci1, ci2, ci3, ci4 = st.columns(4)

        with ci1:
            st.markdown("##### :material/route: Enrutamiento")
            if routing:
                r_total = routing.get('rutas_totales', 0)
                r_active = routing.get('rutas_activas', 0)
                r_gw = routing.get('default_gateway', 'N/A')
                ospf = routing.get('ospf_neighbors', [])
                bgp = routing.get('bgp_peers', [])
                st.metric("Rutas Totales", r_total, delta=f"{r_active} activas")
                st.caption(f"**Gateway:** `{r_gw}`")
                st.caption(f"Estáticas: {routing.get('static_routes', 0)} | Dinámicas: {routing.get('dynamic_routes', 0)}")
                if ospf:
                    st.success(f"🔗 OSPF: {len(ospf)} vecino(s)")
                if bgp:
                    st.info(f"🌐 BGP: {len(bgp)} peer(s)")
            else:
                st.caption("Sin datos de routing")

        with ci2:
            st.markdown("##### :material/dns: Configuración DNS")
            if dns_cfg:
                servers = dns_cfg.get('servers', 'Sin configurar')
                dyn_servers = dns_cfg.get('dynamic_servers', '')
                allow_remote = dns_cfg.get('allow_remote', 'false')
                cache_size = dns_cfg.get('cache_size', '2048')
                cache_used = dns_cfg.get('cache_used', '0')

                st.caption(f"**Servidores:** `{servers}`")
                if dyn_servers:
                    st.caption(f"**Dinámicos (ISP):** `{dyn_servers}`")
                remote_icon = "🟢" if allow_remote == 'true' else "🔴"
                st.caption(f"**Remoto:** {remote_icon} {'Habilitado' if allow_remote == 'true' else 'Deshabilitado'}")
                st.caption(f"**Caché:** {cache_used}/{cache_size} KiB")
            else:
                st.caption("Sin datos DNS")

        with ci3:
            st.markdown("##### :material/hard_drive: Almacenamiento")
            if storage:
                total_hdd = storage.get('total_hdd', 0)
                free_hdd = storage.get('free_hdd', 0)
                used_pct = storage.get('used_pct', 0)
                bad_blocks = storage.get('bad_blocks', '0')

                total_mb = total_hdd / 1_048_576
                free_mb = free_hdd / 1_048_576
                color_s = "#FF4B4B" if used_pct > 90 else "#FFAA00" if used_pct > 70 else "#00FFAA"
                st.metric("Uso NAND", f"{used_pct:.1f}%", delta=f"{free_mb:.1f} MB libres")
                st.caption(f"Total: {total_mb:.1f} MB")
                if str(bad_blocks) != '0' and bad_blocks != '0%':
                    st.error(f"⚠️ Bad blocks: {bad_blocks}")
                else:
                    st.caption("✅ Sin bloques dañados")
            else:
                st.caption("Sin datos de storage")

        with ci4:
            st.markdown("##### :material/traffic: Colas QoS Activas")
            if queues:
                st.metric("Reglas Activas", len(queues))
                for q in queues[:5]:
                    target = q.get('target', '?')
                    max_limit = q.get('max-limit', 'Sin límite')
                    name = q.get('name', '')
                    disabled = q.get('disabled', 'false')
                    icon = "🔴" if disabled == 'true' else "🟢"
                    st.caption(f"{icon} `{target}` → {max_limit}")
                if len(queues) > 5:
                    st.caption(f"... +{len(queues) - 5} más")
            else:
                st.success("Sin reglas QoS activas")

    # ══════════════════════════════════════════════
    # ROW 6: SFP
    # ══════════════════════════════════════════════
    sfp_data = datos.get('sfp_diagnostics', [])
    if sfp_data:
        st.markdown("---")
        st.markdown("<h4 style='color:#ddd;'>:material/flare: Estado Físico del Enlace (SFP / LTE)</h4>", unsafe_allow_html=True)
        st.dataframe(pd.DataFrame(sfp_data), use_container_width=True, hide_index=True)

    # ══════════════════════════════════════════════
    # FOOTER: Sync Timestamp
    # ══════════════════════════════════════════════
    sync_ts = datos.get('sync_timestamp', '')
    if sync_ts:
        st.markdown(f"<div style='text-align:right;color:#444;font-size:11px;margin-top:10px;font-family:JetBrains Mono;'>Última sincronización: {sync_ts}</div>", unsafe_allow_html=True)