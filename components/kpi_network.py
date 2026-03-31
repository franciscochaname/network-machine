import streamlit as st
import pandas as pd
import plotly.graph_objects as go
from datetime import datetime

def render_traffic_kpis(traffic_data, interface_name="ether1"):
    """Dibuja un gráfico de área fluido (Time-Series) con métricas avanzadas."""
    st.subheader(f"📊 Telemetría de Interfaz: `{interface_name}`")
    
    rx = traffic_data.get('rx', 0.0)
    tx = traffic_data.get('tx', 0.0)
    
    # 1. GESTIÓN DE HISTORIAL
    if 'history_time' not in st.session_state:
        st.session_state['history_time'] = []
        st.session_state['history_rx'] = []
        st.session_state['history_tx'] = []
        
    st.session_state['history_time'].append(datetime.now().strftime("%H:%M:%S"))
    st.session_state['history_rx'].append(rx)
    st.session_state['history_tx'].append(tx)
    
    if len(st.session_state['history_time']) > 40:
        st.session_state['history_time'].pop(0)
        st.session_state['history_rx'].pop(0)
        st.session_state['history_tx'].pop(0)

    # Cálculo de Picos
    peak_rx = max(st.session_state['history_rx']) if st.session_state['history_rx'] else 0
    peak_tx = max(st.session_state['history_tx']) if st.session_state['history_tx'] else 0

    # 2. DISEÑO DE MÉTRICAS SUPERIORES
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("⬇️ Descarga Actual", f"{rx:.2f} Mbps")
    m2.metric("⬆️ Subida Actual", f"{tx:.2f} Mbps")
    m3.metric("🔝 Pico Descarga", f"{peak_rx:.2f} Mbps")
    m4.metric("🔝 Pico Subida", f"{peak_tx:.2f} Mbps")

    # 3. GRÁFICO PROFESIONAL
    fig = go.Figure()
    
    # Rx Area
    fig.add_trace(go.Scatter(
        x=st.session_state['history_time'], 
        y=st.session_state['history_rx'],
        mode='lines',
        name='Descarga (Rx)',
        line=dict(color='#00F0FF', width=2, shape='spline'),
        fill='tozeroy',
        fillcolor='rgba(0, 240, 255, 0.1)'
    ))
    
    # Tx Area
    fig.add_trace(go.Scatter(
        x=st.session_state['history_time'], 
        y=st.session_state['history_tx'],
        mode='lines',
        name='Subida (Tx)',
        line=dict(color='#FF007F', width=2, shape='spline'),
        fill='tozeroy',
        fillcolor='rgba(255, 0, 127, 0.1)'
    ))

    fig.update_layout(
        template='plotly_dark',
        height=300,
        margin=dict(l=10, r=10, t=10, b=10),
        xaxis=dict(showgrid=False, showticklabels=True),
        yaxis=dict(showgrid=True, gridcolor='rgba(255,255,255,0.05)', title="Mbps"),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
        hovermode="x unified"
    )
    
    st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})

def render_vpn_status(vpns_data):
    st.subheader("🔐 Túneles VPN Activos")
    if vpns_data:
        df = pd.DataFrame(vpns_data)
        cols_map = {
            'name': 'Usuario/Sede',
            'service': 'Protocolo',
            'caller-id': 'IP Pública',
            'address': 'IP Asignada',
            'uptime': 'Tiempo Activo'
        }
        df_show = df[[c for c in cols_map.keys() if c in df.columns]].rename(columns=cols_map)
        st.dataframe(df_show, use_container_width=True, hide_index=True)
    else:
        st.info("No hay conexiones VPN activas.")