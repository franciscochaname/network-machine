import streamlit as st
import plotly.graph_objects as go

def render_hardware_kpis(info_data):
    st.subheader("⚙️ Core Processing Unit & Memory")
    
    cpu = int(info_data.get('cpu_load', 0))
    ram_libre_mb = int(info_data.get('free_memory', 0)) / 1048576
    ram_total_mb = int(info_data.get('total_memory', 0)) / 1048576 if info_data.get('total_memory') else ram_libre_mb + 256
    ram_usada_pct = ((ram_total_mb - ram_libre_mb) / ram_total_mb) * 100 if ram_total_mb > 0 else 0

    # Procesar Temperatura
    temp_raw = info_data.get('temperature', 'N/A')
    temp_disp = f"{temp_raw}°C" if temp_raw != "N/A" else "N/A"
    try: temp = float(temp_raw)
    except: temp = None

    # Procesar Voltaje
    volt_raw = info_data.get('voltage', 'N/A')
    volt_disp = f"{volt_raw} V" if volt_raw != "N/A" else "N/A"
    try: volt = float(volt_raw)
    except: volt = None

    # Detección de Fallas / Reinicios
    uptime = info_data.get('uptime', '0s')
    bad_blocks = int(info_data.get('bad_blocks', 0))
    
    # Lógica de Alerta de Reinicio Reciente (menos de 10 min)
    is_recent_reboot = False
    if 'm' in uptime and 'h' not in uptime and 'd' not in uptime:
        minutes = int(uptime.split('m')[0])
        if minutes < 10:
            is_recent_reboot = True
    elif 's' in uptime and 'm' not in uptime:
        is_recent_reboot = True

    col1, col2, col3, col4 = st.columns([1, 1, 1, 1.5])
    
    # 1. Gráfico CPU
    fig_cpu = go.Figure(go.Indicator(
        mode="gauge+number",
        value=cpu,
        number={'suffix': "%", 'font': {'size': 24, 'color': '#00FFAA'}},
        gauge={
            'axis': {'range': [None, 100]},
            'bar': {'color': "#00FFAA"},
            'bgcolor': "rgba(255, 255, 255, 0.05)",
            'steps': [{'range': [85, 100], 'color': 'rgba(255, 0, 0, 0.5)'}]
        }
    ))
    fig_cpu.update_layout(template='plotly_dark', height=180, margin=dict(l=10, r=10, t=10, b=10), paper_bgcolor="rgba(0,0,0,0)")
    
    # 2. Gráfico RAM
    fig_ram = go.Figure(go.Indicator(
        mode="gauge+number",
        value=ram_usada_pct,
        number={'suffix': "%", 'font': {'size': 24, 'color': '#FFAA00'}},
        gauge={
            'axis': {'range': [None, 100]},
            'bar': {'color': "#FFAA00"},
            'bgcolor': "rgba(255, 255, 255, 0.05)"
        }
    ))
    fig_ram.update_layout(template='plotly_dark', height=180, margin=dict(l=10, r=10, t=10, b=10), paper_bgcolor="rgba(0,0,0,0)")

    # 3. Gráfico Temperatura
    if temp is not None:
        temp_color = "#00FF00" if temp < 50 else "#FFAA00" if temp < 70 else "#FF0000"
        fig_temp = go.Figure(go.Indicator(
            mode = "gauge+number",
            value = temp,
            number={'suffix': "°C", 'font': {'size': 24, 'color': temp_color}},
            gauge={
                'axis': {'range': [None, 100]},
                'bar': {'color': temp_color},
                'bgcolor': "rgba(255, 255, 255, 0.05)",
                'steps': [
                    {'range': [0, 50], 'color': 'rgba(0, 255, 0, 0.1)'},
                    {'range': [50, 75], 'color': 'rgba(255, 170, 0, 0.1)'},
                    {'range': [75, 100], 'color': 'rgba(255, 0, 0, 0.2)'}
                ]
            }
        ))
        fig_temp.update_layout(template='plotly_dark', height=180, margin=dict(l=10, r=10, t=10, b=10), paper_bgcolor="rgba(0,0,0,0)")
    
    with col1:
        st.markdown("<p style='text-align:center; color:#888; font-size:0.8rem;'>CPU</p>", unsafe_allow_html=True)
        st.plotly_chart(fig_cpu, use_container_width=True, config={'displayModeBar': False})
        
    with col2:
        st.markdown("<p style='text-align:center; color:#888; font-size:0.8rem;'>RAM</p>", unsafe_allow_html=True)
        st.plotly_chart(fig_ram, use_container_width=True, config={'displayModeBar': False})

    with col3:
        st.markdown("<p style='text-align:center; color:#888; font-size:0.8rem;'>TEMP</p>", unsafe_allow_html=True)
        if temp is not None:
            st.plotly_chart(fig_temp, use_container_width=True, config={'displayModeBar': False})
        else:
            st.markdown("<div style='height:180px; display:flex; align-items:center; justify-content:center; color:#555;'>No Sensor</div>", unsafe_allow_html=True)
        
    with col4:
        # Estado de Salud y Fallas
        status_color = "#00FFAA"
        status_text = "SISTEMA SALUDABLE"
        alerts = []

        if is_recent_reboot:
            status_color = "#FFAA00"
            status_text = "REINICIO RECIENTE"
            alerts.append("⚠️ Equipo reiniciado hace pocos minutos.")
        
        if bad_blocks > 0:
            status_color = "#FF4B4B"
            status_text = "FALLA DE DISCO"
            alerts.append(f"🚨 {bad_blocks} Bad Blocks detectados en Flash.")

        if temp and temp > 75:
            status_color = "#FF4B4B"
            status_text = "SOBRECALENTAMIENTO"
            alerts.append("🔥 Temperatura crítica detectada.")

        if volt:
            if volt < 10.5:
                 status_color = "#FF4B4B"
                 status_text = "FALLA ELÉCTRICA"
                 alerts.append(f"⚡ VOLTAJE CRÍTICO: {volt}V (Bajo)")
            elif 18 < volt < 21:
                 status_color = "#FFAA00"
                 status_text = "TENSIÓN INESTABLE"
                 alerts.append(f"⚡ Voltaje bajo: {volt}V")

        st.markdown(f"""
        <div style="background-color: rgba(0,0,0,0.3); padding: 15px; border-radius: 10px; border: 1px solid rgba(255,255,255,0.1); border-left: 4px solid {status_color};">
            <div style="color: {status_color}; font-weight: bold; font-size: 0.9rem; margin-bottom: 8px;">{status_text}</div>
            <div style="color: #bbb; font-family: monospace; font-size: 0.8rem;">
                ▶ Uptime: {uptime}<br>
                ▶ Temp: {temp_disp}<br>
                ▶ Voltaje: {volt_disp}<br>
                ▶ Reinicio: {info_data.get('last_reboot', '---')}<br>
                ▶ Flash: {bad_blocks} bad blocks
            </div>
            {''.join([f'<div style="color: #FF4B4B; font-size: 0.75rem; margin-top: 5px; font-weight: 500;">{a}</div>' for a in alerts])}
        </div>
        """, unsafe_allow_html=True)