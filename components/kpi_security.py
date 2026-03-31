import streamlit as st
import pandas as pd
import plotly.graph_objects as go

def render_security_and_lan(sec_data, dhcp_data):
    st.subheader("🛡️ Seguridad Perimetral y Red Local (LAN)")
    
    col_sec, col_lan = st.columns(2)
    
    with col_sec:
        st.markdown("**Saturación de Tabla de Conexiones**")
        activas = sec_data.get('conexiones_activas', 0)
        max_conn = sec_data.get('max_conexiones', 300000)
        porcentaje = (activas / max_conn) * 100
        
        # Color dinámico según carga
        color = "#00F0FF" if porcentaje < 60 else "#FFAA00" if porcentaje < 85 else "#FF4B4B"
        
        fig = go.Figure(go.Indicator(
            mode = "gauge+number",
            value = activas,
            number = {'font': {'size': 32, 'color': 'white'}, 'valueformat': ","},
            gauge = {
                'axis': {'range': [None, 10000], 'tickwidth': 1, 'tickcolor': "rgba(255,255,255,0.2)"},
                'bar': {'color': color},
                'bgcolor': "rgba(255,255,255,0.05)",
                'steps': [
                    {'range': [0, 6000], 'color': 'rgba(0, 240, 255, 0.05)'},
                    {'range': [6000, 8500], 'color': 'rgba(255, 170, 0, 0.1)'},
                    {'range': [8500, 10000], 'color': 'rgba(255, 75, 75, 0.2)'}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 3},
                    'thickness': 0.75,
                    'value': 9000
                }
            }
        ))
        fig.update_layout(height=220, margin=dict(l=20, r=20, t=30, b=20), paper_bgcolor="rgba(0,0,0,0)")
        st.plotly_chart(fig, use_container_width=True, config={'displayModeBar': False})
        st.caption(f"Capacidad del Firewall: {porcentaje:.1f}% utilizándose.")

    with col_lan:
        st.markdown(f"**Dispositivos DHCP Activos:** `{len(dhcp_data)}`")
        if dhcp_data:
            df_dhcp = pd.DataFrame(dhcp_data)
            cols_map = {
                'address': 'Dirección IP',
                'mac-address': 'MAC Address',
                'host-name': 'Hostname'
            }
            df_show = df_dhcp[[c for c in cols_map.keys() if c in df_dhcp.columns]].rename(columns=cols_map)
            df_show.fillna('---', inplace=True)
            
            st.dataframe(
                df_show,
                use_container_width=True, 
                hide_index=True, 
                height=220
            )
        else:
            st.info("Sin registros DHCP.")