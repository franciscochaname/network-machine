import streamlit as st
import pandas as pd

def render_routing_kpis(routing_data):
    st.subheader("🗺️ Topología Lógica y Enrutamiento")
    
    col1, col2 = st.columns([1, 2])
    
    with col1:
        st.markdown(f"""
        <div style="background-color: rgba(138, 43, 226, 0.05); padding: 20px; border-radius: 12px; border: 1px solid rgba(138, 43, 226, 0.2); border-left: 5px solid #8a2be2;">
            <p style="color: #888; margin-bottom: 0px; font-size: 0.9rem;">Rutas Activas en Tabla</p>
            <h2 style="color: white; margin-top: 5px; margin-bottom: 0px;">{routing_data.get('rutas_activas', 0)}</h2>
            <p style="color: #555; font-size: 0.8rem;">Total: {routing_data.get('rutas_totales', 0)} registros</p>
        </div>
        """, unsafe_allow_html=True)
        
    with col2:
        vecinos_ospf = routing_data.get('ospf_neighbors', [])
        if vecinos_ospf:
            st.markdown(f"**Vecinos OSPF Adyacentes:** `{len(vecinos_ospf)}`")
            df = pd.DataFrame(vecinos_ospf)
            cols_map = {'instance': 'Instancia', 'address': 'Dirección IP', 'state': 'Estado'}
            df_show = df[[c for c in cols_map.keys() if c in df.columns]].rename(columns=cols_map)
            st.dataframe(df_show, use_container_width=True, hide_index=True)
        else:
            st.markdown("""
            <div style="background-color: rgba(255,255,255,0.02); padding: 15px; border-radius: 10px; border: 1px dashed rgba(255,255,255,0.1); text-align: center; color: #666;">
                <p style="margin-bottom: 0;">Sin adyacencias OSPF detectadas.</p>
                <small>(Operando bajo Ruteo Estático o BGP)</small>
            </div>
            """, unsafe_allow_html=True)