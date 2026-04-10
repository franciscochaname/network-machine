import streamlit as st
import pandas as pd
import folium
from streamlit_folium import st_folium
from database.db_models import SessionLocal, Router
from core.geolocation import auto_geolocate_router, geolocate_ip, is_public_ip
from core.router_api import RouterManager


def render_network_map(router_id=None):
    if not router_id:
        st.title("🗺️ Mapa de Red Global")
        st.markdown("Visualización geográfica en tiempo real de toda la infraestructura monitoreada.")

    db = SessionLocal()
    if router_id:
        routers = db.query(Router).filter(Router.id == router_id).all()
    else:
        routers = db.query(Router).all()

    if not routers:
        if not router_id:
            st.markdown("""
            <div class="empty-state">
                <div class="empty-state-icon">🗺️</div>
                <h2 class="empty-state-title">Sin Infraestructura Registrada</h2>
                <p class="empty-state-desc">Registra equipos en el Inventario para verlos en el mapa.</p>
            </div>
            """, unsafe_allow_html=True)
        db.close()
        return

    # --- PANEL DE GEOLOCALIZACIÓN MASIVA ---
    routers_sin_ubicacion = [r for r in routers if not r.latitude or not r.longitude]

    if not router_id and routers_sin_ubicacion:
        with st.expander(f"📍 {len(routers_sin_ubicacion)} equipo(s) sin ubicación — Click para geo-detectar", expanded=True):
            st.caption("Se conectará a cada router para descubrir su IP pública y geolocalizar automáticamente.")
            
            col_btn, col_info = st.columns([1, 3])
            with col_btn:
                detectar = st.button(":material/public: Auto-Detectar Todos", type="primary", use_container_width=True)
            
            if detectar:
                progreso = st.progress(0, text="Iniciando geolocalización...")
                total = len(routers_sin_ubicacion)
                exitos = 0

                for idx, r in enumerate(routers_sin_ubicacion):
                    progreso.progress((idx + 1) / total, text=f"Conectando a {r.name} ({r.ip_address})...")
                    
                    router = RouterManager(r.ip_address, r.api_user, r.api_pass_encrypted)
                    conectado, _ = router.connect()
                    
                    if conectado:
                        geo = auto_geolocate_router(router.api, fallback_ip=r.ip_address)
                        router.disconnect()
                        
                        if geo:
                            r.latitude = geo['lat']
                            r.longitude = geo['lon']
                            r.wan_ip = geo.get('wan_ip', '')
                            r.location = f"{geo.get('city', '')}, {geo.get('country', '')}"
                            db.commit()
                            exitos += 1
                            st.success(f":material/task_alt: **{r.name}** → {geo.get('city')}, {geo.get('country')} ({geo['lat']:.4f}, {geo['lon']:.4f})")
                        else:
                            st.warning(f":material/warning_amber: **{r.name}** — No se pudo determinar IP pública. Ingresa coordenadas manualmente en el Inventario.")
                    else:
                        st.error(f":material/cancel: **{r.name}** — No se pudo conectar.")

                progreso.progress(1.0, text=f"Completado: {exitos}/{total} equipos geolocalizados.")
                if exitos > 0:
                    st.rerun()

    # --- CONSTRUCCIÓN DEL MAPA ---
    routers_con_ubicacion = [r for r in routers if r.latitude and r.longitude]

    if not routers_con_ubicacion:
        st.info("📍 Ningún equipo tiene coordenadas asignadas. Usa el botón de arriba para detectar automáticamente o ingresa las coordenadas en el Inventario.")
        db.close()
        return

    # Calcular centro del mapa
    avg_lat = sum(r.latitude for r in routers_con_ubicacion) / len(routers_con_ubicacion)
    avg_lon = sum(r.longitude for r in routers_con_ubicacion) / len(routers_con_ubicacion)

    # Crear mapa con tema oscuro
    m = folium.Map(
        location=[avg_lat, avg_lon],
        zoom_start=6 if len(routers_con_ubicacion) > 1 else 13,
        tiles='CartoDB dark_matter',
        attr='NOC v3.5'
    )

    # --- AGREGAR MARCADORES ---
    for r in routers_con_ubicacion:
        # Intentar verificar conectividad (ligero, sin telemetría completa)
        estado = "unknown"
        estado_color = "gray"
        estado_icon = "question"

        # Si hay telemetría activa para este router, verificar
        if st.session_state.get('nodo_actual') == r.ip_address and st.session_state.get('telemetria'):
            estado = "online"
            estado_color = "green"
            estado_icon = "cloud"
        else:
            estado = "sin datos"
            estado_color = "blue"
            estado_icon = "cloud"

        # HTML del popup
        popup_html = f"""
        <div style="font-family: 'Segoe UI', Arial, sans-serif; min-width: 250px; color: #222;">
            <h4 style="margin: 0 0 8px; color: #0066CC; border-bottom: 2px solid #0066CC; padding-bottom: 5px;">
                🔲 {r.name}
            </h4>
            <table style="width: 100%; font-size: 13px; border-collapse: collapse;">
                <tr><td style="padding: 3px 0; color: #666;">IP Gestión:</td>
                    <td style="padding: 3px 0;"><strong>{r.ip_address}</strong></td></tr>
                <tr><td style="padding: 3px 0; color: #666;">IP Pública:</td>
                    <td style="padding: 3px 0;"><strong>{r.wan_ip or 'N/A'}</strong></td></tr>
                <tr><td style="padding: 3px 0; color: #666;">Ubicación:</td>
                    <td style="padding: 3px 0;">{r.location or 'Sin definir'}</td></tr>
                <tr><td style="padding: 3px 0; color: #666;">Coordenadas:</td>
                    <td style="padding: 3px 0;">{r.latitude:.4f}, {r.longitude:.4f}</td></tr>
                <tr><td style="padding: 3px 0; color: #666;">Estado:</td>
                    <td style="padding: 3px 0;">
                        <span style="color: {'#00AA00' if estado == 'online' else '#0066CC'}; font-weight: bold;">
                            {'● ONLINE' if estado == 'online' else '● SIN TELEMETRÍA'}
                        </span>
                    </td></tr>
            </table>
        </div>
        """

        # Determinar icono segun tipo (AP vs Router) validando NoneType
        telemetria = st.session_state.get('telemetria')
        t_data = telemetria if isinstance(telemetria, dict) else {}
        t_info = t_data.get('info', {}) if isinstance(t_data, dict) else {}
        has_ap = t_info.get('has_ap', False) if isinstance(t_info, dict) else False
        
        icon_type = "wifi" if r.ip_address in str(t_info) and has_ap else "server"
        
        folium.Marker(
            location=[r.latitude, r.longitude],
            popup=folium.Popup(popup_html, max_width=400),
            tooltip=f"{r.name} (Click para detalles)",
            icon=folium.Icon(color=estado_color, icon=icon_type, prefix='fa')
        ).add_to(m)

        # Anillo de radio alrededor del marcador
        folium.CircleMarker(
            location=[r.latitude, r.longitude],
            radius=15,
            color='#00F0FF' if estado == 'online' else '#4488FF',
            fill=True,
            fill_opacity=0.15,
            weight=1
        ).add_to(m)

    # --- DIBUJAR LÍNEAS VPN ENTRE SITIOS ---
    if len(routers_con_ubicacion) > 1:
        # Si hay VPN activas, conectar nodos
        if st.session_state.get('telemetria') and st.session_state['telemetria'].get('vpns'):
            # Líneas punteadas entre todos los nodos activos (representación de mesh)
            for i in range(len(routers_con_ubicacion)):
                for j in range(i + 1, len(routers_con_ubicacion)):
                    r1 = routers_con_ubicacion[i]
                    r2 = routers_con_ubicacion[j]
                    folium.PolyLine(
                        locations=[[r1.latitude, r1.longitude], [r2.latitude, r2.longitude]],
                        color='#00F0FF',
                        weight=2,
                        opacity=0.4,
                        dash_array='10 6',
                        tooltip='Enlace VPN'
                    ).add_to(m)

    # --- RENDERIZAR MAPA ---
    if router_id:
        st_folium(m, width=None, height=350, use_container_width=True)
    else:
        col_map, col_panel = st.columns([3, 1])

        with col_map:
            st_folium(m, width=None, height=520, use_container_width=True)

        with col_panel:
            st.markdown("#### 📋 Nodos Registrados")
            st.markdown(f"""
            <div class="map-stats">
                <div class="map-stat-item">
                    <span class="map-stat-value">{len(routers)}</span>
                    <span class="map-stat-label">Total</span>
                </div>
                <div class="map-stat-item">
                    <span class="map-stat-value" style="color: #00FFAA;">{len(routers_con_ubicacion)}</span>
                    <span class="map-stat-label">En Mapa</span>
                </div>
                <div class="map-stat-item">
                    <span class="map-stat-value" style="color: #FF4B4B;">{len(routers_sin_ubicacion)}</span>
                    <span class="map-stat-label">Sin Ubicación</span>
                </div>
            </div>
            """, unsafe_allow_html=True)

            st.markdown("---")

            for r in routers:
                tiene_ubicacion = r.latitude and r.longitude
                icono = '<i class="fa-solid fa-location-crosshairs" style="color: #00FFAA; font-size: 18px;"></i>' if tiene_ubicacion else '<i class="fa-solid fa-location-dot" style="color: #FF4B4B; font-size: 18px;"></i>'
                st.markdown(f"""
                <div class="map-router-card">
                    <div style="display: flex; align-items: center; gap: 12px;">
                        <span>{icono}</span>
                        <div>
                            <div class="map-router-name">{r.name}</div>
                            <div class="map-router-ip">{r.ip_address}</div>
                            <div class="map-router-location">{r.location or 'Sin ubicación'}</div>
                        </div>
                    </div>
                </div>
                """, unsafe_allow_html=True)

    db.close()
