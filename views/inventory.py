import streamlit as st
from database.db_models import SessionLocal, Router
from core.geolocation import auto_geolocate_router, geolocate_ip, is_public_ip
from core.router_api import RouterManager
from core.crypto import encrypt_password

def render_inventory():
    st.title("⚙️ Gestión de Inventario de Nodos")
    st.markdown("Administra los equipos de red conectados al centro de operaciones.")

    db = SessionLocal()
    routers = db.query(Router).all()

    # ==========================================
    # 1. LISTA DE EQUIPOS
    # ==========================================
    st.subheader("📋 Nodos Registrados")
    if routers:
        for r in routers:
            with st.container(border=True):
                col1, col2, col3, col4, col5 = st.columns([2.5, 2, 1.5, 0.8, 0.8])

                with col1:
                    st.markdown(f"<h4 style='margin:0; color:#00F0FF;'>{r.name}</h4>", unsafe_allow_html=True)
                    st.caption(f"📍 {r.location or 'Sin ubicación'}")
                with col2:
                    st.markdown(f"**IP:** `{r.ip_address}`")
                    st.markdown(f"**Usuario:** `{r.api_user}`")
                with col3:
                    if r.latitude and r.longitude:
                        st.markdown(f":material/public: `{r.latitude:.4f}, {r.longitude:.4f}`")
                        if r.wan_ip:
                            st.caption(f"WAN: {r.wan_ip}")
                    else:
                        st.markdown("⚪ Sin coordenadas")
                with col4:
                    if st.button("✏️", key=f"edit_{r.id}", use_container_width=True, help="Editar"):
                        st.session_state['edit_router_id'] = r.id
                with col5:
                    if st.button("🗑️", key=f"del_{r.id}", type="primary", use_container_width=True, help="Borrar"):
                        db.delete(r)
                        db.commit()
                        st.rerun()
                
            with st.expander(f"🗺️ Mapa del Nodo: {r.name}", expanded=False):
                from views.network_map import render_network_map
                render_network_map(r.id)
    else:
        st.info("No hay equipos en la base de datos.")

    # ==========================================
    # 2. PANEL DE EDICIÓN (incluye geolocalización)
    # ==========================================
    if 'edit_router_id' in st.session_state:
        edit_id = st.session_state['edit_router_id']
        router_edit = db.query(Router).filter(Router.id == edit_id).first()

        if router_edit:
            st.markdown("---")
            st.subheader(f"✏️ Editando: {router_edit.name}")

            # Botón de auto-detección de ubicación
            col_geo, col_geo_info = st.columns([1, 2])
            with col_geo:
                if st.button("📍 Auto-Detectar ISP/Región", use_container_width=True):
                    with st.spinner("Conectando al router para descubrir IP pública..."):
                        router = RouterManager(
                            router_edit.ip_address, router_edit.api_user, router_edit.api_pass_encrypted
                        )
                        conectado, _ = router.connect()
                        if conectado:
                            geo = auto_geolocate_router(router.api, fallback_ip=router_edit.ip_address)
                            
                            # Detectar si la IP es DHCP/PPPoE (Dinámica) o Estática
                            try:
                                rutas = router.api.get_resource('/ip/route').get()
                                rutas_def = [rt for rt in rutas if rt.get('dst-address') == '0.0.0.0/0']
                                is_dynamic = any(rt.get('dynamic') == 'true' for rt in rutas_def)
                                tipo_ip = "IP Dinámica" if is_dynamic else "IP Fija (Estática)"
                            except Exception:
                                tipo_ip = "Desconocida"
                                
                            router.disconnect()
                            if geo:
                                router_edit.latitude = geo['lat']
                                router_edit.longitude = geo['lon']
                                # Guardar la IP Wan junto con su tipo
                                router_edit.wan_ip = f"{geo.get('wan_ip', '')} ({tipo_ip})"
                                router_edit.location = f"{geo.get('city', '')}, {geo.get('country', '')}"
                                db.commit()
                                st.success(f":material/task_alt: Ubicado en {geo.get('city')} - Proveedor asgina: {tipo_ip}")
                                st.rerun()
                            else:
                                st.warning("No se pudo determinar IP pública/ubicación.")
                        else:
                            st.error("No se pudo conectar al equipo.")

            with col_geo_info:
                if router_edit.latitude and router_edit.longitude:
                    st.success(f"📍 Actual: {router_edit.location} ({router_edit.latitude:.4f}, {router_edit.longitude:.4f})")
            
            # --- GEO BSSID (Wi-Fi Precision) ---
            with st.expander(":material/satellite_alt: Geolocalización Precisa por BSSID (Wi-Fi Extrema Precisión)"):
                st.caption("El router escaneará las redes Wi-Fi vecinas y enviará sus MAC addresses (BSSID) a una base de datos para triangular la posición a nivel de edificio (< 50m).")
                with st.form("bssid_geo_form"):
                    col_prov, col_iface = st.columns([1, 1])
                    api_provider = col_prov.radio("Proveedor de Base de Datos BSSID:", ["Mylnikov GEO (100% Gratis)", "Google Maps API (Requiere Key)"], horizontal=False)
                    wifi_iface = col_iface.text_input("Interfaz Wi-Fi", value="wlan1", help="Nombre de tu interfaz Wi-Fi (ej: wlan1, wifi1)")
                    
                    api_key_input = ""
                    if "Google" in api_provider:
                         api_key_input = st.text_input("Ingresa tu GOOGLE_MAPS_API_KEY:", type="password")
                         
                    if st.form_submit_button("📡 Escanear y Triangular BSSID", type="primary"):
                        from core.geolocation import geolocate_by_bssid, geolocate_by_mylnikov
                        
                        if "Google" in api_provider and not api_key_input:
                            st.error("Debes ingresar tu API Key de Google Maps para usar este servicio premium.")
                        else:
                            with st.spinner(f"Escaneando redes cercanas en la interfaz {wifi_iface}..."):
                                router = RouterManager(router_edit.ip_address, router_edit.api_user, router_edit.api_pass_encrypted)
                                ok, _ = router.connect()
                                if ok:
                                    # Absorber BSSIDs vecinos
                                    scan_results = router.get_wifi_scan(interface=wifi_iface, duration=5)
                                    router.disconnect()
                                    
                                    if scan_results:
                                        geo = None
                                        if "Mylnikov" in api_provider:
                                             geo = geolocate_by_mylnikov(scan_results)
                                        else:
                                             geo = geolocate_by_bssid(scan_results, api_key_input)
                                             
                                        if geo:
                                            router_edit.latitude = geo['lat']
                                            router_edit.longitude = geo['lon']
                                            db.commit()
                                            
                                            st.success(f":material/task_alt: ¡Triangulación exitosa! Precisión estimada: {geo.get('accuracy', 'N/A')} metros.")
                                            st.markdown(f"**Coordenadas Capturadas:** `{geo['lat']}, {geo['lon']}` (Powered by {geo.get('country', 'BSSID Database')})")
                                            st.rerun()
                                        else:
                                            st.error(f":material/cancel: La base de datos de {api_provider.split(' ')[0]} no encontró el edificio para estas redes Wi-Fi o la conexión expiró.")
                                            st.write("Redes encontradas:", ", ".join([ap.get('ssid','Hidden') for ap in scan_results]))
                                    else:
                                        st.error(f":material/warning_amber: No se detectaron redes vecinas en {wifi_iface}. Verifica que exista y que el equipo tenga Wi-Fi.")
                                else:
                                    st.error("Error conectando al router.")

            with st.form("form_editar"):
                col_a, col_b = st.columns(2)
                e_name = col_a.text_input("Nombre de Sede", router_edit.name)
                e_ip = col_b.text_input("Dirección IP", router_edit.ip_address)
                e_user = col_a.text_input("Usuario API", router_edit.api_user)
                e_pass = col_b.text_input("Nueva Contraseña (vacío = mantener actual)", type="password")
                e_location = col_a.text_input("Ubicación", router_edit.location or "")

                st.markdown("##### :material/public: Coordenadas (Opcional — o usa Auto-Detectar)")
                col_lat, col_lon = st.columns(2)
                e_lat = col_lat.number_input("Latitud", value=router_edit.latitude or 0.0, format="%.6f", step=0.001)
                e_lon = col_lon.number_input("Longitud", value=router_edit.longitude or 0.0, format="%.6f", step=0.001)

                col_save, col_cancel = st.columns(2)
                if col_save.form_submit_button("💾 Guardar Cambios", use_container_width=True):
                    import ipaddress
                    error = False
                    if not e_name.strip() or not e_ip.strip() or not e_user.strip():
                        st.error(":material/warning_amber: Nombre, IP y Usuario son obligatorios.")
                        error = True
                    try:
                        # Allow domains by not strictly enforcing IP unless it looks like one.
                        # We will check if it's a valid IP only if it's purely digits/dots, else assume domain.
                        if any(c.isdigit() for c in e_ip) and not any(c.isalpha() for c in e_ip):
                            ipaddress.ip_address(e_ip)
                    except ValueError:
                        st.error(":material/warning_amber: Formato de Dirección IP o Hostname inválido. Verifica que sea una IP válida (ej. 192.168.1.1) o un nombre de host sin caracteres raros.")
                        error = True
                        
                    if not error:
                        router_edit.name = e_name.strip()
                        router_edit.ip_address = e_ip.strip()
                        router_edit.api_user = e_user.strip()
                        router_edit.location = e_location.strip()
                        if e_pass:
                            router_edit.api_pass_encrypted = encrypt_password(e_pass)
                        if e_lat != 0.0:
                            router_edit.latitude = e_lat
                        if e_lon != 0.0:
                            router_edit.longitude = e_lon
                        db.commit()
                        del st.session_state['edit_router_id']
                        st.success("Cambios aplicados correctamente.")
                        st.rerun()

                if col_cancel.form_submit_button(":material/cancel: Cancelar", use_container_width=True):
                    del st.session_state['edit_router_id']
                    st.rerun()

    # ==========================================
    # 3. FORMULARIO DE CREACIÓN
    # ==========================================
    st.markdown("---")
    with st.expander("➕ Añadir Nuevo Nodo a la Red", expanded=False):
        with st.form("add_router_form"):
            col1, col2 = st.columns(2)
            r_name = col1.text_input("Nombre de Sede (Ej: Sede Principal)")
            r_ip = col2.text_input("Dirección IP o Dominio")
            r_user = col1.text_input("Usuario API", value="admin")
            r_pass = col2.text_input("Contraseña API", type="password")
            r_location = col1.text_input("Ubicación (Ej: Tegucigalpa, Honduras)", value="")

            st.markdown("##### :material/public: Coordenadas (Opcional — se detectarán automáticamente al sincronizar)")
            col_lat, col_lon = st.columns(2)
            r_lat = col_lat.number_input("Latitud", value=0.0, format="%.6f", step=0.001)
            r_lon = col_lon.number_input("Longitud", value=0.0, format="%.6f", step=0.001)

            submitted = st.form_submit_button("Registrar Nodo", type="primary")
            if submitted:
                import ipaddress
                error = False
                if not r_name.strip() or not r_ip.strip() or not r_user.strip() or not r_pass:
                    st.error(":material/warning_amber: Nombre, IP, Usuario y Contraseña son obligatorios.")
                    error = True
                try:
                    if any(c.isdigit() for c in r_ip) and not any(c.isalpha() for c in r_ip):
                        ipaddress.ip_address(r_ip)
                except ValueError:
                    st.error(":material/warning_amber: Formato de Dirección IP o Hostname inválido. Verifica que sea una IP válida (ej. 192.168.1.1) o un nombre de host sin caracteres raros.")
                    error = True
                
                if not error:
                    new_router = Router(
                        name=r_name.strip(), ip_address=r_ip.strip(), api_user=r_user.strip(),
                        api_pass_encrypted=encrypt_password(r_pass), location=r_location or "Sede Nueva",
                        latitude=r_lat if r_lat != 0.0 else None,
                        longitude=r_lon if r_lon != 0.0 else None
                    )
                    db.add(new_router)
                    db.commit()
                    st.success(":material/task_alt: Nodo agregado exitosamente. Las coordenadas se detectarán automáticamente en la primera sincronización.")
                    st.rerun()

    db.close()