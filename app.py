import streamlit as st
from streamlit_option_menu import option_menu
from datetime import datetime
from streamlit_autorefresh import st_autorefresh
from streamlit_cookies_controller import CookieController
import time

from core.security import verify_password
from core.router_api import RouterManager
from core.styles import load_global_css, hide_sidebar
from core.health_score import calculate_health_score
from core.geolocation import auto_geolocate_router
from database.db_models import SessionLocal, User, Router, TrafficSnapshot

@st.dialog("🚪 Port Knocking - Desbloqueo Seguro (Tok Tok)")
def knock_dialog(ip_address):
    st.markdown("### Secuencia de Desbloqueo")
    st.markdown(f"**Destino:** `{ip_address}`")
    st.write("Iniciando proceso de autenticación segura por secuencia de puertos...")
    
    from core.port_knock import port_knock
    import time
    
    status_placeholder = st.empty()
    status_placeholder.info("⏳ Esperando respuesta del router...")
    
    time.sleep(0.5)
    
    with st.spinner("🔑 Enviando toques de desbloqueo (Tok Tok)..."):
        ok, msg = port_knock(ip_address)
    
    if ok:
        status_placeholder.success(f"✅ ¡Completado! {msg}")
        st.balloons()
        st.success("El router ha respondido. Re-conectando en 3 segundos...")
        time.sleep(3)
        st.rerun()
    else:
        status_placeholder.error(f"❌ Falló el desbloqueo: {msg}")
        if st.button("Cerrar"):
            st.rerun()


from views.overview import render_overview
from views.inventory import render_inventory
from views.intelligence import render_intelligence
from components.login import render_login

# ==========================================
# 1. CONFIGURACIÓN GLOBAL
# ==========================================
st.set_page_config(
    page_title="Network Operations Center",
    page_icon="🌐",
    layout="wide",
    initial_sidebar_state="expanded"
)

load_global_css()

# ==========================================
# 2. COOKIES Y ESTADO DE SESIÓN
# ==========================================
cookies = CookieController()
time.sleep(0.3)

if 'logged_in' not in st.session_state:
    if cookies.get("is_logged_in"):
        st.session_state['logged_in'] = True
        st.session_state['username'] = cookies.get("username")
        st.session_state['role'] = cookies.get("role")
    else:
        st.session_state['logged_in'] = False

if 'telemetria' not in st.session_state: st.session_state['telemetria'] = None
if 'nodo_actual' not in st.session_state: st.session_state['nodo_actual'] = None
if 'hist_time' not in st.session_state: st.session_state['hist_time'] = []
if 'hist_rx' not in st.session_state: st.session_state['hist_rx'] = []
if 'hist_tx' not in st.session_state: st.session_state['hist_tx'] = []
if 'refresh_count' not in st.session_state: st.session_state['refresh_count'] = 0
if 'health_score' not in st.session_state: st.session_state['health_score'] = None

# ==========================================
# 3. PANTALLA DE LOGIN (INDEPENDIENTE)
# ==========================================
if not st.session_state['logged_in']:
    render_login(cookies)

# ==========================================
# 4. BARRA LATERAL
# ==========================================
with st.sidebar:
    safe_username = st.session_state.get('username') or "NOC"
    safe_role = st.session_state.get('role') or "Admin"
    
    st.markdown(f"""
    <div class="sidebar-profile">
        <div class="sidebar-profile-inner">
            <div class="sidebar-avatar">{safe_username[0].upper()}</div>
            <div>
                <div class="sidebar-username">{safe_username.upper()}</div>
                <div class="sidebar-role">{safe_role}</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    if 'menu_key' not in st.session_state:
        st.session_state['menu_key'] = 0

    menu_global = option_menu(
        menu_title="Centro de Operaciones",
        options=["Vista General", "Topología de Red",
                 "Inteligencia de Red", "Centro Táctico", "Herramientas NOC", "Inventario de Nodos"],
        icons=["grid-1x2-fill", "diagram-3-fill",
               "eye-fill", "shield-lock-fill", "tools", "hdd-network-fill"],
        menu_icon="broadcast", default_index=0,
        key=f"sidebar_menu_{st.session_state['menu_key']}",
        styles={
            "container": {"padding": "5px !important", "background-color": "transparent"},
            "icon": {"color": "#00F0FF", "font-size": "16px"},
            "nav-link": {
                "font-size": "13px", "text-align": "left", "margin": "2px 0",
                "border-radius": "8px", "padding": "10px 15px",
                "color": "#999", "font-weight": "500",
                "--hover-color": "rgba(0, 240, 255, 0.05)"
            },
            "nav-link-selected": {
                "background": "linear-gradient(135deg, rgba(0, 240, 255, 0.1), rgba(177, 0, 255, 0.05))",
                "border-left": "3px solid #00F0FF",
                "color": "white", "font-weight": "600"
            },
        }
    )
    st.markdown("---")

    # --- INFRAESTRUCTURA ---
    db = SessionLocal()
    routers_db = db.query(Router).all()
    db.close()

    router_db = None
    force_refresh = False

    if not routers_db:
        st.info("📌 Registra un equipo en el Inventario para comenzar.")
    else:
        st.markdown('<p class="sidebar-section-label">🌍 Infraestructura Activa</p>', unsafe_allow_html=True)
        opciones = {f"{r.name} ({r.ip_address})": r for r in routers_db}
        nombres_menu = ["-- Seleccionar Nodo --"] + list(opciones.keys())
        seleccion = st.selectbox("Nodo Central", nombres_menu, label_visibility="collapsed")

        if seleccion == "-- Seleccionar Nodo --":
            router_db = None
            st.info("👈 Selecciona un equipo.")
        else:
            router_db = opciones[seleccion]

            st.markdown('<p class="sidebar-refresh-label">⏱️ Tasa de Refresco</p>', unsafe_allow_html=True)
            opciones_tiempo = {
                "Automático (2 min)": 120, "Lento (50s)": 50,
                "Normal (30s)": 30, "Rápido (20s)": 20,
                "Extremo (10s)": 10, "Pausado (Manual)": 0
            }
            sel_tiempo = st.selectbox("Refresco", list(opciones_tiempo.keys()), index=0, label_visibility="collapsed")
            tiempo_segundos = opciones_tiempo[sel_tiempo]

            if tiempo_segundos > 0:
                count = st_autorefresh(interval=tiempo_segundos * 1000, key="data_refresh")
                if count != st.session_state['refresh_count']:
                    force_refresh = True
                    st.session_state['refresh_count'] = count

            if st.session_state['nodo_actual'] != router_db.ip_address:
                st.session_state['telemetria'] = None
                st.session_state['nodo_actual'] = router_db.ip_address
                st.session_state['health_score'] = None
                for key in ['hist_time', 'hist_rx', 'hist_tx']:
                    st.session_state[key].clear()
                
                # Forzar redirección al Dashboard (Vista General) incrementando el modificador de menú
                st.session_state['menu_key'] += 1
                st.rerun()

            necesita_sincronizar = (
                st.button("🔄 Forzar Sincronización", use_container_width=True) or
                st.session_state['telemetria'] is None or
                force_refresh
            )

            if necesita_sincronizar:
                with st.spinner(f"🔌 Conectando con {router_db.name} | Procesando carga de Telemetría (100%)... no interrumpas."):
                    router = RouterManager(router_db.ip_address, router_db.api_user, router_db.api_pass_encrypted)
                    if router.connect()[0]:
                        trafico = router.get_smart_traffic()
                        total_rx = sum(t['rx'] for t in trafico)
                        total_tx = sum(t['tx'] for t in trafico)

                        # Determinar si cargamos telemetría pesada (L7)
                        force_l7 = st.session_state.get('force_l7', False)

                        st.session_state['telemetria'] = {
                            "info": router.get_system_info(),
                            "traffic_list": trafico,
                            "total_rx": total_rx, "total_tx": total_tx,
                            "sec": router.get_security_saturation(),
                            "dhcp": router.get_dhcp_leases(),
                            "vpns": router.get_active_vpns(),
                            "top_talkers": router.get_top_talkers() if force_l7 else [],
                            "flujos_sankey": router.get_connection_flows() if force_l7 else [],
                            "latencia": router.get_server_latency(),
                            "blacklist": router.get_blacklisted_ips() if force_l7 else [],
                            "router_ips": router.get_router_ips(),
                            "arp_table": router.get_arp_table(),
                            "local_networks": router.get_local_networks(),
                            "wifi_interfaces": router.get_wifi_interfaces(),
                            "wifi_neighbors": router.get_wifi_neighbors(),
                            "interface_health": router.get_interface_health(),
                            "sfp_diagnostics": router.get_sfp_diagnostics(),
                        }
                        # Resetar flag después de cargar
                        if force_l7: st.session_state['force_l7'] = False

                        # Calcular Health Score
                        st.session_state['health_score'] = calculate_health_score(st.session_state['telemetria'])

                        # Historial volátil (gráfico en vivo)
                        st.session_state['hist_time'].append(datetime.now().strftime("%H:%M:%S"))
                        st.session_state['hist_rx'].append(total_rx)
                        st.session_state['hist_tx'].append(total_tx)
                        if len(st.session_state['hist_time']) > 20:
                            st.session_state['hist_time'].pop(0)
                            st.session_state['hist_rx'].pop(0)
                            st.session_state['hist_tx'].pop(0)

                        # Historial persistente (tabla traffic_history en SQLite)
                        try:
                            info = st.session_state['telemetria']['info']
                            total_mem = int(info.get('total_memory', 1))
                            free_mem = int(info.get('free_memory', 0))
                            ram_pct = ((total_mem - free_mem) / total_mem) * 100 if total_mem > 0 else 0

                            db_snap = SessionLocal()
                            snapshot = TrafficSnapshot(
                                router_id=router_db.id,
                                total_rx=total_rx,
                                total_tx=total_tx,
                                cpu_load=info.get('cpu_load', 0),
                                ram_pct=round(ram_pct, 1),
                                connections=st.session_state['telemetria']['sec'].get('conexiones_activas', 0),
                                health_score=st.session_state['health_score']['total']
                            )
                            db_snap.add(snapshot)
                            db_snap.commit()
                            db_snap.close()
                        except Exception:
                            pass

                        # Auto-geolocalización (solo si aún no tiene coordenadas)
                        if not router_db.latitude or not router_db.longitude:
                            try:
                                geo = auto_geolocate_router(router.api, fallback_ip=router_db.ip_address)
                                if geo:
                                    db_geo = SessionLocal()
                                    r_update = db_geo.query(Router).filter(Router.id == router_db.id).first()
                                    if r_update:
                                        r_update.latitude = geo['lat']
                                        r_update.longitude = geo['lon']
                                        r_update.wan_ip = geo.get('wan_ip', '')
                                        r_update.location = f"{geo.get('city', '')}, {geo.get('country', '')}"
                                        db_geo.commit()
                                    db_geo.close()
                            except Exception:
                                pass

                        router.disconnect()
                        st.markdown(f'<div class="sync-badge">● Sync {datetime.now().strftime("%H:%M:%S")}</div>', unsafe_allow_html=True)
                    else:
                        st.session_state['telemetria'] = None
                        if not force_refresh:
                            st.error("🚨 Nodo Inalcanzable — La API no respondió.")
                            
                            st.warning("El router puede estar protegido por la secuencia Tok Tok (Port Knocking).")
                            
                            if st.button("🚪 Iniciar Desbloqueo Tok Tok", type="primary", use_container_width=True):
                                knock_dialog(router_db.ip_address)
                            
                            with st.expander("🛠️ Script de Configuración / Manual"):
                                from core.port_knock import get_knock_status_text, generate_mikrotik_script, generate_powershell_script
                                st.code(get_knock_status_text(router_db.ip_address), language="text")
                                st.markdown("**Reglas MikroTik:**")
                                st.code(generate_mikrotik_script(), language="bash")
                                st.markdown("**Script PowerShell Windows:**")
                                st.code(generate_powershell_script(router_db.ip_address), language="powershell")

    # --- CERRAR SESIÓN ---
    st.markdown("---")
    if st.button("🔒 Cerrar Sesión", use_container_width=True):
        st.session_state['logged_in'] = False
        for cookie in ["is_logged_in", "username", "role"]:
            cookies.remove(cookie)
        keys_to_clear = [k for k in st.session_state.keys() if k != 'logged_in']
        for k in keys_to_clear:
            del st.session_state[k]
        time.sleep(0.3)
        st.rerun()

# ==========================================
# 5. ALERTAS GLOBALES (AIOps)
# ==========================================
if st.session_state.get('telemetria'):
    latencia_servers = st.session_state['telemetria'].get('latencia', [])
    for srv in latencia_servers:
        if str(srv.get('status', '')).lower() == 'down':
            st.toast(f"CRÍTICO: {srv.get('comment')} CAÍDO", icon="🚨")
            st.markdown(f"""
            <div class="aiops-alert">
                <span class="aiops-alert-icon">🚨</span>
                <div>
                    <div class="aiops-alert-title">ALERTA AIOps CRÍTICA</div>
                    <div class="aiops-alert-body">
                        El equipo <strong>{srv.get('host')}</strong> ({srv.get('comment')}) ha dejado de responder.
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

# ==========================================
# 6. ENRUTADOR DE VISTAS (SPA)
# ==========================================

# Vistas globales (no requieren router conectado)
if menu_global == "Inventario de Nodos":
    render_inventory()

elif menu_global == "Herramientas NOC":
    from views.tools import render_tools
    render_tools()

# Vistas operativas (requieren router + telemetría)
else:
    if not router_db:
        st.markdown("""
        <div class="empty-state">
            <div class="empty-state-icon">🌐</div>
            <h2 class="empty-state-title">Sin Nodo Seleccionado</h2>
            <p class="empty-state-desc">Selecciona un equipo en el panel lateral para activar el centro de operaciones.</p>
        </div>
        """, unsafe_allow_html=True)
    elif not st.session_state.get('telemetria'):
        st.markdown("""
        <div class="empty-state">
            <div class="empty-state-icon" style="font-size: 3em;">🔄</div>
            <h3 class="empty-state-title">Estableciendo Conexión...</h3>
            <p class="empty-state-desc">Si no carga, presiona "Forzar Sincronización" en el panel lateral.</p>
        </div>
        """, unsafe_allow_html=True)
    else:
        telemetria = st.session_state['telemetria']
        if menu_global == "Vista General":
            render_overview(router_db, telemetria)
        elif menu_global == "Topología de Red":
            from views.topology import render_topology
            render_topology(router_db, telemetria)
        elif menu_global == "Inteligencia de Red":
            render_intelligence(router_db, telemetria)
        elif menu_global == "Centro Táctico":
            from views.tactical_console import render_tactical_console
            render_tactical_console(router_db, st.session_state['telemetria'])

# ==========================================
# 7. FOOTER
# ==========================================
st.markdown(f"""
<div class="soc-footer">
    <span>NOC</span> v4.0 • Security Operations Center • NetworkX • Scapy • Netmiko &copy; {datetime.now().year}
</div>
""", unsafe_allow_html=True)