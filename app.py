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



from views.overview import render_overview
from views.inventory import render_inventory
from views.intelligence import render_intelligence
from components.login import render_login

# ==========================================
# 1. CONFIGURACIÓN GLOBAL
# ==========================================
st.set_page_config(
    page_title="Network Operations Center",
    page_icon=":material/language:",
    layout="wide",
    initial_sidebar_state="expanded"
)

load_global_css()

# ==========================================
# 2. COOKIES Y ESTADO DE SESIÓN (SECURIZADAS CON HMAC)
# ==========================================
cookies = CookieController()
time.sleep(0.3)

from core.crypto import verify_session_token, create_session_token

if 'logged_in' not in st.session_state:
    session_token = cookies.get("session_token")
    if session_token:
        session_data = verify_session_token(str(session_token))
        if session_data:
            st.session_state['logged_in'] = True
            st.session_state['username'] = session_data['u']
            st.session_state['role'] = session_data['r']
        else:
            st.session_state['logged_in'] = False
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

    # Contador de alertas activas
    alert_history = st.session_state.get('alert_history', [])
    n_critical = sum(1 for a in alert_history if a.get('severity') == 'critical')
    n_total = len(alert_history)
    badge_html = ""
    if n_total > 0:
        badge_html = f'<span class="soc-counter">{n_critical if n_critical > 0 else n_total}</span>'

    st.markdown(f"""
    <div class="sidebar-profile">
        <div class="sidebar-profile-inner">
            <div class="sidebar-avatar">{safe_username[0].upper()}</div>
            <div>
                <div class="sidebar-username">{safe_username.upper()}{badge_html}</div>
                <div class="sidebar-role">{safe_role}</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

    # --- INFRAESTRUCTURA PRIMERO (HARD LOCK) ---
    db = SessionLocal()
    routers_db = db.query(Router).all()
    db.close()

    router_db = None
    force_refresh = False

    if not routers_db:
        st.markdown("""
        <div style="background-color: rgba(255, 170, 0, 0.1); border-left: 4px solid #FFAA00; padding: 12px; margin-bottom: 10px; border-radius: 4px;">
            <p style="margin: 0; color: #FFAA00; font-size: 13px; font-weight: bold;"><i class="fa-solid fa-triangle-exclamation"></i> INFRAESTRUCTURA VACÍA</p>
            <p style="margin: 5px 0 0 0; color: #ccc; font-size: 12px;">No existen nodos L3 registrados. Diríjase a <b>Inventario Infraestructura</b> para dar de alta su primer equipo.</p>
        </div>
        """, unsafe_allow_html=True)
    else:
        st.markdown('<p class="sidebar-section-label"><i class="fa-solid fa-server"></i> NODO BASE OPERATIVO</p>', unsafe_allow_html=True)
        opciones = {f"{r.name} ({r.ip_address})": r for r in routers_db}
        nombres_menu = ["-- Seleccionar Nodo Central --"] + list(opciones.keys())
        seleccion = st.selectbox("Nodo Central", nombres_menu, label_visibility="collapsed")

        if seleccion == "-- Seleccionar Nodo Central --":
            router_db = None
            st.markdown("""
            <div style="background: rgba(0, 240, 255, 0.1); border-left: 3px solid #00F0FF; padding: 10px; margin-top: 5px; border-radius: 4px; margin-bottom: 15px;">
                <span style="color: #00F0FF; font-size: 13px; font-weight: bold;"><i class="fa-solid fa-caret-up"></i> SELECCIONE UNA NUBE</span>
                <p style="color: #aaa; font-size: 11px; margin: 3px 0 0 0;">Debe acoplarse visualmente a un nodo para extraer datos NetOps.</p>
            </div>
            """, unsafe_allow_html=True)
        else:
            router_db = opciones[seleccion]

    st.markdown("---")

    # --- MENU RESTRINGIDO POR ESTADO L3 ---
    if 'menu_key' not in st.session_state:
        st.session_state['menu_key'] = 0

    if not router_db:
        opciones_menu = ["Panel General", "Inventario Infraestructura"]
        iconos_menu = ["activity", "server"]
        titulo_menu = "NOC / SOC"
        color_tema = "#00F0FF"
        icono_tema = "cpu-fill"
    else:
        opciones_menu = ["Visión Global AIOps", "Topología L2/L3",
                 "Inteligencia NOC", "Consola Táctica (SOC)", "Herramientas NetOps", "Inventario Infraestructura"]
        iconos_menu = ["activity", "diagram-2-fill",
               "radar", "shield-shaded", "wrench-adjustable", "server"]
        titulo_menu = "NOC / SOC"
        color_tema = "#00F0FF"
        icono_tema = "cpu-fill"

    menu_global = option_menu(
        menu_title=titulo_menu,
        options=opciones_menu,
        icons=iconos_menu,
        menu_icon=icono_tema, default_index=0,
        key=f"sidebar_menu_{st.session_state['menu_key']}",
        styles={
            "container": {"padding": "5px !important", "background-color": "transparent"},
            "icon": {"color": color_tema, "font-size": "16px"},
            "nav-link": {
                "font-size": "13px", "text-align": "left", "margin": "2px 0",
                "border-radius": "8px", "padding": "10px 15px",
                "color": "#999" if router_db else "#666", "font-weight": "500",
                "--hover-color": "rgba(0, 240, 255, 0.05)"
            },
            "nav-link-selected": {
                "background": "linear-gradient(135deg, rgba(0, 240, 255, 0.1), rgba(177, 0, 255, 0.05))" if router_db else "rgba(255,255,255,0.05)",
                "border-left": f"3px solid {color_tema}",
                "color": "white", "font-weight": "600"
            },
        }
    )

    if router_db:
        st.markdown("---")
        st.markdown('<p class="sidebar-refresh-label"><i class="fa-solid fa-clock-rotate-left"></i> Ciclo de Telemetría (Polling)</p>', unsafe_allow_html=True)
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
                    ok, conn_msg = router.connect()
                    if ok:
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
                            "ethernet_neighbors": router.get_ethernet_neighbors(),
                            "bridge_hosts": router.get_bridge_hosts(),
                            "interface_health": router.get_interface_health(),
                            "sfp_diagnostics": router.get_sfp_diagnostics(),
                            "wan_status": router.get_wan_status(),
                            # --- Funciones previamente muertas, ahora ACTIVAS ---
                            "routing_health": router.get_routing_health(),
                            "dns_config": router.get_dns_config(),
                            "storage_info": router.get_storage_info(),
                            "protocol_distribution": router.get_protocol_distribution() if force_l7 else {},
                            "bandwidth_by_subnet": router.get_bandwidth_by_subnet() if force_l7 else [],
                            "active_queues": router.get_active_queues(),
                            # --- Metadatos de sincronización ---
                            "sync_timestamp": datetime.now().strftime("%H:%M:%S"),
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

                        # Auto-geolocalización (solo si NUNCA fue configurado — None, no 0.0)
                        if router_db.latitude is None or router_db.longitude is None:
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
                            from core.router_base import check_port_open
                            import socket

                            # Detectar la IP actual de esta máquina
                            try:
                                mi_ip = socket.gethostbyname(socket.gethostname())
                            except Exception:
                                mi_ip = "TU_IP"

                            puerto_abierto = check_port_open(router_db.ip_address, 8728, timeout=2.0)

                            if conn_msg == "CREDENTIALS" or (puerto_abierto and conn_msg != "BLOCKED"):
                                # Puerto abierto pero credenciales incorrectas
                                st.error(":material/key: Credenciales incorrectas o servicio API deshabilitado.")
                                st.markdown(f"""
                                <div style="background:rgba(255,170,0,0.08);border-left:4px solid #FFAA00;padding:16px;border-radius:6px;margin-top:8px;">
                                    <h4 style="margin:0 0 10px 0;color:#FFAA00;">:material/key: Solución — Verificar en WinBox</h4>
                                    <p style="color:#ccc;font-size:13px;margin-bottom:8px;">Conecta a <b>{router_db.ip_address}</b> por WinBox y ejecuta en Terminal (New Terminal):</p>
                                    <pre style="background:#111;padding:10px;border-radius:4px;font-size:12px;color:#00FF88;">/ip service print
# Verificar que 'api' esté enabled y address esté vacío.
# Si address tiene una IP específica, límpiala:
/ip service set api address=""</pre>
                                    <p style="color:#888;font-size:12px;margin-top:8px;">También verifica que el usuario tenga permisos <b>full</b> en /system/user.</p>
                                </div>
                                """, unsafe_allow_html=True)

                            else:
                                # Puerto bloqueado por firewall
                                st.error(f":material/lock: API bloqueada en {router_db.ip_address}:8728 — El firewall rechaza la conexión.")
                                st.markdown(f"""
                                <div style="background:rgba(255,60,60,0.08);border-left:4px solid #ff3c3c;padding:16px;border-radius:6px;margin-top:8px;">
                                    <h4 style="margin:0 0 10px 0;color:#ff3c3c;">:material/security: Solución — Dar acceso en WinBox</h4>
                                    <p style="color:#ccc;font-size:13px;margin-bottom:8px;">Conecta a <b>{router_db.ip_address}</b> por WinBox y ejecuta en Terminal (New Terminal):</p>
                                    <pre style="background:#111;padding:10px;border-radius:4px;font-size:12px;color:#00FF88;"># Agrega tu IP a la lista de acceso permitido:
/ip firewall address-list add \\
    list=API_Segura \\
    address={mi_ip} \\
    comment="NOC Dashboard - Acceso Temporal"

# Verifica que estas 2 reglas existan en /ip/firewall/filter:
# ACCEPT: chain=input dst-port=8728 src-address-list=API_Segura
# DROP:   chain=input dst-port=8728 (al final)</pre>
                                    <p style="color:#888;font-size:12px;margin-top:8px;">Tu IP detectada: <b>{mi_ip}</b> · Router: <b>{router_db.ip_address}</b></p>
                                </div>
                                """, unsafe_allow_html=True)

                                with st.expander(":material/network_check: Diagnóstico de puertos"):
                                    from core.router_base import check_port_open as _chk
                                    for p, label in [(8728, "API (8728)"), (8291, "WinBox (8291)"), (22, "SSH (22)"), (80, "HTTP (80)")]:
                                        ok_p = _chk(router_db.ip_address, p, timeout=1.5)
                                        st.markdown(f"{'🟢' if ok_p else '🔴'} **{label}** — {'ABIERTO' if ok_p else 'BLOQUEADO/CERRADO'}")

    # --- CERRAR SESIÓN ---
    st.markdown("---")
    if st.button(":material/lock_outline: Cerrar Sesión", use_container_width=True):
        st.session_state['logged_in'] = False
        # SEC-03: Limpiar token firmado
        try:
            cookies.remove("session_token")
        except Exception:
            pass
        keys_to_clear = [k for k in st.session_state.keys() if k != 'logged_in']
        for k in keys_to_clear:
            try:
                del st.session_state[k]
            except Exception:
                pass
        time.sleep(0.3)
        st.rerun()

# ==========================================
# 5. ALERTAS GLOBALES (AIOps) — Registro persistente
# ==========================================
if st.session_state.get('telemetria'):
    latencia_servers = st.session_state['telemetria'].get('latencia', [])
    from views.overview import _alert_register
    for srv in latencia_servers:
        if str(srv.get('status', '')).lower() == 'down':
            _alert_register('critical', f"Servidor CAÍDO: {srv.get('comment', srv.get('host', '?'))}")
            st.toast(f"🚨 {srv.get('comment')} — CAÍDO", icon=":material/emergency:")

# ==========================================
# 6. ENRUTADOR DE VISTAS (SPA)
# ==========================================

# Vistas globales (no requieren router conectado)
if menu_global == "Inventario Infraestructura":
    render_inventory()

elif menu_global == "Herramientas NetOps":
    from views.tools import render_tools
    render_tools()

# Vistas operativas (requieren router + telemetría)
else:
    if not routers_db:
        st.markdown("""
        <div class="empty-state">
            <div class="empty-state-icon" style="color: #FFAA00; font-size: 4em;"><i class="fa-solid fa-server"></i></div>
            <h2 class="empty-state-title">Despliegue Cero (Zero-Day Setup)</h2>
            <p class="empty-state-desc" style="max-width: 600px; margin: 0 auto;">No existen equipos enrutadores / firewalls registrados en la base de datos forense.</p>
            <br>
            <div style="text-align: left; background: rgba(0,0,0,0.3); padding: 20px; border-radius: 8px; border: 1px solid #333; max-width: 500px; margin: 0 auto;">
                <h4 style="color: #00F0FF; margin-top: 0;"><i class="fa-solid fa-clipboard-check"></i> Requisitos Críticos Previos:</h4>
                <ul style="color: #ccc; font-size: 14px;">
                    <li>Estar conectado físicamente (LAN) o lógicamente (Túnel VPN / OSPF) con la IP de Gestión del equipo.</li>
                    <li>Tener habilitado el <b>Servicio API de MikroTik</b> (puerto 8728 por defecto o custom).</li>
                    <li>Disponer de credenciales nivel 'full' o escalado de privilegios equivalente.</li>
                </ul>
            </div>
        </div>
        """, unsafe_allow_html=True)
    elif not router_db:
        st.markdown("""
        <div class="empty-state" style="margin-top: 10%;">
            <div class="empty-state-icon" style="color: #444; font-size: 6em; margin-bottom: 20px;"><i class="fa-solid fa-plug-circle-xmark"></i></div>
            <h2 class="empty-state-title" style="color: #666; font-weight: 400;">Telemetría en Espera</h2>
            <div style="display: inline-block; background: rgba(0, 240, 255, 0.1); border-left: 4px solid #00F0FF; padding: 12px 25px; border-radius: 4px; margin-top: 15px;">
                <span style="color: #00F0FF; font-size: 16px; font-weight: bold;"><i class="fa-solid fa-angles-left"></i> SELECCIONE UN NODO OPERATIVO EN EL PANEL LATERAL</span>
            </div>
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
        if menu_global == "Visión Global AIOps":
            render_overview(router_db, telemetria)
        elif menu_global == "Topología L2/L3":
            from views.topology import render_topology
            render_topology(router_db, telemetria)
        elif menu_global == "Inteligencia NOC":
            render_intelligence(router_db, telemetria)
        elif menu_global == "Consola Táctica (SOC)":
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