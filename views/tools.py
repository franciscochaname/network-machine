import streamlit as st
import pandas as pd
from core.ip_tools import get_subnet_info, classify_ip, check_subnet_overlap, aggregate_cidrs, enumerate_hosts
from core.network_scanner import is_scapy_ready, arp_scan, tcp_port_scan, system_traceroute, system_ping
from core.ssh_manager import (
    SSHDeviceManager, get_supported_device_types, get_command_templates, is_netmiko_ready
)

def render_help_tip(key: str, content: str, icon: str = "ℹ️"):
    """Renderiza un bloque de ayuda que el usuario puede cerrar (descartar)."""
    if st.session_state.get(f"hide_tip_{key}", False):
        return
    
    with st.container(border=True):
        st.info(content, icon=icon)
        col1, col2 = st.columns([8, 2])
        with col2:
            if st.button("✖️ Ocultar", key=f"btn_close_tip_{key}", use_container_width=True):
                st.session_state[f"hide_tip_{key}"] = True
                st.rerun()


def render_tools():
    st.title(":material/handyman: Herramientas NOC Avanzadas")
    st.markdown("Suite de ingeniería de redes: Scanner, Calculadora CIDR, Terminal SSH Multi-Vendor.")

    tab_scanner, tab_cidr, tab_ssh = st.tabs([
        ":material/search: Network Scanner",
        ":material/architecture: Calculadora CIDR",
        ":material/computer: Terminal SSH"
    ])

    # ==========================================
    # 1. NETWORK SCANNER (Scapy)
    # ==========================================
    with tab_scanner:
        # Estado de Scapy
        if is_scapy_ready():
            st.success(":material/check_circle: Motor Scapy activo — Escaneo de paquetes disponible")
        else:
            st.warning(":material/warning_amber: Scapy no disponible (instalar Npcap). Usando escáner por socket como fallback.")

        col_type, col_ports = st.columns(2)
        with col_type:
            scan_type = st.radio("Tipo de Escaneo:", [
                "TCP Port Scan", "ARP Discovery", "Ping Local"
            ], horizontal=True)
            
        with col_ports:
            port_preset = None
            if scan_type == "TCP Port Scan":
                port_preset = st.radio("Puertos a escanear:", [
                    "Top 20 Comunes",
                    "MikroTik",
                    "Web",
                    "BDs",
                    "Personalizado"
                ], horizontal=True)

        if "TCP Port Scan" in scan_type:
            st.markdown("#### :material/api: Escaneo de Puertos TCP")
            render_help_tip("tcp", """
            **Propósito:** Auditar la seguridad buscando servicios abiertos o expuestos a internet.\n
            :material/emergency: **Casos de Emergencia:**
            - **Caídas de Servicio:** Saber inmediatamente si el puerto de tu BD (3306) o Web (443) se cerró inesperadamente.
            - **Vulnerabilidades:** Detectar si un troyano abrió un puerto oscuro o si dejaste expuesto el Winbox (8291) al público.
            """, icon=":material/security:")

            col1, col2 = st.columns([2, 1])
            with col1:
                target_ip = st.text_input("IP objetivo:", placeholder="192.168.20.1")
            # port_preset selection is now handled above in col_ports
            
            custom_ports = None
            if port_preset == "Personalizado":
                custom_text = st.text_input("Puertos (separados por coma):", placeholder="22, 80, 443")
                if custom_text:
                    custom_ports = [int(p.strip()) for p in custom_text.split(',') if p.strip().isdigit()]

            if st.button(":material/bolt: Iniciar Escaneo", type="primary", key="btn_portscan"):
                if target_ip:
                    ports_map = {
                        "Top 20 Comunes": None,
                        "MikroTik": [22, 80, 443, 8291, 8728, 8729],
                        "Web": [80, 443, 8080, 8443],
                        "BDs": [3306, 5432, 1433, 27017, 6379],
                        "Personalizado": custom_ports,
                    }
                    ports = ports_map.get(port_preset)

                    with st.spinner(f"Escaneando {target_ip}..."):
                        results = tcp_port_scan(target_ip, ports)

                    if results:
                        st.success(f":material/api: {len(results)} puerto(s) abierto(s) encontrado(s)")
                        df = pd.DataFrame(results)
                        
                        def evaluar_riesgo_puerto(port):
                            críticos = [21, 23, 3389, 445, 135, 139] # Telnet, RDP, SMB
                            atencion = [22, 3306, 5432, 8291, 27017] # SSH, DBs, Winbox
                            if port in críticos: return ":material/error: CRÍTICO (Inseguro)"
                            if port in atencion: return ":material/warning: Precaución (Gestión)"
                            return ":material/check_circle: Normal (Servicio Público)"

                        df['Riesgo de Seguridad'] = df['port'].apply(evaluar_riesgo_puerto)
                        df.rename(columns={'port': 'Puerto', 'state': 'Estado', 'service': 'Servicio', 'protocol': 'Protocolo'}, inplace=True)
                        
                        st.dataframe(
                            df, hide_index=True, use_container_width=True,
                            column_config={
                                "Riesgo de Seguridad": st.column_config.TextColumn("Evaluación de Riesgo")
                            }
                        )
                        
                        criticos_cnt = len(df[df['Riesgo de Seguridad'].str.contains('CRÍTICO')])
                        if criticos_cnt > 0:
                            st.warning(f":material/warning_amber: ¡ATENCIÓN! Se detectaron {criticos_cnt} puerto(s) críticos abiertos. Es urgente cerrarlos si están expuestos a internet directo.")
                    else:
                        st.info(":material/task_alt: Excelente: No se encontraron puertos abiertos en los puertos escaneados (Servidor blindado).")
                else:
                    st.warning("Ingresa una IP o dominio.")

        elif "ARP Discovery" in scan_type:
            st.markdown("#### :material/language: Descubrimiento ARP (Hardware)")
            render_help_tip("arp", """
            **Propósito:** Mapeo implacable de Nivel 2. Encuentra equipos físicos conectados a tu subred, ¡incluso si su Firewall de Windows bloquea el Ping!\n
            :material/emergency: **Casos de Emergencia:**
            - **Intrusos Wi-Fi/LAN:** Identificar rápidamente si hay dispositivos no reconocidos "robando" internet ocultos en la red.
            - **Conflictos de IP:** Encontrar la MAC address del equipo rebelde que se asignó una IP estática equivocada tirando otros servicios.
            """, icon="📡")

            if "telemetria" in st.session_state and st.session_state["telemetria"]:
                redes = st.session_state["telemetria"].get("local_networks", [])
                if redes:
                    opciones = [f"{r['network']} ({r.get('interface', 'LAN')})" for r in redes]
                    cidr_sel = st.selectbox("Selecciona una subred detectada en tu Nodo:", ["-- Ingresar Manualmente --"] + opciones)
                    if cidr_sel == "-- Ingresar Manualmente --":
                        cidr = st.text_input("Subred CIDR Manual:", placeholder="192.168.20.0/24")
                    else:
                        cidr = cidr_sel.split(' ')[0]
                else:
                    cidr = st.text_input("Subred CIDR:", placeholder="192.168.20.0/24")
            else:
                cidr = st.text_input("Subred CIDR:", placeholder="192.168.20.0/24", help="No hay Nodo Central activo, por favor escribe la subred del host actual.")

            import ipaddress
            def is_valid_cidr(c):
                try:
                    ipaddress.ip_network(c, strict=False)
                    return True
                except: return False

            if st.button(":material/search: Escanear Subred", type="primary", key="btn_arpscan"):
                if cidr and is_valid_cidr(cidr):
                    with st.spinner(f"Enviando paquetes ARP a {cidr}..."):
                        devices = arp_scan(cidr)
                    if devices:
                        st.success(f"📡 {len(devices)} dispositivo(s) descubierto(s) en la red física")
                        df = pd.DataFrame(devices)
                        df.rename(columns={'ip': 'Dirección IP', 'mac': 'MAC Address (Hardware)', 'vendor': 'Fabricante'}, inplace=True)
                        
                        # Añadir indicador visual de fabricante
                        def icon_vendor(v):
                            v_low = str(v).lower()
                            if 'apple' in v_low: return f"🍏 {v}"
                            if 'mikrotik' in v_low: return f":material/bolt: {v}"
                            if 'cisco' in v_low: return f":material/domain: {v}"
                            if 'desconocido' in v_low: return f"❓ Desconocido/Oculto"
                            return f":material/computer: {v}"
                            
                        df['Fabricante'] = df['Fabricante'].apply(icon_vendor)
                        
                        st.dataframe(df, hide_index=True, use_container_width=True)
                    else:
                        st.info("No se descubrieron dispositivos. Verifica que estés ejecutando la herramienta desde la misma red LAN del objetivo.")
                else:
                    st.error(":material/warning_amber: Por favor ingresa una subred CIDR válida (ej: 192.168.1.0/24).")



        elif "Ping" in scan_type:
            st.markdown("#### 📡 Ping de Supervivencia (ICMP)")
            render_help_tip("ping", """
            **Propósito:** Prueba de vida y tiempo de respuesta fundamental hacia un host.\n
            :material/emergency: **Casos de Emergencia:**
            - **Servidor Caído:** Comprobar instantáneamente (1 paquete) si el equipo principal sigue encendido y respondiendo en red.
            - **Micro-cortes:** Si el RTT fluctúa masivamente o se pierden, confirma saturación del CPU o del canal físico.
            """, icon=":material/bolt:")
            target = st.text_input("IP objetivo:", placeholder="8.8.8.8", key="ping_target")
            if st.button("📡 Enviar Pulso de 10 Paquetes (Ping)", type="primary", key="btn_ping"):
                if target:
                    with st.spinner(f"Enviando tren de 10 paquetes a {target}... (Aprox. 10s)"):
                        output = system_ping(target)
                        
                        import re
                        loss_match = re.search(r'\((\d+)%\s*(loss|perdidos)', output, re.IGNORECASE)
                        if not loss_match:
                            loss_match = re.search(r'(\d+)%\s*packet\s*loss', output, re.IGNORECASE)
                        perdida = int(loss_match.group(1)) if loss_match else 0
                        
                        tiempos_brutos = re.findall(r'(?:tiempo|time)[=<]\s*(\d+)\s*ms', output, re.IGNORECASE)
                        tiempos = [int(t) for t in tiempos_brutos]
                        
                        if tiempos:
                            promedio = sum(tiempos) // len(tiempos)
                            pico = max(tiempos)
                        else:
                            promedio = 0
                            pico = 0
                            
                        st.subheader("📡 Informe Biométrico de Ping")
                        c1, c2, c3, c4 = st.columns(4)
                        c1.metric("Paquetes Enviados", "10")
                        c2.metric("Pérdida (Packet Loss)", f"{perdida}%")
                        c3.metric("Latencia Promedio", f"{promedio} ms")
                        c4.metric("Picos (Max RTT)", f"{pico} ms")
                        
                        st.markdown("### :material/psychology: Diagnóstico de Estabilidad")
                        if perdida >= 50:
                            st.error(":material/emergency: CRITICO: El enlace está caído o sufriendo micro-cortes fatales (Pérdida superior al 50%). Es imposible mantener sesiones activas o telefonía.")
                        elif perdida > 0:
                            st.warning(f":material/warning_amber: PELIGRO: Conexión inestable. Se perdió el {perdida}% de los paquetes. Sufrirás desconexiones de VPN o cortes de voz/streaming constantes.")
                        elif promedio == 0 and perdida == 0 and not tiempos:
                            st.error(":material/cancel: El host no procesó el ICMP o la ruta es inalcanzable (Revisar DNS o Firewall).")
                        else:
                            if promedio > 150:
                                st.warning(f":material/warning: CONGESTIÓN DE RUTA: 0% pérdidas, pero latencia elevada ({promedio}ms). Enlace internacional, red saturada por exceso de tráfico, o conexión vía satélite.")
                            else:
                                st.success(f":material/task_alt: CONEXIÓN ÓPTIMA: Línea limpia. Excelente latencia ({promedio}ms) sin pérdida de información y totalmente estable para aplicaciones en tiempo real.")
                                
                        with st.expander(":material/build: Ver Registro Original del SO (Consola)", expanded=False):
                            st.code(output, language='text')

    with tab_cidr:
        st.markdown("#### :material/architecture: Herramientas de Direccionamiento Inteligente (CIDR)")
        st.caption("Arquitectura lógica — Powered by Netaddr")

        subtab_calc, subtab_classify, subtab_overlap = st.tabs([
            "🔢 División de Subredes", "🏷️ Analizador Forense IP", ":material/warning_amber: Radar de Solapamientos (Conflictos)"
        ])

        with subtab_calc:
            render_help_tip("cidr_calc", """
            **Propósito:** Es la base para diseñar y segmentar redes (Subnetting). Aquí puedes dividir grandes bloques de IPs en pedazos exactos. Te mostrará exactamente dónde inicia, dónde termina y qué tamaño tiene la red.
            :material/lightbulb: **Casos Prácticos:** Si el ISP te entrega una subred `/27` o armaste un túnel VPN y no quieres gastar más IPs de las necesarias, escríbelo aquí para ver cuántas computadoras caben exactamente y cuál es el Gateway ideal.
            """, icon=":material/architecture:")
            cidr_input = st.text_input("Dirección de Red o CIDR (Ej. 192.168.20.0/24):", placeholder="192.168.20.0/24", key="cidr_calc")

            if cidr_input:
                info = get_subnet_info(cidr_input)
                if info:
                    c1, c2, c3 = st.columns(3)
                    c1.metric(":material/language: Identificador de Red (ID)", info['network'])
                    c2.metric("📡 IP de Broadcast (Fin)", info['broadcast'])
                    c3.metric(":material/group: Equipos Soportados (Hosts)", f"{info['usable_hosts']:,}")
                    
                    st.markdown("#### :material/bar_chart: Desglose de Parámetros Clave")
                    col_a, col_b, col_c = st.columns(3)
                    col_a.metric("Primer Host Asignable", info['first_host'])
                    col_b.metric("Último Host Asignable", info['last_host'])
                    col_c.metric("Total Absoluto (Reserva CPU)", f"{info['total_hosts']:,} IPs")
                    
                    col_d, col_e, col_f = st.columns(3)
                    col_d.metric("Máscara de Subred", info['netmask'])
                    col_e.metric("Wildcard (Usable para OSPF)", info['wildcard'])
                    col_f.metric("Naturaleza de IP", "Privada (LAN)" if info['is_private'] else "Pública (Internet) :material/public:")

                    with st.expander("📋 Exportar Secuencia de IPs (Ejemplo para OSPF/Acls/Inventario)"):
                        hosts = enumerate_hosts(cidr_input, limit=256)
                        st.code('\n'.join(hosts), language="text")

        with subtab_classify:
            render_help_tip("cidr_class", """
            **Propósito:** Auditoría forense del Nivel 3 (Capa de Red). Desnuda cualquier IP indicando de forma inmediata su composición y para qué la diseñó la organización mundial en sus orígenes.
            :material/lightbulb: **Casos Prácticos:** Si detectas tráfico de red yendo a IPs extrañas como `169.254.x.x` (Cable desconectado/Fallido) o clases tipo D como `224.0.0.9`, el clasificador interpretará esos flujos automáticamente advirtiéndote y mostrándote conversiones directas usadas por programadores y firewalls duros.
            """, icon="🏷️")
            ip_input = st.text_input("Dirección Analítica IP (Ej. 10.15.5.1):", placeholder="192.168.20.1", key="ip_classify")
            if ip_input:
                info = classify_ip(ip_input)
                if 'error' not in info:
                    c1, c2, c3 = st.columns(3)
                    c1.metric("🏷️ Categoría", info['classification'])
                    c2.metric(":material/bar_chart: Clase Tradicional", info['net_class'])
                    c3.metric("🔢 Estándar", f"IPv{info['version']}")

                    st.markdown(f"""
                    **Código Hexadecimal Interno:** `{info['hex']}`
                    
                    **Traducción Métrica a Binario (Capa Física):**
                    ```
                    {info['binary']}
                    ```
                    """)

                    st.markdown("##### Cumplimiento de Políticas Universales")
                    props = {"Enrutamiento (Unicast)": info['is_unicast'], 
                             "Secreto de Oficina (Privada LAN)": info['is_private'],
                             "Interface Virtual (Loopback)": info['is_loopback'], 
                             "Difusión Masiva Grupal (Multicast)": info['is_multicast']}
                    cols = st.columns(len(props))
                    for i, (k, v) in enumerate(props.items()):
                        cols[i].metric(k, ":material/task_alt: SÍ" if v else ":material/cancel: NO")

        with subtab_overlap:
            render_help_tip("cidr_overlap", """
            **Propósito:** Interceptor Anti-Catástrofes de Enrutamiento. Analiza cruces invisibles donde los segmentos de host chocan.
            :material/emergency: **Emergencias en Túneles VPN:** El error mortal más frecuente es conectar la Sucursal Urbana que reparte la red DHCP `192.168.1.0/24` con otra Sucursal Externa que sin saberlo enrute exactamente su propio segmento interno idéntico `192.168.1.0/24`. Resultado: Choque masivo de ruteo cerrado, colapso de red para ambas plantas. Pon las redes a empatar aquí antes de programar los túneles y detectaremos el choque invisible.
            """, icon=":material/warning_amber:")
            st.markdown("Introduce todos los bloques que pretendes unir para verificar superposiciones o choques de Redes (Una subred por línea):")
            subnets_text = st.text_area("Subredes, Túneles VPN o CIDRs:", placeholder="192.168.10.0/24\n192.168.10.128/25\n10.0.0.0/8",
                                        height=120, key="overlap_input")

            if st.button(":material/search: Analizar Colisiones de Ruteo", type="primary", key="btn_overlap"):
                if subnets_text:
                    cidrs = [line.strip() for line in subnets_text.strip().split('\n') if line.strip()]

                    overlaps = check_subnet_overlap(cidrs)
                    if overlaps:
                        st.error(f":material/emergency: ALERTA ROJA: {len(overlaps)} COLISIONES DETECTADAS. Las siguientes combinaciones resultarán en conflicto de bucle ciego de enrutamiento (Network Collision o Routing Loop):")
                        st.dataframe(pd.DataFrame(overlaps), hide_index=True, use_container_width=True)
                    else:
                        st.success(":material/task_alt: Certificado Operativo: Ninguna de las rutas especificadas choca con otra. Es seguro conectar/routear juntas estas sucursales u oficinas y armar los Túneles.")

                    aggregated = aggregate_cidrs(cidrs)
                    st.markdown(f"**Recomendación de Compresión de Rutas BGP/OSPF (Optimiza y Aligera el consumo en memoria RAM del procesador):**")
                    st.code(', '.join(aggregated), language="text")

    # ==========================================
    # 3. TERMINAL SSH MULTI-VENDOR (Netmiko)
    # ==========================================
    with tab_ssh:
        st.markdown("#### :material/computer: Terminal de Ejecución Remota Multi-Vendor")
        st.caption("Arquitectura CLI Universal — Powered by Netmiko")
        
        render_help_tip("ssh_terminal", """
        **Propósito:** Consola de Administración Centralizada. Te permite inyectar secuencias de comandos directamente en el núcleo físico (CLI) de routers o switches de cualquier marca del mundo, sin necesidad de Putty ni VPNs adicionales.
        :material/emergency: **Casos de Emergencia (NOC Activo):**
        - **Recuperación tras Desastre:** Respaldar la configuración entera en texto plano de un router MikroTik o Cisco antes de que su Memoria Flash colapse permanentemente.
        - **Auditoría de Infección:** Tirar un comando manual oculto al sistema operativo del equipo para ver las tablas BGP o reglas de Firewall que fueron modificadas por un intruso.
        """, icon=":material/computer:")

        if not is_netmiko_ready():
            st.error("Netmiko no disponible. Instala con: pip install netmiko")
            return

        st.success(":material/check_circle: Driver Netmiko activo: Soporte garantizado para MikroTik, Cisco, Juniper, Ubiquiti, y +70 marcas.")

        st.markdown("---")
        # Formulario de conexión
        st.markdown("##### 🔌 Parámetros de Enlace")
        col1, col2, col3, col_port = st.columns([2, 2, 2, 1])
        with col1:
            ssh_host = st.text_input("IP Objetivo (Host):", placeholder="192.168.20.1", key="ssh_host")
        with col2:
            ssh_user = st.text_input("Credencial (Usuario):", placeholder="admin", key="ssh_user")
        with col3:
            ssh_pass = st.text_input("Llave (Contraseña):", type="password", key="ssh_pass")
        with col_port:
            ssh_port = st.number_input("Puerto SSH:", value=22, min_value=1, max_value=65535, key="ssh_port")
            
        st.markdown("<br>", unsafe_allow_html=True)
        col_type, col_blank = st.columns([3, 5])
        with col_type:
            device_types = get_supported_device_types()
            ssh_type = st.selectbox("Arquitectura del Equipo (Vendor):", list(device_types.keys()),
                                    format_func=lambda x: device_types[x]['name'])

        st.markdown("---")
        st.markdown("##### :material/rocket_launch: Ejecución Táctica de Comandos")
        
        templates = get_command_templates(ssh_type)

        col_template, col_custom = st.columns([1, 2])
        with col_template:
            if templates:
                template_choice = st.selectbox("Inyectar Autómata (Comando Predefinido):",
                                               ["-- Selección Manual --"] + list(templates.keys()),
                                               format_func=lambda x: x.replace('_', ' ').title() if x != "-- Selección Manual --" else x)
        with col_custom:
            custom_cmd = st.text_input("O inyectar código CLI personalizado:", placeholder="Por ej: /ip address print o show ip interface brief",
                                       key="ssh_custom_cmd")

        st.markdown("<br>", unsafe_allow_html=True)
        col_exec, col_backup, col_esp = st.columns([2, 2, 4])
        with col_exec:
            ejecutar = st.button(":material/bolt: Fuego (Ejecutar en Host)", type="primary", use_container_width=True, key="btn_ssh_exec")
        with col_backup:
            backup = st.button("💾 Extracción de Respaldo", use_container_width=True, key="btn_ssh_backup")

        # Ejecución
        if ejecutar or backup:
            if ssh_host and ssh_user and ssh_pass:
                manager = SSHDeviceManager(ssh_host, ssh_user, ssh_pass, ssh_type, ssh_port)

                with st.spinner(f"Negociando llaves RSA y conectando a {ssh_host}..."):
                    success, msg = manager.connect()

                if success:
                    st.success(f":material/task_alt: Handshake exitoso: {msg}")

                    with st.spinner("Compilando y ejecutando rutinas CLI..."):
                        if backup:
                            ok, output = manager.backup_config()
                        elif custom_cmd:
                            ok, output = manager.execute_command(custom_cmd)
                        elif templates and template_choice != "-- Selección Manual --":
                            ok, output = manager.execute_template(template_choice)
                        else:
                            ok, output = False, "No se ha armado ninguna orden. Selecciona o escribe un comando."

                    manager.disconnect()

                    if ok:
                        st.markdown("##### 📄 Respuesta del Kernel:")
                        st.code(output, language="text")

                        # Botón de descarga interactivo
                        if backup:
                            st.download_button(
                                "📥 Descargar Certificado de BackUp (.txt)",
                                output,
                                file_name=f"SysBackup_{ssh_host}.txt",
                                mime="text/plain",
                                use_container_width=True
                            )
                    else:
                        st.error(f"Fallo de Capa Aplicación: {output}")
                else:
                    st.error(f":material/cancel: Fallo masivo de Autenticación o Ruta inaccesible: {msg}")
            else:
                st.error(":material/warning_amber: Operación Denegada: Todos los campos (Host, Usuario, Contraseña) son obligatorios para establecer el túnel SSH.")
