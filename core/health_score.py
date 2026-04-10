# core/health_score.py
"""
Motor de cálculo del Network Health Score.
Genera un índice compuesto 0-100 basado en múltiples indicadores de salud del equipo.
"""


def calculate_health_score(telemetria: dict) -> dict:
    """
    Calcula el puntaje de salud de la red basado en telemetría.
    
    Pesos (9 componentes — suman 100%):
        CPU Load:       12%
        RAM Usage:       8%
        FW Saturation:  12%
        Services (NW):  15%
        WAN Connectiv.: 15%  ← NUEVO: estado de internet
        Temperature:     8%
        Uptime Stab.:   10%
        Elec. Stab.:    10%
        Interface HP:   10%
    
    Returns:
        dict con 'total' (0-100), 'grade', 'label', 'color' y desglose por componente.
    """
    info = telemetria.get('info', {})
    sec = telemetria.get('sec', {})
    latencia = telemetria.get('latencia', [])
    wan = telemetria.get('wan_status', {})

    # --- CPU (12%) ---
    cpu = info.get('cpu_load', 0)
    cpu_score = max(0, 100 - cpu * 1.2)  # Penalización acelerada > 80%

    # --- RAM (8%) ---
    free_mem = int(info.get('free_memory', 0))
    total_mem = int(info.get('total_memory', 1))
    ram_pct = ((total_mem - free_mem) / total_mem) * 100 if total_mem > 0 else 0
    ram_score = max(0, 100 - ram_pct)

    # --- Firewall Saturation (12%) ---
    conn = sec.get('conexiones_activas', 0)
    max_conn = sec.get('max_conexiones', 300000)
    fw_pct = (conn / max_conn) * 100 if max_conn > 0 else 0
    fw_score = max(0, 100 - fw_pct * 1.5)  # Penalización acelerada > 66%

    # --- Services / Netwatch (15%) ---
    total_services = len(latencia)
    if total_services > 0:
        up_services = len([s for s in latencia if str(s.get('status', '')).lower() == 'up'])
        svc_score = (up_services / total_services) * 100
    else:
        svc_score = 100  # Sin netwatch = asumimos OK

    # --- WAN Connectivity (15%) — NUEVO ---
    wan_score = 100
    if wan:
        wans = wan.get('wans', [])
        active_wan = wan.get('active_wan', None)
        if not wans:
            # No hay rutas default → sin internet
            wan_score = 0
        elif not active_wan:
            # Hay rutas pero ninguna activa → internet caído
            wan_score = 10
        elif wan.get('has_failover', False):
            # Tiene failover configurado → excelente resiliencia
            # Pero verificar si está en la principal o en el respaldo
            if active_wan.get('distance', 1) > 1:
                wan_score = 60  # Corriendo en respaldo
            else:
                wan_score = 100  # Principal activa + failover disponible
        else:
            # Solo una WAN activa sin respaldo
            wan_score = 80
    else:
        wan_score = 50  # No se pudo obtener WAN status

    # --- Temperature (8%) ---
    try:
        temp = float(info.get('temperature', 40))
        if temp <= 45:
            temp_score = 100
        elif temp <= 60:
            temp_score = 100 - ((temp - 45) * 3.33)
        else:
            temp_score = max(0, 100 - ((temp - 45) * 5))
    except (ValueError, TypeError):
        temp_score = 80

    # --- Uptime Stability (10%) ---
    uptime_str = info.get('uptime', '0s')
    if 'w' in uptime_str:       # Semanas = excelente
        uptime_score = 100
    elif 'd' in uptime_str:     # Días = estable
        uptime_score = 90
    elif 'h' in uptime_str:     # Horas = recién reiniciado
        uptime_score = 60
    else:                       # Minutos/segundos = inestable
        uptime_score = 30

    # --- Electrical Stability (10%) ---
    volt = info.get('voltage', 'N/A')
    volt_score = 100
    try:
        v = float(volt)
        if v < 11.0: # Caída fuerte en 12V
            volt_score = 30
        elif 18.0 < v < 22.0: # Caída en 24V
            volt_score = 50
    except: pass

    # --- Interface Health (10%) ---
    iface_errs = telemetria.get('interface_health', [])
    iface_score = 100 - (len(iface_errs) * 20)
    iface_score = max(0, iface_score)

    # --- CÁLCULO FINAL (9 componentes, pesos suman 100%) ---
    total = (
        cpu_score * 0.12 +
        ram_score * 0.08 +
        fw_score * 0.12 +
        svc_score * 0.15 +
        wan_score * 0.15 +
        temp_score * 0.08 +
        uptime_score * 0.10 +
        volt_score * 0.10 +
        iface_score * 0.10
    )

    # Clasificación
    if total >= 85:
        grade = "A"
        label = "Excelente"
        color = "#00FFAA"
    elif total >= 70:
        grade = "B"
        label = "Bueno"
        color = "#00F0FF"
    elif total >= 50:
        grade = "C"
        label = "Inestable"
        color = "#FFAA00"
    elif total >= 30:
        grade = "D"
        label = "Fallo Parcial"
        color = "#FF6B35"
    else:
        grade = "F"
        label = "Fallo Crítico"
        color = "#FF4B4B"

    return {
        'total': round(total, 1),
        'grade': grade,
        'label': label,
        'color': color,
        'breakdown': {
            'CPU': round(cpu_score, 1),
            'RAM': round(ram_score, 1),
            'Fwall': round(fw_score, 1),
            'Svc': round(svc_score, 1),
            'WAN': round(wan_score, 1),
            'Temp': round(temp_score, 1),
            'Stab': round(uptime_score, 1),
            'Elec': round(volt_score, 1),
            'Iface': round(iface_score, 1),
        }
    }

