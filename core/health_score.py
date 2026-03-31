# core/health_score.py
"""
Motor de cálculo del Network Health Score.
Genera un índice compuesto 0-100 basado en múltiples indicadores de salud del equipo.
"""


def calculate_health_score(telemetria: dict) -> dict:
    """
    Calcula el puntaje de salud de la red basado en telemetría.
    
    Pesos (8 componentes):
        CPU Load:       15%
        RAM Usage:      10%
        FW Saturation:  15%
        Services (NW):  20%
        Temperature:    10%
        Uptime Stab.:   10%
        Elec. Stab.:    10%
        Interface HP:   10%
    
    Returns:
        dict con 'total' (0-100), 'grade', 'label', 'color' y desglose por componente.
    """
    info = telemetria.get('info', {})
    sec = telemetria.get('sec', {})
    latencia = telemetria.get('latencia', [])

    # --- CPU (20%) ---
    cpu = info.get('cpu_load', 0)
    cpu_score = max(0, 100 - cpu * 1.2)  # Penalización acelerada > 80%

    # --- RAM (15%) ---
    free_mem = int(info.get('free_memory', 0))
    total_mem = int(info.get('total_memory', 1))
    ram_pct = ((total_mem - free_mem) / total_mem) * 100 if total_mem > 0 else 0
    ram_score = max(0, 100 - ram_pct)

    # --- Firewall Saturation (20%) ---
    conn = sec.get('conexiones_activas', 0)
    max_conn = sec.get('max_conexiones', 300000)
    fw_pct = (conn / max_conn) * 100 if max_conn > 0 else 0
    fw_score = max(0, 100 - fw_pct * 1.5)  # Penalización acelerada > 66%

    # --- Services / Netwatch (25%) ---
    total_services = len(latencia)
    if total_services > 0:
        up_services = len([s for s in latencia if str(s.get('status', '')).lower() == 'up'])
        svc_score = (up_services / total_services) * 100
    else:
        svc_score = 100  # Sin netwatch = asumimos OK

    # --- Temperature (10%) ---
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

    # --- Electrical Stability (NUEVO) ---
    volt = info.get('voltage', 'N/A')
    volt_score = 100
    try:
        v = float(volt)
        if v < 11.0: # Caída fuerte en 12V
            volt_score = 30
        elif 18.0 < v < 22.0: # Caída en 24V
            volt_score = 50
    except: pass

    # --- Interface Health (NUEVO) ---
    iface_errs = telemetria.get('interface_health', [])
    iface_score = 100 - (len(iface_errs) * 20)
    iface_score = max(0, iface_score)

    # --- CÁLCULO FINAL (Ajustado para incluir Voltage e Interface Health) ---
    total = (
        cpu_score * 0.15 +
        ram_score * 0.10 +
        fw_score * 0.15 +
        svc_score * 0.20 +
        temp_score * 0.10 +
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
            'Temp': round(temp_score, 1),
            'Stab': round(uptime_score, 1),
            'Elec': round(volt_score, 1),
            'Iface': round(iface_score, 1),
        }
    }
