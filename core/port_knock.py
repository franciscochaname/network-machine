# core/port_knock.py
"""
Motor de Port Knocking — Desbloqueo Seguro de API MikroTik.

Envía una secuencia de 3 toques TCP (puertos 7000 → 8000 → 9000)
para desbloquear el acceso a la API (puerto 8728) por 5 minutos.

Requiere configuración previa en el MikroTik:
  - Fase 1: dst-port=7000 → add-src-to-address-list=Knock_Fase1 (15s)
  - Fase 2: dst-port=8000 + src-address-list=Knock_Fase1 → Knock_Fase2 (15s)
  - Fase 3: dst-port=9000 + src-address-list=Knock_Fase2 → API_Segura (5m)
  - Accept: dst-port=8728 + src-address-list=API_Segura
  - Drop:   dst-port=8728 (global fallback)
"""
import socket
import time
import logging


def port_knock(host: str, sequence: list = None, delay: float = 0.6, timeout: float = 0.5) -> tuple:
    """
    Ejecuta la secuencia de port knocking contra un host.

    Args:
        host:     IP o hostname del router MikroTik.
        sequence: Lista de puertos a tocar en orden. Default: [7000, 8000, 9000]
        delay:    Segundos de espera entre cada toque.
        timeout:  Timeout de conexión TCP por toque.

    Returns:
        (success: bool, message: str)
    """
    if sequence is None:
        sequence = [7000, 8000, 9000]

    logging.info(f"Iniciando Port Knocking hacia {host} con secuencia {sequence}...")
    try:
        for port in sequence:
            try:
                # Usamos un socket con un timeout pequeño para el "toque"
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(timeout)
                # Intentamos conectar. No importa el resultado, el SYN ya llegó al router.
                sock.connect_ex((host, port))
                sock.close()
                logging.info(f"  [Tok] Puerto {port} tocado.")
            except:
                pass
            time.sleep(delay)

        # Verificar si la API (8728) se abrió
        logging.info("Verificando si la API respondió al Tok Tok...")
        for i in range(3):  # Reiterar verificación hasta 3 veces con breves pausas
            time.sleep(1.0)
            if check_port_open(host, 8728, timeout=2.5):
                return True, f"✅ ¡Port Knocking exitoso! API (8728) abierta tras secuencia {sequence}."
        
        return False, f"❌ Secuencia {sequence} enviada, pero el puerto 8728 sigue cerrado. ¿Está activado el servicio API en el router?"

    except Exception as e:
        logging.error(f"Error crítico en Port Knocking: {e}")
        return False, f"❌ Error de red durante el Port Knocking: {str(e)}"


def check_port_open(host: str, port: int, timeout: float = 1.5) -> bool:
    """Verifica si un puerto TCP está abierto (respondiendo)."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def check_api_reachable(host: str, port: int = 8728, timeout: float = 2.0) -> bool:
    """Verifica si la API del MikroTik es alcanzable. Útil para decidir si activar Port Knocking."""
    return check_port_open(host, port, timeout)


def get_knock_status_text(host: str) -> str:
    """Genera un reporte de estado de conectividad para la UI."""
    api_open = check_port_open(host, 8728, timeout=2.0)
    winbox_open = check_port_open(host, 8291, timeout=1.5)
    ssh_open = check_port_open(host, 22, timeout=1.5)

    lines = []
    lines.append(f"🔌 API (8728):    {'🟢 ABIERTO' if api_open else '🔴 CERRADO/BLOQUEADO'}")
    lines.append(f"🖥️ WinBox (8291): {'🟢 ABIERTO' if winbox_open else '🔴 CERRADO'}")
    lines.append(f"🔑 SSH (22):      {'🟢 ABIERTO' if ssh_open else '🔴 CERRADO'}")

    return "\n".join(lines)


# ================================================================
# GENERADOR DE SCRIPTS MIKROTIK (para configuración del router)
# ================================================================

MIKROTIK_KNOCK_RULES = """
# ===========================================
# PORT KNOCKING — CONFIGURACIÓN MIKROTIK
# ===========================================
# Pegar estas reglas en la terminal del MikroTik (WinBox/SSH).
# IMPORTANTE: Colocar ANTES de las reglas de drop generales en chain=input.

# 1. Fase 1: Primer toque (Puerto 7000 → Registra IP por 15 segundos)
/ip firewall filter add chain=input action=add-src-to-address-list \\
    address-list=Knock_Fase1 address-list-timeout=15s \\
    protocol=tcp dst-port=7000 comment="KNOCK 1"

# 2. Fase 2: Segundo toque (Puerto 8000 → Solo si pasó Fase 1, registra por 15s)
/ip firewall filter add chain=input action=add-src-to-address-list \\
    address-list=Knock_Fase2 address-list-timeout=15s \\
    protocol=tcp dst-port=8000 src-address-list=Knock_Fase1 comment="KNOCK 2"

# 3. Fase 3: Toque final (Puerto 9000 → Solo si pasó Fase 2, da acceso por 5 min)
/ip firewall filter add chain=input action=add-src-to-address-list \\
    address-list=API_Segura address-list-timeout=5m \\
    protocol=tcp dst-port=9000 src-address-list=Knock_Fase2 comment="KNOCK 3 - Acceso Concedido"

# 4. Permitir API solo a IPs autorizadas por el knock
/ip firewall filter add chain=input action=accept \\
    protocol=tcp dst-port=8728 src-address-list=API_Segura \\
    comment="PERMITIR API SEGURA"

# 5. Bloquear API para el resto del mundo
/ip firewall filter add chain=input action=drop \\
    protocol=tcp dst-port=8728 comment="BLOQUEAR API GLOBAL"
"""

POWERSHELL_KNOCK_SCRIPT = '''# Script de Port Knocking para PowerShell (Windows)
# Ejecutar desde cualquier PC para desbloquear la API del MikroTik

param(
    [string]$RouterIP = "{host}",
    [int[]]$Ports = @(7000, 8000, 9000),
    [int]$DelayMs = 600
)

Write-Host "Iniciando Port Knocking hacia $RouterIP..." -ForegroundColor Green

foreach ($port in $Ports) {{
    Write-Host "  Toque #$($Ports.IndexOf($port)+1): Puerto $port..." -ForegroundColor Cyan
    try {{
        $tcp = New-Object Net.Sockets.TcpClient
        $tcp.BeginConnect($RouterIP, $port, $null, $null).AsyncWaitHandle.WaitOne(500) | Out-Null
        $tcp.Close()
    }} catch {{}}
    Start-Sleep -Milliseconds $DelayMs
}}

Write-Host ""
Write-Host "¡Toques enviados! La API (8728) debería estar abierta por 5 minutos." -ForegroundColor Yellow
Write-Host "Ahora puedes abrir WinBox o conectar el NOC Dashboard." -ForegroundColor Green
'''


def generate_mikrotik_script() -> str:
    """Retorna el script RouterOS para configurar Port Knocking en el MikroTik."""
    return MIKROTIK_KNOCK_RULES


def generate_powershell_script(host: str) -> str:
    """Retorna el script PowerShell personalizado con la IP del router."""
    return POWERSHELL_KNOCK_SCRIPT.format(host=host)
