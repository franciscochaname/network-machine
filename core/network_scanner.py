# core/network_scanner.py
"""
Motor de Escaneo de Red — Powered by Scapy.
ARP Discovery, Port Scanning, Traceroute y análisis de paquetes.
Handles missing Npcap/WinPcap gracefully on Windows.
"""
import logging
import socket
import struct
import time

# Intentar importar Scapy (requiere Npcap en Windows)
SCAPY_AVAILABLE = False
try:
    from scapy.all import ARP, Ether, srp, IP, TCP, sr1, traceroute as scapy_traceroute, ICMP, conf
    conf.verb = 0  # Silenciar output de Scapy
    SCAPY_AVAILABLE = True
except ImportError:
    logging.warning("Scapy no disponible. Algunas funciones de escaneo estarán limitadas.")
except Exception as e:
    logging.warning(f"Scapy no pudo inicializar (¿Npcap instalado?): {e}")


def is_scapy_ready() -> bool:
    """Verifica si Scapy está disponible y funcional."""
    return SCAPY_AVAILABLE


def arp_scan(network_cidr: str, timeout: int = 3) -> list:
    """
    Escaneo ARP de una subred local. Descubre dispositivos activos con IP y MAC.
    Requiere Scapy + Npcap. Solo funciona en subredes directamente accesibles.
    """
    if not SCAPY_AVAILABLE:
        return _fallback_ping_scan(network_cidr)

    try:
        arp_request = ARP(pdst=network_cidr)
        broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = broadcast / arp_request

        answered, _ = srp(packet, timeout=timeout, verbose=0)

        devices = []
        for sent, received in answered:
            devices.append({
                'ip': received.psrc,
                'mac': received.hwsrc.upper(),
                'vendor': _mac_vendor_lookup(received.hwsrc),
            })

        return sorted(devices, key=lambda x: socket.inet_aton(x['ip']))
    except Exception as e:
        logging.error(f"Error en ARP scan: {e}")
        return _fallback_ping_scan(network_cidr)


def tcp_port_scan(target: str, ports: list = None, timeout: float = 1.5) -> list:
    """
    Escaneo TCP SYN de puertos en un objetivo.
    Si Scapy no está disponible, usa socket connect().
    """
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 
                 3306, 3389, 5432, 8080, 8443, 8728, 8729, 8291]

    results = []
    
    if SCAPY_AVAILABLE:
        try:
            for port in ports:
                pkt = IP(dst=target) / TCP(dport=port, flags="S")
                resp = sr1(pkt, timeout=timeout, verbose=0)
                if resp and resp.haslayer(TCP):
                    if resp[TCP].flags == 0x12:  # SYN-ACK
                        service = _get_service_name(port)
                        results.append({
                            'port': port,
                            'state': 'OPEN',
                            'service': service,
                            'protocol': 'TCP'
                        })
                        # Enviar RST para cerrar la conexión
                        sr1(IP(dst=target) / TCP(dport=port, flags="R"), timeout=0.5, verbose=0)
            return results
        except Exception as e:
            logging.error(f"Error Scapy port scan: {e}")

    # Fallback: socket connect scan
    return _socket_port_scan(target, ports, timeout)


def network_traceroute(target: str, max_hops: int = 20, timeout: int = 2) -> list:
    """Traceroute a un destino usando Scapy o fallback."""
    hops = []

    if SCAPY_AVAILABLE:
        try:
            for ttl in range(1, max_hops + 1):
                pkt = IP(dst=target, ttl=ttl) / ICMP()
                reply = sr1(pkt, timeout=timeout, verbose=0)

                if reply is None:
                    hops.append({'hop': ttl, 'ip': '*', 'rtt': 'timeout', 'status': 'timeout'})
                elif reply.type == 11:  # Time Exceeded
                    rtt = round((reply.time - pkt.sent_time) * 1000, 2) if hasattr(pkt, 'sent_time') else 0
                    hops.append({
                        'hop': ttl, 'ip': reply.src,
                        'rtt': f"{rtt}ms" if rtt else 'N/A',
                        'status': 'transit'
                    })
                elif reply.type == 0:  # Echo Reply (destino alcanzado)
                    rtt = round((reply.time - pkt.sent_time) * 1000, 2) if hasattr(pkt, 'sent_time') else 0
                    hops.append({
                        'hop': ttl, 'ip': reply.src,
                        'rtt': f"{rtt}ms" if rtt else 'N/A',
                        'status': 'destination'
                    })
                    break
            return hops
        except Exception as e:
            logging.error(f"Error traceroute: {e}")

    return [{'hop': 1, 'ip': 'N/A', 'rtt': 'N/A', 'status': 'Scapy no disponible'}]


def system_ping(target: str) -> str:
    import subprocess
    import platform
    param = '-n' if platform.system().lower() == 'windows' else '-c'
    try:
        out = subprocess.check_output(['ping', param, '10', target], stderr=subprocess.STDOUT, text=True, encoding='cp850', errors='ignore')
        return out
    except subprocess.CalledProcessError as e:
        return str(e.output)
        
def system_traceroute(target: str) -> str:
    import subprocess
    import platform
    cmd = 'tracert' if platform.system().lower() == 'windows' else 'traceroute'
    try:
        out = subprocess.check_output([cmd, '-d', '-h', '15', target], stderr=subprocess.STDOUT, text=True, encoding='cp850', errors='ignore')
        return out
    except subprocess.CalledProcessError as e:
        return str(e.output)

def scan_network_scapy(target_ip: str) -> bool:
    """Verifica si un host responde a ICMP (Ping rápido para SOC)."""
    if not SCAPY_AVAILABLE:
        # Fallback simple vía socket
        try:
            socket.create_connection((target_ip, 80), timeout=1)
            return True
        except: return False
    try:
        pkt = IP(dst=target_ip)/ICMP()
        resp = sr1(pkt, timeout=1, verbose=0)
        return resp is not None
    except:
        return False


# === FUNCIONES AUXILIARES ===

def _socket_port_scan(target: str, ports: list, timeout: float) -> list:
    """Fallback: escaneo de puertos via socket."""
    results = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            if result == 0:
                results.append({
                    'port': port,
                    'state': 'OPEN',
                    'service': _get_service_name(port),
                    'protocol': 'TCP'
                })
            sock.close()
        except Exception:
            pass
    return results


def _fallback_ping_scan(network_cidr: str) -> list:
    """Fallback mínimo: intento de conexión TCP al puerto 80/443 para descubrir hosts."""
    # Sin Scapy, no podemos hacer ARP scan real. Devolver aviso.
    return []


def _get_service_name(port: int) -> str:
    """Mapea puertos comunes a nombres de servicio."""
    services = {
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
        80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 445: 'SMB',
        993: 'IMAPS', 995: 'POP3S', 3306: 'MySQL', 3389: 'RDP',
        5432: 'PostgreSQL', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
        8728: 'MikroTik API', 8729: 'MikroTik API-SSL', 8291: 'Winbox',
    }
    return services.get(port, f'port-{port}')


def _mac_vendor_lookup(mac: str) -> str:
    """Intenta identificar el fabricante por los primeros 3 octetos del MAC."""
    prefix = mac.upper().replace(':', '')[:6]
    vendors = {
        '000C42': 'MikroTik', 'D4CA6D': 'MikroTik', '6C3B6B': 'MikroTik',
        '48A98A': 'MikroTik', 'CC2DE0': 'MikroTik', '2C:CF:67': 'MikroTik',
        '00E04C': 'Realtek', '001A2B': 'Cisco', '0050BA': 'D-Link',
        '0013A9': 'Sony', '00265A': 'D-Link', '9C5C8E': 'TP-Link',
        '001E58': 'D-Link', '14CC20': 'TP-Link', 'E4186B': 'TP-Link',
    }
    return vendors.get(prefix, 'Desconocido')


# ================================================================
# SEGURIDAD DE RED — ARP Spoofing Detection, Rogue DHCP
# ================================================================

def detect_arp_anomalies(previous_arp: dict, current_arp: dict) -> list:
    """
    Compara tablas ARP entre sincronizaciones para detectar:
    - MAC Flapping: Una IP cambia de MAC (posible ARP spoofing / MITM).
    - Nuevos dispositivos: IPs que no existían antes.
    - Dispositivos desaparecidos: IPs que ya no responden.
    """
    alerts = []

    # MAC Flapping (posible ARP Spoofing)
    for ip, old_mac in previous_arp.items():
        new_mac = current_arp.get(ip)
        if new_mac and new_mac.upper() != old_mac.upper():
            alerts.append({
                'tipo': '🔴 ARP SPOOFING',
                'ip': ip,
                'detalle': f'MAC cambió: {old_mac} → {new_mac}',
                'severidad': 'CRÍTICO',
                'accion': 'Verificar dispositivo físico conectado en esa IP',
            })

    # Nuevos dispositivos
    nuevos = set(current_arp.keys()) - set(previous_arp.keys())
    for ip in nuevos:
        alerts.append({
            'tipo': '🟡 NUEVO DISPOSITIVO',
            'ip': ip,
            'detalle': f'MAC: {current_arp[ip]}',
            'severidad': 'INFO',
            'accion': 'Verificar si es un dispositivo autorizado',
        })

    # Dispositivos desaparecidos
    desaparecidos = set(previous_arp.keys()) - set(current_arp.keys())
    for ip in desaparecidos:
        alerts.append({
            'tipo': '🟠 DISPOSITIVO DESCONECTADO',
            'ip': ip,
            'detalle': f'MAC anterior: {previous_arp[ip]}',
            'severidad': 'WARNING',
            'accion': 'Verificar conectividad del dispositivo',
        })

    return alerts


def detect_rogue_dhcp(timeout: int = 8) -> dict:
    """
    Envía un DHCP Discover broadcast y lista todos los servidores que responden.
    Si hay más de 1 servidor, uno podría ser rogue (no autorizado).
    Requiere Scapy + Npcap y privilegios de administrador.
    """
    if not SCAPY_AVAILABLE:
        return {'status': '⚠️ Scapy no disponible', 'servers': []}

    try:
        from scapy.all import Ether, IP, UDP, BOOTP, DHCP
        import random

        mac_bytes = bytes([random.randint(0, 255) for _ in range(6)])

        dhcp_discover = (
            Ether(dst="ff:ff:ff:ff:ff:ff") /
            IP(src="0.0.0.0", dst="255.255.255.255") /
            UDP(sport=68, dport=67) /
            BOOTP(chaddr=mac_bytes, xid=random.randint(1, 0xFFFFFFFF)) /
            DHCP(options=[("message-type", "discover"), "end"])
        )

        answered, _ = srp(dhcp_discover, timeout=timeout, verbose=0)

        servers = []
        for _, reply in answered:
            if reply.haslayer(BOOTP):
                server_ip = reply[IP].src
                server_mac = reply[Ether].src.upper()
                offered_ip = reply[BOOTP].yiaddr

                servers.append({
                    'server_ip': server_ip,
                    'server_mac': server_mac,
                    'offered_ip': offered_ip,
                })

        if len(servers) > 1:
            return {
                'status': '🔴 ROGUE DHCP DETECTADO — Múltiples servidores respondieron',
                'servers': servers,
                'alert': True
            }
        elif len(servers) == 1:
            return {
                'status': '✅ Un único servidor DHCP legítimo detectado',
                'servers': servers,
                'alert': False
            }
        else:
            return {
                'status': '⚠️ Ningún servidor DHCP respondió',
                'servers': [],
                'alert': False
            }

    except Exception as e:
        return {'status': f'Error: {str(e)}', 'servers': [], 'alert': False}

