# core/ip_tools.py
"""
Motor de Inteligencia IP — Powered by Netaddr 1.x.
Herramientas de análisis CIDR, clasificación y cálculo de subredes.
Compatible con netaddr >= 1.0 (API is_global/is_ipv4_private_use).
"""
from netaddr import IPAddress, IPNetwork, IPSet, cidr_merge
import logging


def _is_private(addr) -> bool:
    """Wrapper compatible con netaddr 1.x — verifica si una IP es privada."""
    try:
        if hasattr(addr, 'is_ipv4_private_use'):
            return addr.is_ipv4_private_use() or addr.is_loopback() or addr.is_link_local()
        return not addr.is_global()
    except Exception:
        return True


def get_subnet_info(cidr: str) -> dict:
    """Análisis completo de una subred CIDR."""
    try:
        net = IPNetwork(cidr)
        first_ip = net.network
        is_priv = _is_private(IPAddress(int(first_ip) + 1)) if net.size > 2 else _is_private(first_ip)

        return {
            'network': str(net.network),
            'broadcast': str(net.broadcast),
            'netmask': str(net.netmask),
            'wildcard': str(net.hostmask),
            'prefix': net.prefixlen,
            'total_hosts': net.size,
            'usable_hosts': max(0, net.size - 2),
            'first_host': str(net.network + 1) if net.size > 2 else str(net.network),
            'last_host': str(net.broadcast - 1) if net.size > 2 else str(net.broadcast),
            'is_private': is_priv,
            'version': net.version,
            'cidr': str(net.cidr),
        }
    except Exception as e:
        logging.error(f"Error analizando CIDR {cidr}: {e}")
        return {}


def classify_ip(ip: str) -> dict:
    """Clasifica una IP con metadatos detallados."""
    try:
        addr = IPAddress(ip)
        is_priv = _is_private(addr)

        if is_priv:
            classification = "Privada (RFC1918)"
        elif addr.is_loopback():
            classification = "Loopback"
        elif addr.is_link_local():
            classification = "Link-Local"
        elif addr.is_multicast():
            classification = "Multicast"
        elif addr.is_reserved():
            classification = "Reservada"
        else:
            classification = "Pública"

        first_octet = int(str(addr).split('.')[0])
        if first_octet <= 127:
            net_class = "Clase A"
        elif first_octet <= 191:
            net_class = "Clase B"
        elif first_octet <= 223:
            net_class = "Clase C"
        elif first_octet <= 239:
            net_class = "Clase D (Multicast)"
        else:
            net_class = "Clase E (Experimental)"

        return {
            'ip': str(addr),
            'version': addr.version,
            'classification': classification,
            'net_class': net_class,
            'is_private': is_priv,
            'is_loopback': addr.is_loopback(),
            'is_multicast': addr.is_multicast(),
            'is_unicast': addr.is_unicast(),
            'hex': hex(int(addr)),
            'binary': addr.bits(),
        }
    except Exception as e:
        return {'ip': ip, 'error': str(e)}


def find_ip_in_subnets(ip: str, subnets: list) -> str | None:
    """Encuentra a qué subred pertenece una IP."""
    try:
        addr = IPAddress(ip)
        for cidr in subnets:
            if addr in IPNetwork(cidr):
                return cidr
    except Exception:
        pass
    return None


def check_subnet_overlap(cidrs: list) -> list:
    """Detecta solapamientos entre subredes — crítico para auditoría de red."""
    overlaps = []
    networks = []
    for cidr in cidrs:
        try:
            networks.append(IPNetwork(cidr))
        except Exception:
            continue

    for i in range(len(networks)):
        for j in range(i + 1, len(networks)):
            set1 = IPSet([networks[i]])
            set2 = IPSet([networks[j]])
            intersection = set1 & set2
            if intersection:
                overlaps.append({
                    'red_a': str(networks[i]),
                    'red_b': str(networks[j]),
                    'overlap': str(intersection),
                    'hosts_afectados': intersection.size,
                })
    return overlaps


def aggregate_cidrs(cidrs: list) -> list:
    """Agrega/resume una lista de CIDRs en la mínima representación."""
    try:
        networks = [IPNetwork(c) for c in cidrs]
        merged = cidr_merge(networks)
        return [str(n) for n in merged]
    except Exception:
        return cidrs


def enumerate_hosts(cidr: str, limit: int = 256) -> list:
    """Lista las IPs de host en una subred (limitado para evitar redes enormes)."""
    try:
        net = IPNetwork(cidr)
        hosts = list(net.iter_hosts())
        return [str(h) for h in hosts[:limit]]
    except Exception:
        return []


def is_same_network(ip1: str, ip2: str, cidr: str) -> bool:
    """Verifica si dos IPs están en la misma red."""
    try:
        net = IPNetwork(cidr)
        return IPAddress(ip1) in net and IPAddress(ip2) in net
    except Exception:
        return False
