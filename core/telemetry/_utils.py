# core/telemetry/_utils.py
"""
Utilidades compartidas para el subsistema de Telemetría MikroTik.
Contiene constantes, decoradores y helpers usados por todos los módulos de telemetría.
Eliminan redundancia y centralizan lógica transversal.
"""
import logging
import functools
import re
from datetime import timedelta
from typing import Any, Dict, List, Tuple

logger = logging.getLogger("telemetry")

# ============================================================
# CONSTANTES GLOBALES — Definidas UNA sola vez
# ============================================================

SOCIAL_DOMAIN_MAP: Dict[str, List[str]] = {
    "youtube":   ["youtube.com", "googlevideo.com", "ytimg.com", "i.ytimg.com", "yt.be", "ggpht.com"],
    "facebook":  ["facebook.com", "fbcdn.net", "fbsbx.com", "messenger.com", "facebook.net"],
    "tiktok":    ["tiktok.com", "tiktokv.com", "byteoversea.com", "ibyteimg.com", "snssdk.com"],
    "instagram": ["instagram.com", "cdninstagram.com", "ig.me"],
    "netflix":   ["netflix.com", "nflxext.com", "nflxvideo.net", "nflxso.net"],
    "whatsapp":  ["whatsapp.com", "whatsapp.net", "wa.me", "web.whatsapp.com",
                  "d.whatsapp.net", "g.whatsapp.net", "mmg.whatsapp.net",
                  "pps.whatsapp.net", "static.whatsapp.net"],
    "spotify":   ["spotify.com", "scdn.co", "spotifycdn.com"],
    "twitch":    ["twitch.tv", "ttvnw.net", "jtvnw.net"],
    "twitter":   ["twitter.com", "x.com", "twimg.com", "t.co"],
    "telegram":  ["telegram.org", "t.me", "telegram.me"],
    "discord":   ["discord.com", "discord.gg", "discordapp.com", "discordapp.net"],
    "zoom":      ["zoom.us", "zoom.com", "zoomgov.com"],
    "teams":     ["teams.microsoft.com", "teams.cdn.office.net"],
}

SERVICE_ICON_MAP: Dict[str, Tuple[str, str]] = {
    # pattern_in_domain: (service_name, icon)
    "googlevideo": ("YouTube", "🎬"), "youtube": ("YouTube", "🎬"), "ytimg": ("YouTube", "🎬"),
    "facebook": ("Facebook", "📘"), "fbcdn": ("Facebook", "📘"),
    "instagram": ("Instagram", "📸"), "cdninstagram": ("Instagram", "📸"),
    "tiktok": ("TikTok", "🎵"), "byteoversea": ("TikTok", "🎵"), "musical.ly": ("TikTok", "🎵"),
    "netflix": ("Netflix", "🎥"), "nflx": ("Netflix", "🎥"),
    "whatsapp": ("WhatsApp", "💬"),
    "spotify": ("Spotify", "🎧"), "scdn": ("Spotify", "🎧"),
    "twitch": ("Twitch", "🟣"), "ttvnw": ("Twitch", "🟣"),
    "twitter": ("Twitter/X", "🐦"), "twimg": ("Twitter/X", "🐦"),
    "telegram": ("Telegram", "✈️"),
    "discord": ("Discord", "🎮"), "discordapp": ("Discord", "🎮"),
    "zoom": ("Zoom", "📹"),
    "teams": ("MS Teams", "👥"),
    "google": ("Google", "🔍"), "gstatic": ("Google", "🔍"), "googleapis": ("Google", "🔍"),
    "microsoft": ("Microsoft", "🪟"), "msn": ("Microsoft", "🪟"), "office": ("Microsoft", "🪟"),
    "amazon": ("Amazon", "📦"), "aws": ("Amazon", "📦"),
    "apple": ("Apple", "🍎"), "icloud": ("Apple", "🍎"),
    "cloudflare": ("Cloudflare", "☁️"),
    "akamai": ("Akamai CDN", "🌐"),
}

PORT_SERVICE_MAP: Dict[str, str] = {
    "443": "HTTPS", "80": "HTTP", "53": "DNS", "22": "SSH",
    "8080": "HTTP-Alt", "8443": "HTTPS-Alt", "25": "SMTP",
    "587": "SMTP-TLS", "993": "IMAPS", "995": "POP3S",
    "3389": "RDP", "5060": "SIP", "5061": "SIPS",
    "1194": "OpenVPN", "1723": "PPTP", "500": "IKE",
    "4500": "IPSec-NAT", "8728": "MikroTik-API", "8729": "MikroTik-API-SSL",
    "8291": "Winbox",
}


# ============================================================
# DECORADORES
# ============================================================

def require_api(default_return: Any = None):
    """
    Decorador que valida la conexión API antes de ejecutar el método.
    Si `self.api` es None, retorna `default_return` inmediatamente.

    Uso:
        @require_api(default_return=[])
        def get_interfaces(self): ...

        @require_api(default_return=(False, "API desconectada."))
        def block_ip(self, ip): ...
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(self, *args, **kwargs):
            if not self.api:
                logger.debug(f"{func.__name__}: API no disponible.")
                return default_return
            return func(self, *args, **kwargs)
        return wrapper
    return decorator


# ============================================================
# HELPERS DE PARSEO Y FORMATO
# ============================================================

def parse_mikrotik_uptime(uptime_str: str) -> timedelta:
    """
    Parsea un string de uptime MikroTik (e.g., '2w3d5h12m30s') a timedelta.
    Soporta: semanas(w), días(d), horas(h), minutos(m), segundos(s).
    """
    weeks = re.search(r'(\d+)w', uptime_str)
    days = re.search(r'(\d+)d', uptime_str)
    hours = re.search(r'(\d+)h', uptime_str)
    minutes = re.search(r'(\d+)m', uptime_str)
    seconds = re.search(r'(\d+)s', uptime_str)
    return timedelta(
        weeks=int(weeks.group(1)) if weeks else 0,
        days=int(days.group(1)) if days else 0,
        hours=int(hours.group(1)) if hours else 0,
        minutes=int(minutes.group(1)) if minutes else 0,
        seconds=int(seconds.group(1)) if seconds else 0,
    )


def format_bytes(byte_count: int) -> str:
    """Convierte bytes a formato legible (B, KB, MB, GB)."""
    if byte_count >= 1_073_741_824:
        return f"{byte_count / 1_073_741_824:.2f} GB"
    elif byte_count >= 1_048_576:
        return f"{byte_count / 1_048_576:.2f} MB"
    elif byte_count >= 1024:
        return f"{byte_count / 1024:.1f} KB"
    return f"{byte_count} B"


def safe_int(value: Any, default: int = 0) -> int:
    """Convierte un valor a entero de forma segura, sin excepciones."""
    try:
        return int(value)
    except (ValueError, TypeError):
        return default


def clean_ip(ip_string: str) -> str:
    """
    Extrae una IP limpia de formatos comunes:
    '192.168.1.1:8080' → '192.168.1.1'
    '192.168.1.1 (hostname)' → '192.168.1.1'
    """
    if not ip_string:
        return ""
    ip = ip_string.split(':')[0]
    ip = ip.split(' (')[0]
    return ip.strip()


def resolve_service(domain: str) -> Tuple[str, str]:
    """
    Mapea un dominio a su servicio conocido e icono.
    Returns: (display_name, icon) — e.g., ("YouTube (googlevideo.com)", "🎬")
    """
    domain_lower = domain.lower()
    for pattern, (service_name, icon) in SERVICE_ICON_MAP.items():
        if pattern in domain_lower:
            return f"{service_name} ({domain})", icon
    return domain, "🌐"


def resolve_port_service(port: str, protocol: str = "tcp") -> str:
    """Resuelve un número de puerto a un nombre de servicio conocido."""
    if port in PORT_SERVICE_MAP:
        return PORT_SERVICE_MAP[port]
    return f"Port {port}" if port else protocol.upper()


def expand_social_domains(domain: str) -> List[str]:
    """
    Expande un dominio a todos sus dominios satélite conocidos.
    'youtube.com' → ['youtube.com', 'googlevideo.com', 'ytimg.com', ...]
    """
    domain_lower = domain.strip().lower()
    result = [domain_lower]
    for key, satellites in SOCIAL_DOMAIN_MAP.items():
        if key in domain_lower:
            result = list(set(result + satellites))
            break
    return result


def resolve_dns_cache(api) -> Dict[str, str]:
    """
    Descarga la caché DNS del MikroTik y retorna un mapa IP→Dominio.
    Método compartido para evitar múltiples descargas de la misma tabla.
    """
    try:
        dns_cache = api.get_resource('/ip/dns/cache').get()
        return {
            entry['address']: entry['name']
            for entry in dns_cache
            if 'address' in entry and 'name' in entry
        }
    except Exception as e:
        logger.debug(f"DNS cache no disponible: {e}")
        return {}
