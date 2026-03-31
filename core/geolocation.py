# core/geolocation.py
"""
Módulo de Geolocalización de Infraestructura.
Usa ip-api.com (gratuito, sin API key) para resolver coordenadas desde IPs públicas.
"""
import requests
import ipaddress
import logging


def is_public_ip(ip: str) -> bool:
    """Verifica si una IP es pública (no RFC1918, no loopback, no link-local)."""
    try:
        addr = ipaddress.ip_address(ip)
        return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved)
    except (ValueError, TypeError):
        return False


def geolocate_ip(ip: str) -> dict | None:
    """
    Consulta ipwhois.app para obtener coordenadas y metadatos de una IP pública.
    Retorna dict con lat, lon, city, region, country, isp, timezone — o None si falla.
    """
    if not is_public_ip(ip):
        return None
    try:
        response = requests.get(
            f"http://ipwhois.app/json/{ip}",
            timeout=5
        )
        data = response.json()
        if data.get('success'):
            return {
                'lat': data.get('latitude', 0.0),
                'lon': data.get('longitude', 0.0),
                'city': data.get('city', ''),
                'region': data.get('region', ''),
                'country': data.get('country', ''),
                'isp': data.get('isp', ''),
                'timezone': data.get('timezone', ''),
                'ip': data.get('ip', ip)
            }
    except Exception as e:
        logging.error(f"Error geolocalizando {ip}: {e}")
    return None


def discover_wan_ip(router_api) -> str | None:
    """
    Intenta descubrir la IP pública (WAN) del router MikroTik.
    Estrategia:
      1. /ip/cloud (si está habilitado)
      2. Buscar IPs no privadas en /ip/address
      3. Consultar la IP del cliente (NOC Server) como fallback
    """
    if not router_api:
        return None
    try:
        # Estrategia 1: MikroTik Cloud (detecta NAT también)
        try:
            cloud = router_api.get_resource('/ip/cloud').get()
            if cloud:
                public_ip = cloud[0].get('public-address', '')
                if public_ip and is_public_ip(public_ip):
                    return public_ip
        except Exception:
            pass

        # Estrategia 2: Buscar IPs públicas asignadas directamente
        try:
            addresses = router_api.get_resource('/ip/address').get()
            for addr in addresses:
                ip = addr.get('address', '').split('/')[0]
                if is_public_ip(ip):
                    return ip
        except Exception:
            pass
            
        # Estrategia 3: Hacer que el router pregunte por su IP a ipify
        try:
            router_api.get_resource('/tool').call('fetch', {'url': 'http://api.ipify.org', 'mode': 'http', 'dst-path': 'my_pub_ip.txt'})
            file_data = router_api.get_resource('/file').get()
            for f in file_data:
                if f.get('name') == 'my_pub_ip.txt' and 'contents' in f:
                    content = f.get('contents', '').strip()
                    if is_public_ip(content):
                        return content
        except Exception:
            pass

    except Exception as e:
        logging.error(f"Error descubriendo WAN IP: {e}")
    return None


def auto_geolocate_router(router_api, fallback_ip: str = None) -> dict | None:
    """
    Pipeline completo: descubrir WAN IP → geolocalizar.
    Si la IP de conexión es pública, la usa como fallback.
    Si nada de lo del router funciona, usa la IP pública del servidor NOC.
    """
    wan_ip = discover_wan_ip(router_api)

    if not wan_ip and fallback_ip and is_public_ip(fallback_ip):
        wan_ip = fallback_ip

    # Si aún no tenemos WAN IP, usar la IP pública del propio servidor que ejecuta el script
    if not wan_ip:
        try:
             # Al no pasar IP en la URL, se usa la del servidor solicitante
             resp = requests.get("http://ipwhois.app/json/", timeout=5).json()
             if resp.get('success'):
                 wan_ip = resp.get('ip')
        except Exception:
             pass

    if wan_ip:
        geo = geolocate_ip(wan_ip)
        if geo:
            geo['wan_ip'] = wan_ip
            return geo
    return None

def geolocate_by_bssid(wifi_scan_results: list, api_key: str) -> dict | None:
    """
    Envía las direcciones MAC (BSSIDs) y fuerza de señal a la API de Geolocalización de Google.
    Retorna una latitud/longitud con una precisión extrema (< 20 metros).
    Requiere una GOOGLE_MAPS_API_KEY.
    wifi_scan_results: Lista de dicts con {'bssid': 'mac', 'signal': -55}
    """
    if not api_key or not wifi_scan_results:
        return None

    # Formatear datos para Google API
    wifi_access_points = []
    for ap in wifi_scan_results:
        bssid = ap.get('bssid')
        signal_str = str(ap.get('signal', ''))
        
        # Parsear señal (ej. -55dBm)
        try:
            signal_val = int(''.join([c for c in signal_str if c.isdigit() or c == '-']))
        except Exception:
            signal_val = -80

        if bssid and len(bssid) == 17:  # MAC address válida
            wifi_access_points.append({
                "macAddress": bssid,
                "signalStrength": signal_val
            })

    if not wifi_access_points:
        return None

    url = f"https://www.googleapis.com/geolocation/v1/geolocate?key={api_key}"
    payload = {
        "considerIp": "false",  # Obligamos a usar SOLO BSSID para máxima precisión
        "wifiAccessPoints": wifi_access_points
    }

    try:
        response = requests.post(url, json=payload, timeout=8)
        data = response.json()
        
        if 'location' in data:
            return {
                'lat': data['location']['lat'],
                'lon': data['location']['lng'],
                'accuracy': data.get('accuracy', 0.0),
                'city': 'Ubicación Precisa por Wi-Fi',
                'country': 'API de Google Maps'
            }
        else:
            logging.error(f"Error Google Geolocation: {data}")
            return None
    except Exception as e:
        logging.error(f"Excepción en geolocalización BSSID: {e}")
        return None

def geolocate_by_mylnikov(wifi_scan_results: list) -> dict | None:
    """
    Alternativa 100% GRATUITA para geolocalización por BSSID (Sin API Key).
    Usa la API abierta de Mylnikov GEO (agrupa bases de datos open source de MACs).
    Itera sobre las MACs con mejor señal hasta que una devuelva latitud/longitud válidas.
    """
    if not wifi_scan_results:
        return None

    # Ordenar BSSIDs por fuerza de señal (los que están más cerca del router)
    sorted_aps = sorted(wifi_scan_results, key=lambda x: str(x.get('signal', '-99')), reverse=True)
    
    for ap in sorted_aps:
        bssid = ap.get('bssid', '').strip()
        if not bssid or len(bssid) != 17:
             continue
             
        # La API requiere el BSSID en formato MAC clásico con dos puntos: AA:BB:CC:11:22:33
        url = f"https://api.mylnikov.org/geolocation/wifi?v=1.1&bssid={bssid.upper()}"
        
        try:
             response = requests.get(url, timeout=3)
             data = response.json()
             
             # Result 200 indica éxito encontrando la antena en la DB
             if data.get("result") == 200 and "data" in data:
                 return {
                     'lat': data["data"].get("lat"),
                     'lon': data["data"].get("lon"),
                     'accuracy': 50.0, # Mylnikov asume ~50m de radio típico
                     'city': 'Triangulado (Open DB)',
                     'country': 'Mylnikov API (Gratis)',
                     'bssid_used': bssid
                 }
        except Exception as e:
             logging.debug(f"Mylnikov BSSID {bssid} falló: {e}")
             
    # Si ninguna de las BSSIDs en el escaneo está en la base de datos pública
    return None
