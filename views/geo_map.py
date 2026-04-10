# views/geo_map.py
"""
Módulo de Mapa Geográfico Interactivo para el NOC Dashboard.
Muestra en un mapa mundial Plotly:
  - Ubicación del router (IP WAN)
  - Peers VPN activos geolocalizados
  - Top Talkers WAN (IPs externas con mayor tráfico)
  - Líneas de conexión animadas desde el router hacia cada peer
Usa ip-api.com (gratuito, sin API key, hasta 45 req/min).
"""
import streamlit as st
import plotly.graph_objects as go
import requests
import ipaddress
import logging
from datetime import datetime

# ─────────────────────────────────────────────────────────────
# CACHE: evitar re-consultar IPs ya geolocalizadas en sesión
# ─────────────────────────────────────────────────────────────

def _geo_cache() -> dict:
    if 'geo_cache' not in st.session_state:
        st.session_state['geo_cache'] = {}
    return st.session_state['geo_cache']


def _is_public(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
        return not (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved)
    except Exception:
        return False


def _geolocate(ip: str) -> dict | None:
    """Retorna dict {lat, lon, city, country, isp, org} o None."""
    if not ip or not _is_public(ip):
        return None
    cache = _geo_cache()
    if ip in cache:
        return cache[ip]
    try:
        r = requests.get(
            f"http://ip-api.com/json/{ip}?fields=status,lat,lon,city,regionName,country,isp,org,as",
            timeout=4
        )
        d = r.json()
        if d.get('status') == 'success':
            result = {
                'lat': d['lat'], 'lon': d['lon'],
                'city': d.get('city', ''),
                'region': d.get('regionName', ''),
                'country': d.get('country', ''),
                'isp': d.get('isp', ''),
                'org': d.get('org', ''),
                'as_info': d.get('as', ''),
            }
            cache[ip] = result
            return result
    except Exception as e:
        logging.debug(f"Geoloc {ip}: {e}")
    return None


# ─────────────────────────────────────────────────────────────
# RENDER PRINCIPAL
# ─────────────────────────────────────────────────────────────

def render_geo_map(router_db, datos: dict):
    """
    Renderiza el mapa geográfico interactivo completo.
    router_db: objeto Router SQLAlchemy (tiene .lat, .lon, .wan_ip)
    datos: dict de telemetría que incluye 'vpns' y 'top_talkers'
    """
    st.markdown(
        "<h4 style='color:#ddd; margin-bottom:4px;'>"
        "<i class='fa-solid fa-earth-americas'></i>"
        " Mapa Geográfico de Conectividad Global</h4>",
        unsafe_allow_html=True
    )
    st.caption(
        "Geolocalización en tiempo real de peers VPN, Top Talkers WAN y la ubicación del router. "
        "Actualiza automáticamente con cada sincronización."
    )

    # ── 1. Ubicación del router (nodo central) ──────────────
    router_lat = getattr(router_db, 'lat', None)
    router_lon = getattr(router_db, 'lon', None)
    router_wan = getattr(router_db, 'wan_ip', None) or datos.get('wan_ip')
    router_name = getattr(router_db, 'name', 'Router NOC')

    # Si no tiene coordenadas guardadas, intentar geolocalizarlas
    if not router_lat or not router_lon:
        if router_wan:
            geo_r = _geolocate(router_wan)
            if geo_r:
                router_lat, router_lon = geo_r['lat'], geo_r['lon']
        if not router_lat:
            router_lat, router_lon = 0.0, 0.0  # fallback centro

    # ── 2. Peers VPN ────────────────────────────────────────
    vpn_items = datos.get('vpns', [])
    vpn_points = []
    for vpn in vpn_items:
        remote_ip = vpn.get('remote-address') or vpn.get('address') or ''
        if not remote_ip or not _is_public(remote_ip):
            continue
        geo = _geolocate(remote_ip)
        if geo:
            vpn_points.append({
                'ip': remote_ip,
                'protocol': vpn.get('type', vpn.get('name', 'VPN')),
                'uptime': vpn.get('uptime', ''),
                **geo
            })

    # ── 3. Top Talkers WAN (IPs externas) ───────────────────
    talkers = datos.get('top_talkers', [])
    wan_points = []
    for t in talkers:
        ip = t.get('ip', '')
        if not _is_public(ip):
            continue
        geo = _geolocate(ip)
        if geo:
            mb = t.get('bytes', 0) / (1024 * 1024)
            wan_points.append({
                'ip': ip,
                'mb': mb,
                'mb_str': f"{mb:.1f} MB",
                'domains': ', '.join(
                    d.get('domain', '') for d in t.get('domains', [])[:3]
                ),
                **geo
            })

    # ── 4. Build Plotly Scattergeo ───────────────────────────
    fig = go.Figure()

    # Fondo del mapa estilo oscuro NOC
    fig.update_layout(
        geo=dict(
            showland=True, landcolor='#12151c',
            showocean=True, oceancolor='#0a0d14',
            showframe=False, showcoastlines=True,
            coastlinecolor='rgba(0,240,255,0.1)',
            showcountries=True, countrycolor='rgba(255,255,255,0.06)',
            bgcolor='rgba(0,0,0,0)',
            projection_type='natural earth',
        ),
        paper_bgcolor='rgba(0,0,0,0)',
        plot_bgcolor='rgba(0,0,0,0)',
        margin=dict(l=0, r=0, t=0, b=0),
        height=500,
        legend=dict(
            orientation="h", yanchor="bottom", y=-0.05,
            font=dict(color='#888', size=11),
            bgcolor='rgba(0,0,0,0)'
        ),
        hovermode='closest',
        font=dict(family='Inter, sans-serif')
    )

    # ── Líneas de conexión (arcos del router a cada punto) ───
    lats_lines, lons_lines = [], []

    for p in vpn_points + wan_points:
        lats_lines += [router_lat, p['lat'], None]
        lons_lines += [router_lon, p['lon'], None]

    if lats_lines:
        fig.add_trace(go.Scattergeo(
            lat=lats_lines, lon=lons_lines,
            mode='lines',
            line=dict(width=1, color='rgba(0,240,255,0.2)'),
            showlegend=False,
            hoverinfo='skip',
            name='Conexiones'
        ))

    # ── Nodo Router (central) ────────────────────────────────
    fig.add_trace(go.Scattergeo(
        lat=[router_lat], lon=[router_lon],
        mode='markers+text',
        marker=dict(
            size=18, color='#00FFAA',
            symbol='star',
            line=dict(width=2, color='rgba(0,255,170,0.4)'),
        ),
        text=[router_name],
        textposition='top center',
        textfont=dict(color='#00FFAA', size=11, family='JetBrains Mono'),
        name='Router NOC',
        hovertemplate=(
            f"<b>🌐 {router_name}</b><br>"
            f"WAN: {router_wan or 'N/A'}<br>"
            f"Lat: {router_lat:.4f} | Lon: {router_lon:.4f}<br>"
            "<extra></extra>"
        )
    ))

    # ── Peers VPN ────────────────────────────────────────────
    if vpn_points:
        fig.add_trace(go.Scattergeo(
            lat=[p['lat'] for p in vpn_points],
            lon=[p['lon'] for p in vpn_points],
            mode='markers',
            marker=dict(
                size=12,
                color='#B100FF',
                symbol='diamond',
                line=dict(width=2, color='rgba(177,0,255,0.5)'),
                opacity=0.9
            ),
            name=f'VPN Peers ({len(vpn_points)})',
            customdata=[
                [p['ip'], p.get('protocol',''), p.get('uptime',''), p.get('city',''), p.get('country',''), p.get('isp','')]
                for p in vpn_points
            ],
            hovertemplate=(
                "<b>🔐 Peer VPN</b><br>"
                "IP: %{customdata[0]}<br>"
                "Protocolo: %{customdata[1]}<br>"
                "Uptime: %{customdata[2]}<br>"
                "📍 %{customdata[3]}, %{customdata[4]}<br>"
                "ISP: %{customdata[5]}<br>"
                "<extra></extra>"
            )
        ))

    # ── Top Talkers WAN ──────────────────────────────────────
    if wan_points:
        sizes = [max(8, min(20, p['mb'] / 2)) for p in wan_points]
        fig.add_trace(go.Scattergeo(
            lat=[p['lat'] for p in wan_points],
            lon=[p['lon'] for p in wan_points],
            mode='markers',
            marker=dict(
                size=sizes,
                color='#FF4B4B',
                symbol='circle',
                line=dict(width=1, color='rgba(255,75,75,0.4)'),
                opacity=0.85,
                colorscale='Reds',
                showscale=False,
            ),
            name=f'WAN Talkers ({len(wan_points)})',
            customdata=[
                [p['ip'], p['mb_str'], p.get('domains',''), p.get('city',''), p.get('country',''), p.get('isp','')]
                for p in wan_points
            ],
            hovertemplate=(
                "<b>📡 Top Talker WAN</b><br>"
                "IP: %{customdata[0]}<br>"
                "Tráfico: %{customdata[1]}<br>"
                "Servicios: %{customdata[2]}<br>"
                "📍 %{customdata[3]}, %{customdata[4]}<br>"
                "ISP: %{customdata[5]}<br>"
                "<extra></extra>"
            )
        ))

    st.plotly_chart(fig, use_container_width=True, config={
        'displayModeBar': True,
        'modeBarButtonsToRemove': ['select2d', 'lasso2d'],
        'displaylogo': False
    })

    # ── 5. Tablas de referencia bajo el mapa ────────────────
    col_vpn_t, col_wan_t = st.columns(2)

    with col_vpn_t:
        st.markdown(
            "<h5 style='color:#B100FF;'>"
            "<i class='fa-solid fa-shield-halved'></i> Peers VPN Geolocalizados</h5>",
            unsafe_allow_html=True
        )
        if vpn_points:
            import pandas as pd
            df_vpn = pd.DataFrame([{
                'IP Remota': p['ip'],
                'Protocolo': p.get('protocol', ''),
                'Ciudad': f"{p.get('city','')}, {p.get('country','')}",
                'ISP': p.get('isp', ''),
                'Uptime': p.get('uptime', ''),
            } for p in vpn_points])
            st.dataframe(df_vpn, hide_index=True, use_container_width=True)
        else:
            st.info("Sin peers VPN activos con IP pública.")

    with col_wan_t:
        st.markdown(
            "<h5 style='color:#FF4B4B;'>"
            "<i class='fa-solid fa-earth-americas'></i> Top Talkers WAN Geolocalizados</h5>",
            unsafe_allow_html=True
        )
        if wan_points:
            import pandas as pd
            df_wan = pd.DataFrame([{
                'IP Externa': p['ip'],
                'Tráfico': p['mb_str'],
                'País': p.get('country', ''),
                'Ciudad': p.get('city', ''),
                'ISP/Organización': p.get('isp', ''),
                'Servicios Top': p.get('domains', '')[:50],
            } for p in sorted(wan_points, key=lambda x: x['mb'], reverse=True)])
            st.dataframe(df_wan, hide_index=True, use_container_width=True)
        else:
            st.info("Sin tráfico externo WAN identificado.")

    # ── 6. Indicadores de cobertura ──────────────────────────
    if vpn_points or wan_points:
        total = len(vpn_points) + len(wan_points)
        paises = set(p.get('country','') for p in vpn_points + wan_points if p.get('country'))
        isps = set(p.get('isp','') for p in vpn_points + wan_points if p.get('isp'))
        mc1, mc2, mc3, mc4 = st.columns(4)
        mc1.metric("🌍 IPs Geolocalizadas", total)
        mc2.metric("🔐 Peers VPN", len(vpn_points))
        mc3.metric("📡 WAN Talkers", len(wan_points))
        mc4.metric("🏴 Países", len(paises))
        if isps:
            st.caption(f"**ISPs detectados:** {', '.join(list(isps)[:6])}")
