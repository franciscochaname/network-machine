# core/network_analysis.py
"""
Motor de Análisis Topológico — Powered by NetworkX + Plotly.
Construye grafos de red desde telemetría MikroTik y genera visualizaciones interactivas.
"""
import networkx as nx
import plotly.graph_objects as go
from netaddr import IPAddress, IPNetwork
import logging


def build_topology_graph(router_db, telemetria: dict) -> nx.Graph:
    """
    Construye un grafo NetworkX completo desde la telemetría del router.
    Nodos: router, interfaces, subredes, dispositivos LAN, peers VPN.
    Aristas: conexiones físicas, lógicas, DHCP, VPN.
    """
    G = nx.Graph()
    router_ip = router_db.ip_address

    # 1. NODO CENTRAL: Router
    info = telemetria.get('info', {})
    G.add_node(router_ip,
               node_type='router', label=info.get('name', router_db.name),
               size=45, color='#00F0FF',
               detail=f"CPU: {info.get('cpu_load', 0)}% | Uptime: {info.get('uptime', 'N/A')}")

    # 2. INTERFACES ACTIVAS
    for iface in telemetria.get('traffic_list', []):
        nid = f"iface:{iface['name']}"
        throughput = iface['rx'] + iface['tx']
        G.add_node(nid, node_type='interface', label=iface['name'],
                   size=20, color='#B100FF',
                   detail=f"↓{iface['rx']}M ↑{iface['tx']}M")
        G.add_edge(router_ip, nid, weight=max(1, throughput), edge_type='physical')

    # 3. SUBREDES LOCALES
    subnets_map = {}  # interface_name → list of CIDRs
    for net in telemetria.get('local_networks', []):
        nid = f"net:{net['network']}"
        G.add_node(nid, node_type='subnet', label=net['network'],
                   size=25, color='#FFAA00',
                   detail=f"Interfaz: {net['interface']} | {net.get('comment', '')}")
        iface_nid = f"iface:{net['interface']}"
        target = iface_nid if iface_nid in G else router_ip
        G.add_edge(target, nid, edge_type='logical', weight=1)
        subnets_map.setdefault(net['interface'], []).append(net['network'])

    # 4. DISPOSITIVOS LAN (DHCP + ARP)
    arp = telemetria.get('arp_table', {})
    all_cidrs = [n['network'] for n in telemetria.get('local_networks', [])]

    for lease in telemetria.get('dhcp', []):
        ip = lease.get('address', '')
        if not ip:
            continue
        mac = arp.get(ip, lease.get('mac-address', 'N/A'))
        hostname = lease.get('host-name', '')
        display = hostname if hostname and hostname != 'N/A' else ip

        G.add_node(ip, node_type='device', label=display,
                   size=12, color='#00FFAA',
                   detail=f"MAC: {mac} | {hostname or 'Sin nombre'}")

        # Conectar al subnet correcto usando netaddr
        connected = False
        try:
            addr = IPAddress(ip)
            for cidr in all_cidrs:
                if addr in IPNetwork(cidr):
                    G.add_edge(f"net:{cidr}", ip, edge_type='dhcp', weight=0.5)
                    connected = True
                    break
        except Exception:
            pass
        if not connected:
            G.add_edge(router_ip, ip, edge_type='dhcp', weight=0.5)

    # 5. CONEXIONES VPN
    for vpn in telemetria.get('vpns', []):
        name = vpn.get('name', 'VPN')
        nid = f"vpn:{name}"
        G.add_node(nid, node_type='vpn', label=f"🌍 {name}",
                   size=18, color='#FF007F',
                   detail=f"IP: {vpn.get('address', 'N/A')} | Conectado: {vpn.get('uptime', 'N/A')}")
        G.add_edge(router_ip, nid, edge_type='vpn', weight=2)

    # 6. TOP TALKERS (conexiones externas significativas, solo los top 5 destinos)
    talkers = telemetria.get('top_talkers', [])
    router_ips = set(telemetria.get('router_ips', []))
    external_seen = set()

    for t in talkers[:10]:
        dst = t.get('destino', '')
        if dst and dst not in G and dst not in router_ips and dst not in external_seen:
            try:
                if IPAddress(dst).is_global():
                    external_seen.add(dst)
                    if len(external_seen) <= 5:
                        G.add_node(dst, node_type='external', label=f"☁ {dst}",
                                   size=10, color='#FF6B35',
                                   detail=f"Tráfico: {t.get('total_mb', 0)} MB | Proto: {t.get('protocolo', 'N/A')}")
                        src = t.get('origen', router_ip)
                        src_node = src if src in G else router_ip
                        G.add_edge(src_node, dst, edge_type='wan', weight=t.get('total_mb', 1))
            except Exception:
                pass

    return G


def calculate_network_metrics(G: nx.Graph) -> dict:
    """Calcula métricas de teoría de grafos sobre la topología."""
    if len(G.nodes) < 2:
        return {'total_nodes': len(G.nodes), 'total_edges': G.number_of_edges()}

    metrics = {
        'total_nodes': G.number_of_nodes(),
        'total_edges': G.number_of_edges(),
        'density': round(nx.density(G), 4),
    }

    # Conteo por tipo
    type_counts = {}
    for _, data in G.nodes(data=True):
        t = data.get('node_type', 'unknown')
        type_counts[t] = type_counts.get(t, 0) + 1
    metrics['type_counts'] = type_counts

    # Betweenness Centrality (nodos más críticos)
    try:
        centrality = nx.betweenness_centrality(G)
        top = sorted(centrality.items(), key=lambda x: x[1], reverse=True)[:5]
        metrics['critical_nodes'] = [
            {'node': G.nodes[n].get('label', n), 'centrality': round(c, 4)}
            for n, c in top if c > 0
        ]
    except Exception:
        metrics['critical_nodes'] = []

    # Componentes conectados
    components = list(nx.connected_components(G))
    metrics['components'] = len(components)

    # Diámetro de la red
    try:
        if components:
            largest = max(components, key=len)
            metrics['diameter'] = nx.diameter(G.subgraph(largest))
    except Exception:
        metrics['diameter'] = 'N/A'

    # Clustering coefficient promedio
    try:
        metrics['avg_clustering'] = round(nx.average_clustering(G), 4)
    except Exception:
        metrics['avg_clustering'] = 0

    # Grado promedio
    degrees = [d for _, d in G.degree()]
    metrics['avg_degree'] = round(sum(degrees) / len(degrees), 2) if degrees else 0

    return metrics


def generate_topology_figure(G: nx.Graph) -> go.Figure:
    """Genera una visualización Plotly interactiva del grafo topológico."""
    if len(G.nodes) == 0:
        return go.Figure()

    # Calcular layout
    if len(G.nodes) <= 5:
        pos = nx.spring_layout(G, k=3, seed=42)
    else:
        try:
            pos = nx.kamada_kawai_layout(G)
        except Exception:
            pos = nx.spring_layout(G, k=1.5, seed=42, iterations=50)

    fig = go.Figure()

    # --- EDGES ---
    edge_styles = {
        'physical': {'color': 'rgba(0, 240, 255, 0.35)', 'dash': 'solid'},
        'logical':  {'color': 'rgba(255, 170, 0, 0.25)', 'dash': 'dot'},
        'dhcp':     {'color': 'rgba(0, 255, 170, 0.12)', 'dash': 'solid'},
        'vpn':      {'color': 'rgba(255, 0, 127, 0.4)',  'dash': 'dash'},
        'wan':      {'color': 'rgba(255, 107, 53, 0.3)', 'dash': 'dot'},
    }

    for u, v, data in G.edges(data=True):
        etype = data.get('edge_type', 'dhcp')
        style = edge_styles.get(etype, edge_styles['dhcp'])
        weight = data.get('weight', 1)
        x0, y0 = pos[u]
        x1, y1 = pos[v]
        fig.add_trace(go.Scatter(
            x=[x0, x1, None], y=[y0, y1, None],
            mode='lines',
            line=dict(width=max(0.5, min(weight, 6)), color=style['color'], dash=style['dash']),
            hoverinfo='none', showlegend=False
        ))

    # --- NODES (agrupados por tipo para leyenda) ---
    type_config = {
        'router':    {'name': '🔲 Router',     'symbol': 'diamond'},
        'interface': {'name': '🔌 Interfaz',   'symbol': 'square'},
        'subnet':    {'name': '🌐 Subred',     'symbol': 'hexagon2'},
        'device':    {'name': '💻 Dispositivo', 'symbol': 'circle'},
        'vpn':       {'name': '🌍 VPN',        'symbol': 'star'},
        'external':  {'name': '☁ Externo',     'symbol': 'triangle-up'},
    }

    groups = {}
    for node, data in G.nodes(data=True):
        nt = data.get('node_type', 'device')
        groups.setdefault(nt, []).append((node, data))

    for nt, nodes in groups.items():
        cfg = type_config.get(nt, {'name': nt, 'symbol': 'circle'})
        xs, ys, texts, sizes, colors, hovers = [], [], [], [], [], []
        for node, data in nodes:
            x, y = pos[node]
            xs.append(x)
            ys.append(y)
            texts.append(data.get('label', ''))
            sizes.append(data.get('size', 12))
            colors.append(data.get('color', '#888'))
            hovers.append(f"<b>{data.get('label', node)}</b><br>{data.get('detail', '')}")

        fig.add_trace(go.Scatter(
            x=xs, y=ys, mode='markers+text',
            marker=dict(size=sizes, color=colors, symbol=cfg['symbol'],
                        line=dict(width=1.5, color='rgba(255,255,255,0.15)')),
            text=texts, textposition='top center',
            textfont=dict(size=9, color='#777'),
            hovertext=hovers, hoverinfo='text',
            customdata=[n[0] for n in nodes],
            name=cfg['name']
        ))

    fig.update_layout(
        template='plotly_dark', height=560,
        paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, visible=False),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, visible=False),
        margin=dict(l=5, r=5, t=5, b=5),
        legend=dict(orientation='h', yanchor='bottom', y=1.02, xanchor='center', x=0.5,
                    font=dict(size=11, color='#999'), bgcolor='rgba(0,0,0,0)'),
        dragmode='pan',
        hoverlabel=dict(bgcolor='#1A1C23', bordercolor='#00F0FF',
                        font=dict(size=12, color='white', family='JetBrains Mono'))
    )
    return fig


# ================================================================
# ANÁLISIS AVANZADO — What-If, SPOF, Shortest Path, Sankey
# ================================================================

def simulate_node_failure(G: nx.Graph, node_to_remove: str) -> dict:
    """
    Simula la caída de un nodo y calcula el impacto en la red.
    Retorna: dispositivos afectados directos, nodos aislados, fragmentos de red.
    """
    if node_to_remove not in G:
        return {'error': 'Nodo no existe en el grafo'}

    label = G.nodes[node_to_remove].get('label', node_to_remove)
    direct_neighbors = list(G.neighbors(node_to_remove))

    G_copy = G.copy()
    G_copy.remove_node(node_to_remove)

    components_before = nx.number_connected_components(G)
    components_after_list = list(nx.connected_components(G_copy))
    components_after = len(components_after_list)

    isolated = [n for c in components_after_list if len(c) == 1 for n in c]
    largest = max((len(c) for c in components_after_list), default=0)

    affected_devices = []
    for n in direct_neighbors:
        data = G.nodes[n]
        affected_devices.append({
            'node': data.get('label', n),
            'type': data.get('node_type', 'unknown'),
        })

    severity = 'CRÍTICO' if components_after > components_before + 1 else 'MODERADO' if components_after > components_before else 'BAJO'

    return {
        'removed': label,
        'direct_impact': len(direct_neighbors),
        'isolated_nodes': len(isolated),
        'network_fragments': components_after,
        'largest_fragment': largest,
        'severity': severity,
        'affected_devices': affected_devices,
    }


def find_spof(G: nx.Graph) -> dict:
    """
    Encuentra Single Points of Failure:
    - Articulation Points: nodos cuya eliminación desconecta la red
    - Bridges: enlaces cuya eliminación desconecta la red
    """
    try:
        art_points = list(nx.articulation_points(G))
        bridges = list(nx.bridges(G))
    except Exception:
        return {'spof_nodes': [], 'bridges': [], 'redundancy_score': 0}

    spof_details = []
    for n in art_points:
        data = G.nodes.get(n, {})
        impact = simulate_node_failure(G, n)
        spof_details.append({
            'node': data.get('label', n),
            'node_id': n,
            'type': data.get('node_type', 'unknown'),
            'fragments_if_removed': impact['network_fragments'],
            'isolated_if_removed': impact['isolated_nodes'],
            'severity': impact['severity'],
        })

    bridge_details = []
    for u, v in bridges:
        u_label = G.nodes[u].get('label', u)
        v_label = G.nodes[v].get('label', v)
        bridge_details.append({'from': u_label, 'to': v_label})

    total_nodes = max(G.number_of_nodes(), 1)
    redundancy = round(1 - (len(art_points) / total_nodes), 3)

    return {
        'spof_nodes': spof_details,
        'bridges': bridge_details,
        'total_spof': len(art_points),
        'total_bridges': len(bridges),
        'redundancy_score': redundancy,
    }


def find_shortest_path(G: nx.Graph, source: str, target: str) -> dict:
    """Encuentra la ruta más corta y alternativas entre dos nodos."""
    try:
        shortest = nx.shortest_path(G, source, target)
        all_paths = list(nx.all_simple_paths(G, source, target, cutoff=len(shortest) + 2))

        path_labels = [G.nodes[n].get('label', n) for n in shortest]

        return {
            'path': path_labels,
            'hops': len(shortest) - 1,
            'alternative_routes': max(0, len(all_paths) - 1),
            'redundancy': 'ALTA' if len(all_paths) > 2 else 'MEDIA' if len(all_paths) == 2 else 'NINGUNA',
            'path_ids': shortest,
        }
    except nx.NetworkXNoPath:
        return {'error': 'No hay ruta entre los nodos seleccionados'}
    except nx.NodeNotFound as e:
        return {'error': f'Nodo no encontrado: {e}'}


def generate_traffic_sankey(top_talkers: list) -> go.Figure:
    """Genera un diagrama Sankey de flujos de tráfico origen→destino."""
    if not top_talkers:
        return go.Figure()

    sources, targets, values, labels = [], [], [], []
    unique_nodes = {}
    idx = 0

    for t in top_talkers[:15]:
        orig = t.get('origen', '?')
        dest = t.get('destino', '?')
        vol = t.get('total_mb', 0)
        if vol <= 0:
            continue

        for node in [orig, dest]:
            if node not in unique_nodes:
                unique_nodes[node] = idx
                labels.append(node)
                idx += 1

        sources.append(unique_nodes[orig])
        targets.append(unique_nodes[dest])
        values.append(vol)

    if not sources:
        fig = go.Figure()
        fig.update_layout(template='plotly_dark', paper_bgcolor='rgba(0,0,0,0)',
                          annotations=[dict(text="Sin datos de tráfico", showarrow=False,
                                            font=dict(size=16, color='#555'))])
        return fig

    fig = go.Figure(go.Sankey(
        arrangement='snap',
        node=dict(
            label=labels, pad=20, thickness=25,
            color=['#00F0FF' if i < len(labels) // 2 else '#FF007F' for i in range(len(labels))],
            line=dict(color='rgba(255,255,255,0.1)', width=1),
        ),
        link=dict(
            source=sources, target=targets, value=values,
            color='rgba(0, 240, 255, 0.15)',
            hovertemplate='%{source.label} → %{target.label}<br>%{value:.1f} MB<extra></extra>',
        )
    ))

    fig.update_layout(
        template='plotly_dark', height=450,
        paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
        margin=dict(l=10, r=10, t=10, b=10),
        font=dict(size=11, color='#888', family='JetBrains Mono'),
    )
    return fig
def classify_network_topology(G: nx.Graph) -> dict:
    """Clasifica la topología de red según patrones de teoría de grafos. Incluye evidencia."""
    n = G.number_of_nodes()
    e = G.number_of_edges()
    
    if n < 2:
        return {'type': 'Punto a Punto', 'icon': '⬤', 'confidence': 100,
                'description': 'Red mínima.', 'color': '#888', 'risk': 'N/A',
                'evidence': ['Solo hay 1 nodo en el grafo'], 'metrics': {}}

    density = nx.density(G)
    degrees = dict(G.degree())
    max_degree = max(degrees.values()) if degrees else 0
    min_degree = min(degrees.values()) if degrees else 0
    avg_degree = sum(degrees.values()) / n if n > 0 else 0
    degree_values = list(degrees.values())
    
    hub_node = max(degrees, key=degrees.get) if degrees else None
    hub_label = G.nodes[hub_node].get('label', hub_node) if hub_node else ""
    hub_pct = max_degree / (n - 1) if n > 1 else 0
    
    deg_1 = degree_values.count(1)
    deg_2 = degree_values.count(2)
    has_cycles = e >= n
    
    try:
        art_points = len(list(nx.articulation_points(G)))
    except Exception:
        art_points = 0
    
    raw_metrics = {
        'nodos': n, 'enlaces': e, 'densidad': round(density, 4),
        'grado_max': max_degree, 'grado_min': min_degree,
        'grado_promedio': round(avg_degree, 2),
        'hub': hub_label, 'hub_conexiones': max_degree,
        'hub_pct': round(hub_pct * 100, 1),
        'nodos_hoja': deg_1, 'nodos_cadena': deg_2,
        'tiene_ciclos': has_cycles, 'puntos_articulacion': art_points,
    }
    
    if hub_pct > 0.6 and max_degree > avg_degree * 2.5:
        return {'type': 'Estrella (Star)', 'icon': '⭐', 'confidence': min(95, int(hub_pct * 100)),
                'color': '#FF4B4B', 'risk': 'ALTO — Single Point of Failure',
                'description': f'El nodo central "{hub_label}" concentra {max_degree} de {n-1} conexiones posibles.',
                'evidence': [
                    f'Hub "{hub_label}" tiene {max_degree} conexiones ({hub_pct:.0%} del máximo)',
                    f'El grado promedio es {avg_degree:.1f}',
                    f'{deg_1} de {n} nodos son hojas (grado 1)'
                ], 'metrics': raw_metrics}
    
    if deg_2 == n and has_cycles:
        return {'type': 'Anillo (Ring)', 'icon': '🔄', 'confidence': 95, 'color': '#FFAA00',
                'risk': 'MEDIO — Doble fallo causa partición',
                'description': f'Todos los {n} nodos tienen exactamente grado 2.',
                'evidence': [f'Los {n} nodos tienen grado 2', 'Existen ciclos en el grafo'], 'metrics': raw_metrics}
    
    if deg_1 == 2 and deg_2 >= (n - 2) * 0.8 and not has_cycles:
        return {'type': 'Bus (Lineal)', 'icon': '━━━', 'confidence': 85, 'color': '#FF6B35',
                'risk': 'ALTO — Cualquier fallo intermedio divide la red',
                'description': f'Cadena lineal: {deg_2} nodos intermedios.',
                'evidence': [f'2 nodos terminales', f'{deg_2} intermedios con grado 2', 'Sin ciclos detectados'], 'metrics': raw_metrics}
    
    if density >= 0.6:
        return {'type': 'Malla Completa', 'icon': '🕸', 'confidence': int(density * 100), 'color': '#00FFAA',
                'risk': 'BAJO — Alta redundancia',
                'description': f'Red de alta densidad ({density:.0%}).',
                'evidence': [f'Densidad del grafo: {density:.4f} (≥0.6 = malla completa)'], 'metrics': raw_metrics}
    
    if not has_cycles and e == n - 1:
        return {'type': 'Árbol (Tree)', 'icon': '🌳', 'confidence': 90, 'color': '#FFAA00',
                'risk': 'MEDIO-ALTO — Sin rutas alternativas',
                'description': f'Topología jerárquica sin ciclos.',
                'evidence': [f'Enlaces ({e}) = Nodos ({n}) - 1', 'Sin ciclos detectados'], 'metrics': raw_metrics}
    
    if density >= 0.3:
        return {'type': 'Malla Parcial', 'icon': '🔗', 'confidence': int(density * 130), 'color': '#00F0FF',
                'risk': 'MEDIO — Redundancia parcial',
                'description': f'Densidad {density:.0%}, caminos alternativos.',
                'evidence': [f'Densidad {density:.4f}', 'Existen ciclos'], 'metrics': raw_metrics}
    
    return {'type': 'Híbrida', 'icon': '🔀', 'confidence': 60, 'color': '#00F0FF',
            'risk': 'VARIABLE', 'description': 'No encaja en un patrón puro.',
            'evidence': [f'Densidad {density:.4f}', f'Hub concentra {hub_pct:.0%}'], 'metrics': raw_metrics}


def generate_topology_html(G: nx.Graph, height="650px") -> str:
    """Genera visualización Cytoscape con Dagre layout e íconos Cisco/AWS."""
    import json, html
    if len(G.nodes) == 0: return "<div style='color:#555;'>Sin nodos</div>"

    svg_icons = {
        'internet': "data:image/svg+xml;base64,PHN2ZyB4bWxucz0naHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmcnIHZpZXdCb3g9JzAgMCAxMDAgMTAwJz48cGF0aCBkPSdNMjUgNjUgYTIwIDIwIDAgMCAxIDAgLTQwIGEyNSAyNSAwIDAgMSA1MCAtMTAgYTI1IDI1IDAgMCAxIDIwIDQwIGEyMCAyMCAwIDAgMSAwIDQwIEwyNSA5NSB6JyBmaWxsPScjMDJBMEYwJyBvcGFjaXR5PScwLjknLz48cGF0aCBkPSdNMjUgNjUgYTIwIDIwIDAgMCAxIDAgLTQwIGEyNSAyNSAwIDAgMSA1MCAtMTAgYTI1IDI1IDAgMCAxIDIwIDQwIGEyMCAyMCAwIDAgMSAwIDQwIEwyNSA5NSB6JyBzdHJva2U9J3doaXRlJyBzdHJva2Utd2lkdGg9JzQnIGZpbGw9J25vbmUnLz48L3N2Zz4=",
        'router': "data:image/svg+xml;base64,PHN2ZyB4bWxucz0naHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmcnIHZpZXdCb3g9JzAgMCAxMDAgMTAwJz48Y2lyY2xlIGN4PSc1MCcgY3k9JzUwJyByPSc0NScgZmlsbD0nIzAwYmNlYicvPjxwYXRoIGQ9J001MCAxNSBMNTAgODUgTTE1IDUwIEw4NSA1MCcgc3Ryb2tlPSd3aGl0ZScgc3Ryb2tlLXdpZHRoPSc2Jy8+PHBhdGggZD0nTTUwIDE1IEw0MCAyNSBNNTAgMTUgTDYwIDI1IE01MCA4NSBMNDAgNzUgTTUwIDg1IEw2MCA3NSBNMTUgNTAgTDI1IDQwIE0xNSA1MCBMMjUgNjAgTTg1IDUwIEw3NSA0MCBNODUgNTAgTDc1IDYwJyBzdHJva2U9J3doaXRlJyBzdHJva2Utd2lkdGg9JzYnIGZpbGw9J25vbmUnLz48L3N2Zz4=",
        'switch': "data:image/svg+xml;base64,PHN2ZyB4bWxucz0naHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmcnIHZpZXdCb3g9JzAgMCAxMDAgMTAwJz48cmVjdCB4PScxMCcgeT0nMjUnIHdpZHRoPSc4MCcgaGVpZ2h0PSc1MCcgcng9JzUnIGZpbGw9JyMwMGJjZWInLz48cGF0aCBkPSdNMjAgNDAgTDgwIDQwIE0yMCA2MCBMODAgNjAnIHN0cm9rZT0nd2hpdGUnIHN0cm9rZS13aWR0aD0nNCcvPjxwYXRoIGQ9J004MCA0MCBMNzAgMzUgTTgwIDQwIEw3MCA0NSBNMjAgNjAgTDMwIDU1IE0yMCA2MCBMMzAgNjUnIHN0cm9rZT0nd2hpdGUnIHN0cm9rZS13aWR0aD0nNCcgZmlsbD0nbm9uZScvPjwvc3ZnPg==",
        'firewall': "data:image/svg+xml;base64,PHN2ZyB4bWxucz0naHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmcnIHZpZXdCb3g9JzAgMCAxMDAgMTAwJz48cmVjdCB4PScxNScgeT0nMjAnIHdpZHRoPSc3MCcgaGVpZ2h0PSc2MCcgZmlsbD0nI0UxMkQzOScvPjxwYXRoIGQ9J00xNSA0MCBMODUgNDAgTTE1IDYwIEw4NSA2MCBNMzAgMjAgTDMwIDQwIE02MCAyMCBMNjAgNDAgTTQ1IDQwIEw0NSA2MCBNMjAgNjAgTDIwIDgwIE03NSA2MCBMNzUgODAnIHN0cm9rZT0nd2hpdGUnIHN0cm9rZS13aWR0aD0nNCcvPjwvc3ZnPg==",
        'wifi': "data:image/svg+xml;base64,PHN2ZyB4bWxucz0naHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmcnIHZpZXdCb3g9JzAgMCAxMDAgMTAwJz48Y2lyY2xlIGN4PSc1MCcgY3k9JzgwJyByPScxMCcgZmlsbD0nIzAwYmNlYicvPjxwYXRoIGQ9J00zMCA2MCBhMzAgMzAgMCAwIDEgNDAgMCBNMjAgNDAgYTQ1IDQ1IDAgMCAxIDYwIDAgTTEwIDIwIGE2MCA2MCAwIDAgMSA4MCAwJyBzdHJva2U9JyMwMGJjZWInIGZpbGw9J25vbmUnIHN0cm9rZS13aWR0aD0nOCcvPjwvc3ZnPg==",
        'device': "data:image/svg+xml;base64,PHN2ZyB4bWxucz0naHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmcnIHZpZXdCb3g9JzAgMCAxMDAgMTAwJz48cmVjdCB4PScyMCcgeT0nMzAnIHdpZHRoPSc2MCcgaGVpZ2h0PSc0MCcgcng9JzMnIHN0cm9rZT0nI0FBQUFBQScgZmlsbD0nIzIyMjIyMicgc3Ryb2tlLXdpZHRoPSc1Jy8+PHBhdGggZD0nTTEwIDgwIEw5MCA4MCcgc3Ryb2tlPScjMDBiY2ViJyBzdHJva2Utd2lkdGg9JzgnIHN0cm9rZS1saW5lY2FwPSdyb3VuZCcvPjwvc3ZnPg==",
        'vpn': "data:image/svg+xml;base64,PHN2ZyB4bWxucz0naHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmcnIHZpZXdCb3g9JzAgMCAxMDAgMTAwJz48Y2lyY2xlIGN4PSc1MCcgY3k9JzUwJyByPSc0NScgZmlsbD0nI0RFMTgyRCcvPjxwYXRoIGQ9J000MCA0NSBMNDAgMzUgQTEwIDEwIDAgMCAxIDYwIDM1IEw2MCA0NSBNMzUgNDUgTDY1IDQ1IEw2NSA3MCBMMzUgNzAgWicgZmlsbD0nbm9uZScgc3Ryb2tlPSd3aGl0ZScgc3Ryb2tlLXdpZHRoPSc2Jy8+PGNpcmNsZSBjeD0nNTAnIGN5PSc1NScgcj0nMycgZmlsbD0nd2hpdGUnLz48cGF0aCBkPSdNNTAgNTUgTDUwIDYyJyBzdHJva2U9J3doaXRlJyBzdHJva2Utd2lkdGg9JzQnLz48L3N2Zz4=",
        'wan': "data:image/svg+xml;base64,PHN2ZyB4bWxucz0naHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmcnIHZpZXdCb3g9JzAgMCAxMDAgMTAwJz48cGF0aCBkPSdNNTAgMTUgTDg1IDg1IEwxNSA4NSBaJyBmaWxsPScjRkY2QjM1Jy8+PHBhdGggZD0nTTUwIDM1IEw1MCA2MCBNNTAgNzUgTDUwIDc2JyBzdHJva2U9J3doaXRlJyBzdHJva2Utd2lkdGg9JzYnIHN0cm9rZS1saW5lY2FwPSdyb3VuZCcvPjwvc3ZnPg=="
    }

    def get_icon(nt):
        if 'internet' in nt or 'external' in nt: return svg_icons['internet']
        if 'router' in nt or 'gateway' in nt: return svg_icons['router']
        if 'bridge' in nt or 'ethernet' in nt or 'switch' in nt: return svg_icons['switch']
        if 'wireless' in nt: return svg_icons['wifi']
        if 'vpn' in nt or 'tunnel' in nt: return svg_icons['vpn']
        if 'wan' in nt: return svg_icons['wan']
        return svg_icons['device']

    elements = []
    for node, data in G.nodes(data=True):
        nt = data.get('node_type', 'device')
        label = data.get('label', str(node)).replace('\n', ' ')
        detail_raw = data.get('detail', '')
        detail_html = html.escape(detail_raw).replace('\n', '<br>')
        elements.append({
            'group': 'nodes',
            'data': {'id': str(node), 'label': label, 'type': nt, 'detail': detail_html,
                     'bg_image': get_icon(nt), 'node_size': 45 if ('router' in nt or 'gateway' in nt or 'wan' in nt) else 35}
        })
        
    edge_styles = {'physical': {'c': '#00bceb', 's': 'solid'}, 'logical': {'c': '#FFAA00', 's': 'dashed'}, 'dhcp': {'c': '#444444', 's': 'solid'}, 'vpn': {'c': '#DE182D', 's': 'dashed'}, 'wan': {'c': '#FF6B35', 's': 'solid'}}
    for u, v, data in G.edges(data=True):
        etype = data.get('edge_type', 'physical')
        weight = data.get('weight', 1)
        st = edge_styles.get(etype, edge_styles['physical'])
        elements.append({
            'group': 'edges',
            'data': {'id': f"e_{u}_{v}", 'source': str(u), 'target': str(v),
                     'line_color': st['c'], 'line_style': st['s'], 'width': max(1, min(weight * 0.8, 6)),
                     'tooltip': html.escape(data.get('detail', ''))}
        })

    elements_json = json.dumps(elements, ensure_ascii=False)

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.26.0/cytoscape.min.js"></script>
        <script src="https://unpkg.com/dagre@0.7.4/dist/dagre.js"></script>
        <script src="https://unpkg.com/cytoscape-dagre@2.5.0/cytoscape-dagre.js"></script>
        <style>
            * {{ margin: 0; padding: 0; box-sizing: border-box; }}
            body {{ background: transparent; overflow: hidden; font-family: 'Inter', sans-serif; }}
            #cy {{ width: 100%; height: {height}; border: 1px solid rgba(255,255,255,0.08); border-radius: 12px; background: linear-gradient(135deg, rgba(13,15,20,0.95) 0%, rgba(5,7,10,0.98) 100%); }}
            #controls {{ position: absolute; top: 16px; left: 16px; display: flex; gap: 8px; z-index: 100; }}
            button {{ background: rgba(20,25,35,0.8); border: 1px solid rgba(255,255,255,0.15); border-radius: 6px; padding: 6px 14px; color: #bbb; font-size: 11px; font-weight: 600; cursor: pointer; backdrop-filter: blur(4px); }}
            button:hover {{ background: rgba(0,188,235,0.2); border-color: #00bceb; color: #fff; }}
            #legend {{ position: absolute; bottom: 16px; left: 16px; background: rgba(15,20,25,0.9); border: 1px solid rgba(255,255,255,0.1); border-radius: 8px; padding: 12px; color: #888; font-size: 11px; line-height: 1.6; z-index: 100; backdrop-filter: blur(8px); }}
            #tooltip {{ position: absolute; display: none; background: rgba(20,25,30,0.95); border: 1px solid #00bceb; border-radius: 6px; padding: 12px; color: #ddd; font-size: 11px; pointer-events: none; z-index: 999; box-shadow: 0 4px 20px rgba(0,0,0,0.5); font-family: 'JetBrains Mono', monospace; }}
        </style>
    </head>
    <body>
        <div style="position:relative;">
            <div id="cy"></div>
            <div id="controls">
                <button onclick="cy.fit(null, 50)">⊞ Ajustar Plano</button>
                <button onclick="runLayout('dagre')">▼ Dirigido Dagre</button>
                <button onclick="runLayout('cose')">💫 Físico COSE</button>
            </div>
            <div id="legend">
                <b>Cisco/AWS Blueprint</b><br>
                <span style="color:#00bceb">■</span> Core / L2 / Switch<br>
                <span style="color:#DE182D">■</span> Firewall / VPN<br>
                <span style="color:#FF6B35">▼</span> WAN Links
            </div>
            <div id="tooltip"></div>
        </div>
        <script>
            var elements = {elements_json};
            var cy = cytoscape({{
                container: document.getElementById('cy'),
                elements: elements,
                style: [
                    {{ selector: 'node', style: {{ 'width': 'data(node_size)', 'height': 'data(node_size)', 'background-color': 'transparent', 'background-image': 'data(bg_image)', 'background-fit': 'contain', 'background-clip': 'none', 'background-width': '100%', 'background-height': '100%', 'label': 'data(label)', 'color': '#aaaaaa', 'font-size': '11px', 'font-family': 'Inter', 'text-valign': 'bottom', 'text-halign': 'center', 'text-margin-y': 5, 'text-outline-width': 2, 'text-outline-color': '#111', 'min-zoomed-font-size': 8 }} }},
                    {{ selector: 'node:selected', style: {{ 'overlay-color': '#00bceb', 'overlay-padding': '4px', 'overlay-opacity': 0.3 }} }},
                    {{ selector: 'edge', style: {{ 'width': 'data(width)', 'line-color': 'data(line_color)', 'line-style': 'data(line_style)', 'curve-style': 'bezier', 'target-arrow-shape': 'triangle', 'target-arrow-color': 'data(line_color)', 'arrow-scale': 0.8, 'opacity': 0.7 }} }},
                    {{ selector: 'edge:selected', style: {{ 'opacity': 1, 'width': 4, 'line-color': '#00F0FF', 'target-arrow-color': '#00F0FF' }} }}
                ],
                layout: {{ name: 'dagre', rankDir: 'TB', nodeSep: 60, edgeSep: 40, rankSep: 100, padding: 50 }},
                wheelSensitivity: 0.1
            }});
            function runLayout(type) {{
                cy.layout(type === 'dagre' ? {{ name: 'dagre', rankDir: 'TB', nodeSep: 60, rankSep: 100, animate: true }} : {{ name: 'cose', nodeRepulsion: 400000, idealEdgeLength: 100, animate: true }}).run();
            }}
            var tooltip = document.getElementById('tooltip');
            cy.on('mouseover', 'node', function(e) {{
                var d = e.target.data('detail');
                if(d) {{ tooltip.innerHTML = "<b style='color:#00bceb;'>" + e.target.data('label') + "</b><hr style='border:1px solid #333;margin:5px 0;'>" + d; tooltip.style.display = 'block'; document.body.style.cursor = 'pointer'; }}
            }});
            cy.on('mouseout', function() {{ tooltip.style.display = 'none'; document.body.style.cursor = 'default'; }});
            cy.on('mousemove', function(e) {{ if(tooltip.style.display==='block'){{ tooltip.style.left=(e.originalEvent.pageX+15)+'px'; tooltip.style.top=(e.originalEvent.pageY+15)+'px'; }} }});
        </script>
    </body>
    </html>
    """
# ================================================================
# ANÁLISIS AVANZADO — What-If, SPOF, Shortest Path, Sankey
# ================================================================

def simulate_node_failure(G: nx.Graph, node_to_remove: str) -> dict:
    """
    Simula la caída de un nodo y calcula el impacto en la red.
    Retorna: dispositivos afectados directos, nodos aislados, fragmentos de red.
    """
    if node_to_remove not in G:
        return {'error': 'Nodo no existe en el grafo'}

    label = G.nodes[node_to_remove].get('label', node_to_remove)
    direct_neighbors = list(G.neighbors(node_to_remove))

    G_copy = G.copy()
    G_copy.remove_node(node_to_remove)

    components_before = nx.number_connected_components(G)
    components_after_list = list(nx.connected_components(G_copy))
    components_after = len(components_after_list)

    isolated = [n for c in components_after_list if len(c) == 1 for n in c]
    largest = max((len(c) for c in components_after_list), default=0)

    affected_devices = []
    for n in direct_neighbors:
        data = G.nodes[n]
        affected_devices.append({
            'node': data.get('label', n),
            'type': data.get('node_type', 'unknown'),
        })

    severity = 'CRÍTICO' if components_after > components_before + 1 else 'MODERADO' if components_after > components_before else 'BAJO'

    return {
        'removed': label,
        'direct_impact': len(direct_neighbors),
        'isolated_nodes': len(isolated),
        'network_fragments': components_after,
        'largest_fragment': largest,
        'severity': severity,
        'affected_devices': affected_devices,
    }


def find_spof(G: nx.Graph) -> dict:
    """
    Encuentra Single Points of Failure:
    - Articulation Points: nodos cuya eliminación desconecta la red
    - Bridges: enlaces cuya eliminación desconecta la red
    """
    try:
        art_points = list(nx.articulation_points(G))
        bridges = list(nx.bridges(G))
    except Exception:
        return {'spof_nodes': [], 'bridges': [], 'redundancy_score': 0}

    spof_details = []
    for n in art_points:
        data = G.nodes.get(n, {})
        impact = simulate_node_failure(G, n)
        spof_details.append({
            'node': data.get('label', n),
            'node_id': n,
            'type': data.get('node_type', 'unknown'),
            'fragments_if_removed': impact['network_fragments'],
            'isolated_if_removed': impact['isolated_nodes'],
            'severity': impact['severity'],
        })

    bridge_details = []
    for u, v in bridges:
        u_label = G.nodes[u].get('label', u)
        v_label = G.nodes[v].get('label', v)
        bridge_details.append({'from': u_label, 'to': v_label})

    total_nodes = max(G.number_of_nodes(), 1)
    redundancy = round(1 - (len(art_points) / total_nodes), 3)

    return {
        'spof_nodes': spof_details,
        'bridges': bridge_details,
        'total_spof': len(art_points),
        'total_bridges': len(bridges),
        'redundancy_score': redundancy,
    }


def find_shortest_path(G: nx.Graph, source: str, target: str) -> dict:
    """Encuentra la ruta más corta y alternativas entre dos nodos."""
    try:
        shortest = nx.shortest_path(G, source, target)
        all_paths = list(nx.all_simple_paths(G, source, target, cutoff=len(shortest) + 2))

        path_labels = [G.nodes[n].get('label', n) for n in shortest]

        return {
            'path': path_labels,
            'hops': len(shortest) - 1,
            'alternative_routes': max(0, len(all_paths) - 1),
            'redundancy': 'ALTA' if len(all_paths) > 2 else 'MEDIA' if len(all_paths) == 2 else 'NINGUNA',
            'path_ids': shortest,
        }
    except nx.NetworkXNoPath:
        return {'error': 'No hay ruta entre los nodos seleccionados'}
    except nx.NodeNotFound as e:
        return {'error': f'Nodo no encontrado: {e}'}


def generate_traffic_sankey(top_talkers: list) -> go.Figure:
    """Genera un diagrama Sankey de flujos de tráfico origen→destino."""
    if not top_talkers:
        return go.Figure()

    sources, targets, values, labels = [], [], [], []
    unique_nodes = {}
    idx = 0

    for t in top_talkers[:15]:
        orig = t.get('origen', '?')
        dest = t.get('destino', '?')
        vol = t.get('total_mb', 0)
        if vol <= 0:
            continue

        for node in [orig, dest]:
            if node not in unique_nodes:
                unique_nodes[node] = idx
                labels.append(node)
                idx += 1

        sources.append(unique_nodes[orig])
        targets.append(unique_nodes[dest])
        values.append(vol)

    if not sources:
        fig = go.Figure()
        fig.update_layout(template='plotly_dark', paper_bgcolor='rgba(0,0,0,0)',
                          annotations=[dict(text="Sin datos de tráfico", showarrow=False,
                                            font=dict(size=16, color='#555'))])
        return fig

    fig = go.Figure(go.Sankey(
        arrangement='snap',
        node=dict(
            label=labels, pad=20, thickness=25,
            color=['#00F0FF' if i < len(labels) // 2 else '#FF007F' for i in range(len(labels))],
            line=dict(color='rgba(255,255,255,0.1)', width=1),
        ),
        link=dict(
            source=sources, target=targets, value=values,
            color='rgba(0, 240, 255, 0.15)',
            hovertemplate='%{source.label} → %{target.label}<br>%{value:.1f} MB<extra></extra>',
        )
    ))

    fig.update_layout(
        template='plotly_dark', height=450,
        paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
        margin=dict(l=10, r=10, t=10, b=10),
        font=dict(size=11, color='#888', family='JetBrains Mono'),
    )
    return fig



def generate_bandwidth_sunburst(G: nx.Graph) -> go.Figure:
    fig = go.Figure(go.Sunburst(
        labels=["WAN", "LAN", "VPN"],
        parents=["", "WAN", "WAN"],
        values=[100, 70, 30]
    ))
    fig.update_layout(template='plotly_dark', paper_bgcolor='rgba(0,0,0,0)')
    return fig
