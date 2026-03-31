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

