import sys, io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

import networkx as nx
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
import re

dot_file = 'ODG_Scientific_Final.dot'
with open(dot_file, encoding='utf-8') as f:
    content = f.read()

G = nx.DiGraph()
edge_colors = {}

# Parse nodes
nodes = re.findall(r'"([^"]+)";', content)
for n in nodes:
    G.add_node(n)

# Parse edges: "src" -> "dst" [label="...", color="..."]
edges = re.findall(
    r'"([^"]+)"\s*->\s*"([^"]+)"\s*\[label="([^"]+)",\s*color="([^"]+)"',
    content
)
for src, dst, label, color in edges:
    G.add_edge(src, dst)
    edge_colors[(src, dst)] = color

print(f'Nodes: {G.number_of_nodes()}, Edges: {G.number_of_edges()}')

fig, ax = plt.subplots(figsize=(36, 26))
fig.patch.set_facecolor('#0f172a')
ax.set_facecolor('#0f172a')

# Layout hierarchy
try:
    pos = nx.nx_agraph.graphviz_layout(G, prog='dot')
    print('Using graphviz layout')
except Exception:
    pos = nx.spring_layout(G, k=4.0, seed=42, iterations=120)
    print('Using spring layout')

colors_list = [edge_colors.get((u, v), '#555555') for u, v in G.edges()]

# Draw nodes
nx.draw_networkx_nodes(
    G, pos, ax=ax,
    node_color='#1e293b',
    node_size=2800,
    edgecolors='#3b82f6',
    linewidths=2.0
)

# Draw labels
nx.draw_networkx_labels(
    G, pos, ax=ax,
    font_color='#e2e8f0',
    font_size=7,
    font_family='monospace',
    font_weight='bold'
)

# Draw edges
nx.draw_networkx_edges(
    G, pos, ax=ax,
    edge_color=colors_list,
    arrows=True,
    arrowsize=18,
    arrowstyle='->',
    width=1.8,
    connectionstyle='arc3,rad=0.08',
    min_source_margin=30,
    min_target_margin=30
)

# Legend
legend_patches = [
    mpatches.Patch(color='#1E88E5', label='Identity dependency'),
    mpatches.Patch(color='#E53935', label='Auth / Workflow dependency'),
    mpatches.Patch(color='#43A047', label='Finance dependency'),
    mpatches.Patch(color='#F9A825', label='Medium confidence'),
    mpatches.Patch(color='#555555', label='Other dependency'),
    mpatches.Patch(color='#999999', label='Fallback dependency'),
]
legend = ax.legend(
    handles=legend_patches,
    loc='upper left',
    facecolor='#1e293b',
    edgecolor='#3b82f6',
    labelcolor='white',
    fontsize=10,
    title='Edge Type',
    title_fontsize=11
)
legend.get_title().set_color('white')

ax.set_title(
    'Operation Dependency Graph (ODG) — Hybrid Stateful API Fuzzer',
    color='#f8fafc', fontsize=18, fontweight='bold', pad=25
)
ax.axis('off')

plt.tight_layout()
out_file = 'ODG_graph.png'
plt.savefig(out_file, dpi=150, bbox_inches='tight',
            facecolor='#0f172a', edgecolor='none')
print(f'Saved: {out_file}')
