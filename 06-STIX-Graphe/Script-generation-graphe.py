#!/usr/bin/env python3
"""Génère Graphe-CTI.png et Graphe-CTI.pdf DEPUIS Bundle-STIX.json (jamais depuis une autre source).
FILTRE DOCUMENTE : sont affichés les objets analytiques (campaign, malware, attack-pattern, indicator), les identités (victime, systèmes) et les observables
cibles d'un `based-on` ; ne sont PAS affichés : report, grouping, notes, observed-data, network-traffic, marquages, autres observables (voir Rapport-validation-STIX.md).
Légende des arêtes : trait plein = OBSERVE ; tirets = HYPOTHESE ; pointillés = DECLARE (fiche, non vérifié). Le cluster est NON ATTRIBUE (nœud en pointillés).
Régénérer : /Users/rapatt/Projet/cti-helios-env/.venv/bin/python 06-STIX-Graphe/Script-generation-graphe.py"""
import json, os, textwrap
import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt, networkx as nx
G0 = os.path.dirname(os.path.abspath(__file__))
b = json.load(open(os.path.join(G0, "Bundle-STIX.json"), encoding="utf-8")); by = {o["id"]: o for o in b["objects"]}
SHOW = {"campaign", "malware", "attack-pattern", "indicator", "identity"}
rels = [o for o in b["objects"] if o["type"] == "relationship"]
obs_targets = {r["target_ref"] for r in rels if r["relationship_type"] == "based-on"}
keep = {i for i, o in by.items() if o["type"] in SHOW} | obs_targets
keep -= {i for i, o in by.items() if o["type"] == "identity" and o["name"] in ("CHALLENGE-FICTIF", "[CHALLENGE FICTIF] Équipe CTI")}
G = nx.MultiDiGraph()
def label(o):
    t = o["type"]
    if t == "indicator": return o["name"].replace("[CHALLENGE FICTIF] ", "").split(" ")[0] + "\n" + textwrap.fill(textwrap.shorten(o["name"].split(" ", 3)[-1], 30), 15)
    if t == "attack-pattern": return [e["external_id"] for e in o["external_references"] if e["source_name"] == "mitre-attack"][0] + "\n" + textwrap.fill(o["name"], 14)
    if t == "campaign": return "CLUSTER\nNON ATTRIBUÉ\nINC-2026-0302"
    if t == "malware": return o["name"].split("(")[1].rstrip(")") + "\n" + textwrap.fill(o["name"].split(" (")[0], 14) + "\n(déclaré)"
    if t == "identity": return textwrap.fill(o["name"], 13)
    v = o.get("value") or (o.get("hashes", {}).get("SHA-256", "")[:12] + "…")
    return f"{t}\n{textwrap.shorten(str(v), 30)}"
COL = {"campaign": "#d62728", "malware": "#9467bd", "attack-pattern": "#2ca02c", "indicator": "#ff7f0e", "identity": "#1f77b4", "file": "#7f7f7f", "domain-name": "#8c564b", "ipv4-addr": "#17becf", "url": "#bcbd22"}
for i in keep: G.add_node(i, o=by[i])
for r in rels:
    if r["source_ref"] in keep and r["target_ref"] in keep:
        G.add_edge(r["source_ref"], r["target_ref"], lab=(r.get("labels") or ["?"])[0], rt=r["relationship_type"])
camp = next(i for i in keep if by[i]["type"] == "campaign")
cols = {"identity": 0, "campaign": 1, "malware": 2, "attack-pattern": 2, "indicator": 3}
pos = {}
layers = {0: [], 1: [], 2: [], 3: [], 4: []}
for i in keep:
    t = by[i]["type"]; layers[cols.get(t, 4)].append(i)
for x, nodes in layers.items():
    nodes.sort(key=lambda i: (by[i]["type"], by[i].get("name", by[i].get("value", ""))))
    for k, i in enumerate(nodes): pos[i] = (x * 3.6, -(k - (len(nodes) - 1) / 2) * 1.05)
fig, ax = plt.subplots(figsize=(21, 15))
for (u, v, k, d) in G.edges(keys=True, data=True):
    st = {"observe": "-", "hypothese": "--", "declare": ":"}.get(d["lab"], "-")
    rad = 0.12 + 0.05 * (k % 3)
    ax.annotate("", xy=pos[v], xytext=pos[u], arrowprops=dict(arrowstyle="-|>", lw=1.1, linestyle=st, color="#444", connectionstyle=f"arc3,rad={rad}", shrinkA=26, shrinkB=26, alpha=.75))
for i in G.nodes:
    o = by[i]; t = o["type"]
    ax.scatter(*pos[i], s=2300 if t != "campaign" else 5200, c=COL.get(t, "#999"), alpha=.85, edgecolors="k", linewidths=2.5 if t == "campaign" else 0.8, linestyle="--" if t == "campaign" else "-", zorder=3)
    ax.text(pos[i][0], pos[i][1], label(o), ha="center", va="center", fontsize=6.4, zorder=4, color="white" if t in ("campaign", "malware", "identity") else "black")
for x, lab in zip(range(5), ("Victime et systèmes", "Cluster", "Capacités déclarées\net techniques observées", "Indicateurs\n(historiques, expirés)", "Observables cibles")):
    ax.text(x * 3.6, 6.9, lab, ha="center", fontsize=11, fontweight="bold")
ax.set_title("[CHALLENGE FICTIF] Helios Energy : graphe CTI généré depuis Bundle-STIX.json (cluster NON ATTRIBUÉ, aucun acteur nommé)", fontsize=13)
from matplotlib.lines import Line2D
leg = [Line2D([0], [0], color="#444", lw=1.5, ls="-", label="OBSERVÉ"), Line2D([0], [0], color="#444", lw=1.5, ls="--", label="HYPOTHÈSE"), Line2D([0], [0], color="#444", lw=1.5, ls=":", label="DÉCLARÉ (fiche, non vérifié)")]
ax.legend(handles=leg, loc="lower right", fontsize=10, title="Relations")
ax.text(-1.5, -7.1, "Filtre : objets analytiques, identités et observables cibles d'un based-on ; masqués : report, grouping, notes, observed-data, network-traffic, marquages, autres observables.\n"
        "Confiance des relations : voir le champ confidence du bundle (15 faible, 50 moyenne). Le LISEZ-MOI du dossier pédagogique n'est pas une preuve : aucune attribution n'est représentée.", fontsize=9, va="top")
ax.set_xlim(-1.8, 16.2); ax.set_ylim(-8.6, 8); ax.axis("off")
plt.tight_layout(); plt.savefig(os.path.join(G0, "Graphe-CTI.png"), dpi=130); plt.savefig(os.path.join(G0, "Graphe-CTI.pdf"))
print("graphe :", G.number_of_nodes(), "nœuds,", G.number_of_edges(), "arêtes affichés sur", len(b["objects"]), "objets du bundle")
