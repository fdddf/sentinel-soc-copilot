"""The copilot pipeline: decode -> retrieve (Qdrant hybrid) -> hunt (Qdrant recommend) ->
reason over the Cognee knowledge graph -> report."""
from __future__ import annotations

import base64
import math
import re
import statistics
import time
from collections import Counter, defaultdict

from qdrant_client import QdrantClient, models

from . import embed
from .scenario import topology
from .settings import KB_COLLECTION, LOG_COLLECTION, QDRANT_URL

client = QdrantClient(QDRANT_URL, timeout=30)

ENC_RE = re.compile(r"\s-(?:e|en|enc|encodedcommand)\s+([A-Za-z0-9+/=]{16,})", re.I)
URL_RE = re.compile(r"https?://[^\s'\")]+", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
SUSPICIOUS = ["IEX", "Invoke-Expression", "DownloadString", "Net.WebClient", "iwr", "-w hidden",
              "-nop", "-enc", "comsvcs", "MiniDump", "WindowStyle Hidden", "-ep bypass"]


def _ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 1)


def fmt_t(t: int) -> str:
    return f"{t // 3600:02d}:{t % 3600 // 60:02d}:{t % 60:02d}"


# ---------------------------------------------------------------- events

def get_event(event_id: int) -> dict:
    pts = client.retrieve(LOG_COLLECTION, [event_id], with_payload=True)
    if not pts:
        raise KeyError(event_id)
    return pts[0].payload


def list_alerts() -> list[dict]:
    pts, _ = client.scroll(
        LOG_COLLECTION, limit=100, with_payload=True,
        scroll_filter=models.Filter(must_not=[models.IsNullCondition(is_null=models.PayloadField(key="alert"))]),
    )
    alerts = [p.payload for p in pts if p.payload.get("alert")]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(alerts, key=lambda a: (-a["t"], order.get(a["severity"], 9)))


def telemetry_sample(limit: int = 80) -> list[dict]:
    pts, _ = client.scroll(LOG_COLLECTION, limit=limit, with_payload=["t", "host", "process", "parent", "event_type"])
    return [p.payload for p in pts]


# ---------------------------------------------------------------- 1. decode

def decode(event: dict) -> dict:
    cmd = event["cmdline"]
    decoded = None
    m = ENC_RE.search(" " + cmd)
    if m:
        try:
            decoded = base64.b64decode(m.group(1)).decode("utf-16-le")
        except Exception:
            decoded = None
    text = f"{cmd} {decoded or ''}"
    return {
        "raw": cmd,
        "decoded": decoded,
        "iocs": sorted(set(URL_RE.findall(text)) | set(IP_RE.findall(text))),
        "indicators": [s for s in SUSPICIOUS if s.lower() in text.lower()],
        "behaviour": event["behaviour"],
    }


# ---------------------------------------------------------------- 2. retrieve

def _hit(p) -> dict:
    pl = p.payload
    return {"title": pl["title"], "kind": pl["kind"], "attack_ids": pl.get("attack_ids", []),
            "level": pl.get("level"), "score": round(p.score, 4), "path": pl.get("path")}


# Weighted RRF: BM25 counts 3x. Security text is full of exact tokens (DLL names, cmdlets) that
# a small embedding model blurs; with equal weights dense noise pushed real hits out of the top 5.
RRF_WEIGHTS = [1.0, 3.0]  # [dense, bm25], same order as the prefetch list


def retrieve(query_text: str, limit: int = 5) -> dict:
    dv = embed.dense([query_text])[0]
    sv = embed.sparse_query(query_text)
    out = {}

    t = time.perf_counter()
    r = client.query_points(KB_COLLECTION, query=dv, using="dense", limit=limit, with_payload=True)
    out["dense"] = {"ms": _ms(t), "hits": [_hit(p) for p in r.points]}

    t = time.perf_counter()
    r = client.query_points(KB_COLLECTION, query=sv, using="bm25", limit=limit, with_payload=True)
    out["sparse"] = {"ms": _ms(t), "hits": [_hit(p) for p in r.points]}

    t = time.perf_counter()
    r = client.query_points(
        KB_COLLECTION,
        prefetch=[models.Prefetch(query=dv, using="dense", limit=40),
                  models.Prefetch(query=sv, using="bm25", limit=40)],
        query=models.RrfQuery(rrf=models.Rrf(weights=RRF_WEIGHTS)),
        limit=limit, with_payload=True,
    )
    out["hybrid"] = {"ms": _ms(t), "hits": [_hit(p) for p in r.points]}

    # Pull the best matching Sigma rule (full YAML) for the report
    t = time.perf_counter()
    r = client.query_points(
        KB_COLLECTION,
        prefetch=[models.Prefetch(query=dv, using="dense", limit=40),
                  models.Prefetch(query=sv, using="bm25", limit=40)],
        query=models.RrfQuery(rrf=models.Rrf(weights=RRF_WEIGHTS)),
        query_filter=models.Filter(must=[models.FieldCondition(key="kind", match=models.MatchValue(value="sigma"))]),
        limit=1, with_payload=True,
    )
    out["sigma"] = {"ms": _ms(t), "rule": r.points[0].payload if r.points else None}
    return out


def techniques_from(retrievals: list[dict], depth: int = 5, min_weight: float = 0.6,
                    min_support: int = 1) -> list[dict]:
    """Vote technique IDs from hybrid hits (RRF rank-weighted); support = #queries that hit it."""
    votes: Counter = Counter()
    support: Counter = Counter()
    for ret in retrievals:
        seen = set()
        for rank, h in enumerate(ret["hybrid"]["hits"][:depth]):
            for tid in h["attack_ids"]:
                votes[tid] += 1 / (rank + 1)
                seen.add(tid)
        support.update(seen)
    kb = {}
    if votes:
        pts, _ = client.scroll(KB_COLLECTION, limit=len(votes) * 2, with_payload=["attack_ids", "title", "tactics"],
                               scroll_filter=models.Filter(must=[
                                   models.FieldCondition(key="kind", match=models.MatchValue(value="technique")),
                                   models.FieldCondition(key="attack_ids", match=models.MatchAny(any=list(votes)))]))
        kb = {p.payload["attack_ids"][0]: p.payload for p in pts}
    return [{"id": tid, "name": kb.get(tid, {}).get("title", tid).split(" ", 1)[-1],
             "tactics": kb.get(tid, {}).get("tactics", []), "weight": round(w, 2)}
            for tid, w in votes.most_common(8) if tid in kb and w >= min_weight and support[tid] >= min_support]


# ---------------------------------------------------------------- 3. hunt

HOST_ONLY_PROC = models.FieldCondition(key="event_type", match=models.MatchValue(value="process_creation"))


def _negatives() -> list[int]:
    pts, _ = client.scroll(LOG_COLLECTION, limit=500, with_payload=["behaviour"],
                           scroll_filter=models.Filter(must=[models.FieldCondition(
                               key="allowlisted", match=models.MatchValue(value=True))]))
    seen: dict[str, int] = {}
    for p in pts:
        seen.setdefault(p.payload["behaviour"], p.id)
    return list(seen.values())


def _grouped(query, exclude_host: str) -> tuple[list[dict], float]:
    t = time.perf_counter()
    res = client.query_points_groups(
        LOG_COLLECTION, query=query, using="dense", group_by="host", limit=40, group_size=1,
        query_filter=models.Filter(must=[HOST_ONLY_PROC],
                                   must_not=[models.FieldCondition(key="host", match=models.MatchValue(value=exclude_host))]),
        with_payload=True,
    )
    ms = _ms(t)
    rows = [{"host": g.id, "score": round(g.hits[0].score, 4), "event": g.hits[0].payload} for g in res.groups]
    scores = [r["score"] for r in rows]
    mu, sd = statistics.mean(scores), statistics.pstdev(scores) or 1.0
    for r in rows:
        r["z"] = round((r["score"] - mu) / sd, 2)
        ev = r.pop("event")
        r["event"] = {k: ev[k] for k in ("id", "t", "user", "parent", "process", "cmdline", "decoded",
                                           "behaviour", "allowlisted")}
        r["event"]["time"] = fmt_t(ev["t"])
    return rows, ms


def hunt(event_id: int, z_threshold: float = 1.0) -> dict:
    event = get_event(event_id)
    host = event["host"]
    nearest, ms1 = _grouped(event_id, host)
    negs = _negatives()
    rec_query = models.RecommendQuery(recommend=models.RecommendInput(
        positive=[event_id], negative=negs, strategy=models.RecommendStrategy.AVERAGE_VECTOR))
    recommended, ms2 = _grouped(rec_query, host)
    compromised = [r["host"] for r in recommended if r["z"] >= z_threshold and not r["event"]["allowlisted"]]

    # Lateral-movement edges: derived from the patient-zero host's own telemetry
    pts, _ = client.scroll(LOG_COLLECTION, limit=200, with_payload=True, scroll_filter=models.Filter(must=[
        models.FieldCondition(key="host", match=models.MatchValue(value=host)),
        models.FieldCondition(key="allowlisted", match=models.MatchValue(value=False))]))
    lateral = []
    for p in sorted(pts, key=lambda p: p.payload["t"]):
        m = re.search(r"/node:([\w-]+)", p.payload["cmdline"])
        if m and m.group(1) in compromised:
            lateral.append({"source": host, "target": m.group(1), "time": fmt_t(p.payload["t"]),
                            "via": p.payload["process"], "behaviour": p.payload["behaviour"]})
    # Hosts that are one hop from a compromised host and hold high-value roles = at risk
    topo = topology()
    kinds = {n["id"]: n["kind"] for n in topo["nodes"]}
    at_risk = [n for n, k in kinds.items() if k == "dc"]
    return {
        "source_host": host,
        "negatives": len(negs),
        "nearest": {"ms": ms1, "rows": nearest[:8]},
        "recommend": {"ms": ms2, "rows": recommended[:8]},
        "z_threshold": z_threshold,
        "compromised": compromised,
        "lateral": lateral,
        "at_risk": at_risk,
    }


# ---------------------------------------------------------------- 4. Cognee graph reasoning

class ThreatGraph:
    """In-memory view of the Cognee graph for fast traversal during the demo."""

    def __init__(self):
        self.nodes: dict[str, dict] = {}
        self.out: dict[str, list[tuple[str, str]]] = defaultdict(list)
        self.inc: dict[str, list[tuple[str, str]]] = defaultdict(list)
        self.by_attack: dict[str, str] = {}
        self.by_host: dict[str, str] = {}

    async def load(self):
        from cognee.infrastructure.databases.graph import get_graph_engine
        nodes, edges = await (await get_graph_engine()).get_graph_data()
        for nid, props in nodes:
            self.nodes[str(nid)] = props
            if props.get("attack_id"):
                self.by_attack[props["attack_id"]] = str(nid)
            if props.get("hostname"):
                self.by_host[props["hostname"]] = str(nid)
        for s, d, rel, _ in edges:
            self.out[str(s)].append((rel, str(d)))
            self.inc[str(d)].append((rel, str(s)))
        return self

    def stats(self) -> dict:
        return {"nodes": len(self.nodes), "edges": sum(len(v) for v in self.out.values()),
                "types": Counter(n.get("type") for n in self.nodes.values())}

    def techniques_of(self, nid: str) -> set[str]:
        return {self.nodes[d]["attack_id"] for rel, d in self.out[nid] if rel == "uses"
                and self.nodes.get(d, {}).get("type") == "Technique"}

    def tactic_names(self, tech_nid: str) -> list[str]:
        return [self.nodes[d]["name"] for rel, d in self.out[tech_nid] if rel == "in_tactic"]


def reason(graph: ThreatGraph, observed_ids: list[str], compromised: list[str]) -> dict:
    t0 = time.perf_counter()
    observed = [tid for tid in observed_ids if tid in graph.by_attack]
    obs_set = set(observed)

    # Rank groups: overlap with observed TTPs, lightly normalised by repertoire size
    ranked = []
    for nid, props in graph.nodes.items():
        if props.get("type") != "ThreatGroup":
            continue
        uses = graph.techniques_of(nid)
        overlap = uses & obs_set
        if overlap:
            score = len(overlap) / math.sqrt(len(uses))
            ranked.append((score, len(overlap), nid, uses, overlap))
    ranked.sort(key=lambda r: (-r[1], -r[0]))
    top = ranked[:3]

    later_tactics = {"Credential Access", "Discovery", "Lateral Movement", "Collection",
                     "Command and Control", "Exfiltration", "Impact", "Privilege Escalation"}
    votes: Counter = Counter()
    for _, _, nid, uses, _ in top:
        for tid in uses - obs_set:
            tnid = graph.by_attack.get(tid)
            if tnid and later_tactics & set(graph.tactic_names(tnid)):
                votes[tid] += 1
    predicted = [tid for tid, c in votes.most_common(40) if c >= 2][:5]

    mit_scores: Counter = Counter()
    for tid in observed + predicted:
        for rel, src in graph.inc[graph.by_attack[tid]]:
            if rel == "mitigates":
                mit_scores[src] += 1
    mitigations = mit_scores.most_common(4)

    # ---- subgraph for the 3D view
    nodes, links, seen = [], [], set()

    def add_node(nid, kind, label, **extra):
        if nid not in seen:
            seen.add(nid)
            nodes.append({"id": nid, "kind": kind, "label": label, **extra})

    add_node("incident", "incident", "INCIDENT")
    for h in compromised:
        hid = graph.by_host.get(h, f"host:{h}")
        add_node(hid, "asset", h)
        links.append({"source": "incident", "target": hid, "rel": "affected"})
    for tid in observed:
        tn = graph.by_attack[tid]
        add_node(tn, "observed", f"{tid} {graph.nodes[tn]['name']}", attack_id=tid)
        links.append({"source": "incident", "target": tn, "rel": "observed"})
    groups_out = []
    for score, n_overlap, gid, uses, overlap in top:
        g = graph.nodes[gid]
        add_node(gid, "group", g["name"], attack_id=g["attack_id"])
        groups_out.append({"id": g["attack_id"], "name": g["name"], "aliases": g.get("aliases", ""),
                           "overlap": sorted(overlap), "repertoire": len(uses), "score": round(score, 3)})
        for tid in overlap:
            links.append({"source": gid, "target": graph.by_attack[tid], "rel": "uses"})
        for tid in predicted:
            if tid in uses:
                links.append({"source": gid, "target": graph.by_attack[tid], "rel": "predicts"})
        # context: a slice of the group's wider repertoire, for visual density
        for tid in sorted(uses - obs_set - set(predicted))[:14]:
            tn = graph.by_attack[tid]
            add_node(tn, "context", f"{tid} {graph.nodes[tn]['name']}", attack_id=tid)
            links.append({"source": gid, "target": tn, "rel": "uses"})
        sw_nodes = [d for rel, d in graph.out[gid] if rel == "uses_software"][:4]
        for sw in sw_nodes:
            add_node(sw, "software", graph.nodes[sw]["name"])
            links.append({"source": gid, "target": sw, "rel": "uses_software"})
    predicted_out = []
    for tid in predicted:
        tn = graph.by_attack[tid]
        add_node(tn, "predicted", f"{tid} {graph.nodes[tn]['name']}", attack_id=tid)
        predicted_out.append({"id": tid, "name": graph.nodes[tn]["name"], "tactics": graph.tactic_names(tn),
                              "votes": votes[tid]})
    mit_out = []
    for mid, cnt in mitigations:
        m = graph.nodes[mid]
        add_node(mid, "mitigation", f"{m['attack_id']} {m['name']}", attack_id=m["attack_id"])
        mit_out.append({"id": m["attack_id"], "name": m["name"], "covers": cnt})
        for tid in observed + predicted:
            if ("mitigates", mid) in graph.inc[graph.by_attack[tid]]:
                links.append({"source": mid, "target": graph.by_attack[tid], "rel": "mitigates"})

    return {
        "ms": _ms(t0),
        "stats": {k: v for k, v in graph.stats().items() if k != "types"},
        "observed": observed,
        "groups": groups_out, "predicted": predicted_out, "mitigations": mit_out,
        "graph": {"nodes": nodes, "links": links},
    }


async def remember_incident(graph: ThreatGraph, name: str, summary: str, observed: list[str],
                            compromised: list[str], groups: list[str]) -> float:
    """Persist the incident as new memory in Cognee (graph + Qdrant vectors)."""
    from cognee.tasks.storage.add_data_points import add_data_points
    from .graph_models import Asset, Incident, Technique, ThreatGroup, node_id

    t = time.perf_counter()

    def stub(cls, kind, key, nid, **kw):
        props = graph.nodes[nid]
        return cls(id=node_id(kind, key), **{k: props.get(k, "") for k in kw["fields"]})

    inc = Incident(
        id=node_id("incident", name), name=name, summary=summary,
        observed=[stub(Technique, "technique", tid, graph.by_attack[tid], fields=["attack_id", "name", "summary"])
                  for tid in observed if tid in graph.by_attack],
        affected=[stub(Asset, "asset", h, graph.by_host[h], fields=["hostname", "segment", "role"])
                  for h in compromised if h in graph.by_host],
        attributed_to=[stub(ThreatGroup, "group", gid, graph.by_attack[gid], fields=["attack_id", "name", "aliases"])
                       for gid in groups if gid in graph.by_attack],
    )
    await add_data_points([inc])
    return _ms(t)
