"""One-time ingest: ATT&CK + Sigma -> Qdrant hybrid KB, synthetic telemetry -> Qdrant,
ATT&CK relationships -> Cognee knowledge graph (vectors in Qdrant).

    uv run python -m backend.build [--skip-kb] [--skip-logs] [--skip-graph]
"""
from __future__ import annotations

import argparse
import asyncio
import time

from qdrant_client import QdrantClient, models

from . import embed
from .attack import load_attack, load_sigma
from .scenario import generate_events, topology
from .settings import KB_COLLECTION, LOG_COLLECTION, QDRANT_URL, setup_cognee


def log(msg: str):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def recreate(client: QdrantClient, name: str, sparse: bool):
    if client.collection_exists(name):
        client.delete_collection(name)
    client.create_collection(
        name,
        vectors_config={"dense": models.VectorParams(size=384, distance=models.Distance.COSINE)},
        sparse_vectors_config={"bm25": models.SparseVectorParams(modifier=models.Modifier.IDF)} if sparse else None,
    )


def build_kb(client: QdrantClient):
    attack = load_attack()
    sigma = load_sigma()
    log(f"ATT&CK: {len(attack.techniques)} techniques · Sigma: {len(sigma)} windows rules")
    docs = []
    for t in attack.techniques.values():
        docs.append({
            "kind": "technique", "attack_ids": [t.attack_id], "title": f"{t.attack_id} {t.name}",
            "text": f"{t.attack_id} {t.name}. {t.description[:1500]}",
            "tactics": t.tactics, "url": t.url,
        })
    for r in sigma:
        docs.append({
            "kind": "sigma", "attack_ids": r.attack_ids, "title": r.title, "level": r.level,
            "text": f"{r.title}. {r.description} Log source: {r.logsource}. "
                    f"Detection: {' '.join(r.keywords)} Tags: {' '.join(r.attack_ids)}",
            "path": r.path, "rule_id": r.rule_id, "raw": r.raw,
        })
    recreate(client, KB_COLLECTION, sparse=True)
    client.create_payload_index(KB_COLLECTION, "kind", models.PayloadSchemaType.KEYWORD)
    client.create_payload_index(KB_COLLECTION, "attack_ids", models.PayloadSchemaType.KEYWORD)
    batch = 256
    for i in range(0, len(docs), batch):
        chunk = docs[i:i + batch]
        texts = [d["text"] for d in chunk]
        dv, sv = embed.dense(texts), embed.sparse(texts)
        client.upsert(KB_COLLECTION, [
            models.PointStruct(id=i + j, vector={"dense": dv[j], "bm25": sv[j]}, payload=chunk[j])
            for j in range(len(chunk))
        ])
        log(f"  threat_kb {min(i + batch, len(docs))}/{len(docs)}")


def build_logs(client: QdrantClient):
    events = generate_events()
    recreate(client, LOG_COLLECTION, sparse=False)
    for field, schema in [("host", models.PayloadSchemaType.KEYWORD),
                          ("event_type", models.PayloadSchemaType.KEYWORD),
                          ("allowlisted", models.PayloadSchemaType.BOOL),
                          ("t", models.PayloadSchemaType.INTEGER)]:
        client.create_payload_index(LOG_COLLECTION, field, schema)
    vecs = embed.dense([e.behaviour_text() for e in events])
    client.upsert(LOG_COLLECTION, [
        models.PointStruct(id=e.id, vector={"dense": v}, payload=e.to_payload())
        for e, v in zip(events, vecs)
    ])
    log(f"endpoint_logs: {len(events)} events across {len({e.host for e in events})} hosts")


async def build_graph():
    cognee = setup_cognee()
    from cognee.tasks.storage.add_data_points import add_data_points
    from .graph_models import Asset, Mitigation, Software, Tactic, Technique, ThreatGroup, node_id

    attack = load_attack()
    await cognee.prune.prune_data()
    await cognee.prune.prune_system(metadata=True)

    tactics = {s: Tactic(id=node_id("tactic", s), shortname=s, name=n) for s, n in attack.tactics.items()}
    techniques = {
        tid: Technique(id=node_id("technique", tid), attack_id=tid, name=t.name, summary=t.description[:600],
                       in_tactic=[tactics[x] for x in t.tactics if x in tactics])
        for tid, t in attack.techniques.items()
    }
    software = {
        sid: Software(id=node_id("software", sid), attack_id=sid, name=s.name, kind=s.kind,
                      uses=[techniques[t] for t in sorted(s.techniques) if t in techniques])
        for sid, s in attack.software.items()
    }
    groups = [
        ThreatGroup(id=node_id("group", gid), attack_id=gid, name=g.name, aliases=", ".join(g.aliases),
                    uses=[techniques[t] for t in sorted(g.techniques) if t in techniques],
                    uses_software=[software[s] for s in sorted(g.software) if s in software])
        for gid, g in attack.groups.items()
    ]
    mitigations = [
        Mitigation(id=node_id("mitigation", mid), attack_id=mid, name=m.name,
                   mitigates=[techniques[t] for t in sorted(m.techniques) if t in techniques])
        for mid, m in attack.mitigations.items()
    ]
    assets = [Asset(id=node_id("asset", n["id"]), hostname=n["id"], segment=n["segment"], role=n["kind"])
              for n in topology()["nodes"] if n["kind"] in ("workstation", "server", "dc", "edge")]

    log(f"Cognee: {len(groups)} groups, {len(software)} software, {len(mitigations)} mitigations, "
        f"{len(techniques)} techniques, {len(assets)} assets")
    for label, points in [("techniques", list(techniques.values())), ("software", list(software.values())),
                          ("groups", groups), ("mitigations", mitigations), ("assets", assets)]:
        await add_data_points(points)
        log(f"  cognee add_data_points: {label} ✓")

    from cognee.infrastructure.databases.graph import get_graph_engine
    nodes, edges = await (await get_graph_engine()).get_graph_data()
    log(f"Cognee graph: {len(nodes)} nodes, {len(edges)} edges")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-kb", action="store_true")
    ap.add_argument("--skip-logs", action="store_true")
    ap.add_argument("--skip-graph", action="store_true")
    args = ap.parse_args()
    client = QdrantClient(QDRANT_URL, timeout=120)
    if not args.skip_graph:  # first: Cognee's prune touches Qdrant collections
        asyncio.run(build_graph())
    if not args.skip_kb:
        build_kb(client)
    if not args.skip_logs:
        build_logs(client)
    log("done")


if __name__ == "__main__":
    main()
