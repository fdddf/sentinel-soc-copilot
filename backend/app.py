"""FastAPI server for the SOC Copilot demo.

    uv run uvicorn backend.app:app --port 8916
"""
from __future__ import annotations

import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from . import copilot, embed, report
from .scenario import topology
from .settings import KB_COLLECTION, LOG_COLLECTION, setup_cognee

DIST = Path(__file__).resolve().parent.parent / "frontend" / "dist"
STATE: dict = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_cognee()
    embed.dense(["warm up"])
    embed.sparse_query("warm up")
    STATE["graph"] = await copilot.ThreatGraph().load()
    yield


app = FastAPI(title="SOC Copilot", lifespan=lifespan)


@app.get("/api/status")
def status():
    info = {c: copilot.client.count(c).count for c in (KB_COLLECTION, LOG_COLLECTION)}
    g = STATE["graph"].stats()
    return {"qdrant": info, "cognee": {"nodes": g["nodes"], "edges": g["edges"], "types": g["types"]},
            "llm": "local LLM" if report.llm_available() else "grounded template"}


@app.get("/api/topology")
def get_topology():
    return topology()


@app.get("/api/alerts")
def alerts():
    out = copilot.list_alerts()
    for a in out:
        a["time"] = copilot.fmt_t(a["t"])
    return out


@app.get("/api/telemetry")
def telemetry():
    return copilot.telemetry_sample()


@app.post("/api/analyze/{event_id}")
def analyze(event_id: int):
    try:
        alert = copilot.get_event(event_id)
    except KeyError:
        raise HTTPException(404, "event not found")
    related = [a for a in copilot.list_alerts() if a["host"] == alert["host"]]
    related.sort(key=lambda a: a["id"] != event_id)
    steps = []
    for ev in related:
        d = copilot.decode(ev)
        steps.append({"event_id": ev["id"], "alert": ev["alert"], "severity": ev["severity"],
                      "time": copilot.fmt_t(ev["t"]), "decode": d, "retrieval": copilot.retrieve(d["behaviour"])})
    techniques = copilot.techniques_from([s["retrieval"] for s in steps])
    STATE.update(alert=alert, steps=steps, techniques=techniques,
                 decodes=[s["decode"] for s in steps], incident_name=f"INC-2026-0916-{event_id:04d}")
    return {"host": alert["host"], "steps": steps, "techniques": techniques}


@app.post("/api/hunt/{event_id}")
def hunt(event_id: int):
    STATE["hunt"] = copilot.hunt(event_id)
    return STATE["hunt"]


@app.post("/api/graph")
async def graph():
    if "hunt" not in STATE:
        raise HTTPException(409, "run analyze + hunt first")
    alert = STATE["alert"]
    hunt = STATE["hunt"]
    # Evidence found during the hunt (lateral movement + silent footholds) adds TTPs the alerts missed
    evidence = [lat["behaviour"] for lat in hunt["lateral"]] + [
        r["event"]["behaviour"] for r in hunt["recommend"]["rows"] if r["host"] in hunt["compromised"]]
    known = {t["id"] for t in STATE["techniques"]}
    added = [t for t in await run_in_threadpool(
        lambda: copilot.techniques_from([copilot.retrieve(e) for e in evidence], depth=3, min_weight=0.5, min_support=3))
        if t["id"] not in known]
    STATE["techniques"] = STATE["techniques"] + added
    text = " ".join(d["behaviour"] for d in STATE["decodes"])
    result = copilot.reason(STATE["graph"], [t["id"] for t in STATE["techniques"]], hunt["compromised"])
    result["techniques_added"] = added
    result["memory_ms"] = await copilot.remember_incident(
        STATE["graph"], STATE["incident_name"], f"Intrusion starting on {alert['host']}: {text[:400]}",
        [t["id"] for t in STATE["techniques"]], [alert["host"], *STATE["hunt"]["compromised"]],
        [g["id"] for g in result["groups"]])
    STATE["graph_result"] = result
    return result


@app.get("/api/report")
def get_report():
    if "graph_result" not in STATE:
        raise HTTPException(409, "run the pipeline first")
    state = {**STATE, "graph": STATE["graph_result"]}

    def gen():
        for chunk in report.stream_report(state):
            # re-chunk into words so the UI can "type" it
            for i, word in enumerate(chunk.split(" ")):
                yield word if i == 0 else " " + word
                time.sleep(0.012)

    return StreamingResponse(gen(), media_type="text/plain; charset=utf-8")


if DIST.exists():
    app.mount("/assets", StaticFiles(directory=DIST / "assets"), name="assets")

    @app.get("/")
    def index():
        return FileResponse(DIST / "index.html")
