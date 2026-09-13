# SENTINEL: SOC Copilot on Qdrant × Cognee

Demo for Qdrant & Cognee *Bring Your Own Demo Night* (Berlin). 5 minutes, fully local, no API keys.

## Launch

```bash
./run.sh            # starts Qdrant + ingests on first run + serves http://localhost:8916
./run.sh --build    # force re-ingest
```

Presenting: open http://localhost:8916 in the browser, press `F` for fullscreen, press `SPACE` to advance each step.

| Key | Action |
|---|---|
| `SPACE` / `→` | Next step |
| `B` | Back to the network topology (keeps compromised state and attack paths) |
| `G` | Switch to the Cognee knowledge graph |
| `ESC` | Close the report |
| `R` | Reset |

## Architecture

```
MITRE ATT&CK STIX ──┬─> Qdrant  threat_kb      (697 techniques + 2,410 Windows Sigma rules, dense bge-small + sparse BM25)
SigmaHQ rules ──────┘
Synthetic telemetry ──> Qdrant  endpoint_logs  (~1.3k process events, 27 hosts, 1 hidden intrusion)
ATT&CK relationships ─> Cognee graph (Ladybug) + vector index (Qdrant, community adapter)
                        ThreatGroup ─uses→ Technique ─in_tactic→ Tactic; Mitigation ─mitigates→ Technique ...
```

| Step | What happens | Technique |
|---|---|---|
| ① Decode | base64 / UTF-16LE decoding, IOC extraction | local |
| ② Map to ATT&CK | Dense vs BM25 vs hybrid, shown side by side | Qdrant `query_points` + `prefetch` + RRF fusion |
| ③ Hunt | Find hosts that "behave the same" but raised no alert | Qdrant `query_points_groups(group_by=host)` → Recommend API (allowlisted negatives) |
| ④ Graph reasoning | Attribute the likely APT group, predict the next steps, recommend mitigations, write the incident to memory | Cognee graph (built with `add_data_points`) traversal + incident written back as memory |
| ⑤ Report | Streamed incident report + generated Sigma rule | Grounded template (switches to a local LLM automatically if Ollama is running) |

Optional: install Ollama and run `ollama pull qwen2.5:7b`. The executive summary will then be written by the local model (`LOCAL_LLM_MODEL` sets the model).

## 5-minute talk track

**0:00 – Hook (boot screen)**
"A SOC analyst gets thousands of alerts a day. Attackers only need one that gets ignored. This is Sentinel, a security copilot that runs fully local on Qdrant and Cognee."

**0:30 – SPACE → network view, SPACE → alert fires**
"This is a synthetic company with 27 hosts. A critical alert just fired on a finance workstation: Word spawned an encoded PowerShell."

**1:00 – SPACE → ① Decode**
"First we strip the obfuscation. We never embed base64 garbage; we embed the behaviour. It's a download cradle to cdn-update.cloud."

**1:30 – SPACE → ② Retrieval**
"Now we map it to MITRE ATT&CK and 2,400 Sigma rules in Qdrant. Left: dense, middle: BM25, right: hybrid with RRF fusion."
SPACE to switch to the second alert: "For something like `comsvcs MiniDump`, exact tokens matter. Dense alone misses them, sparse alone lacks context. Hybrid gets both."

**2:15 – SPACE → ③ Hunt (the climax)**
"The real question: is this the only host? Signatures say yes. We ask Qdrant for the most similar behaviour, grouped by host… Three hosts that never raised an alert come up on top: different payloads, same behaviour. But right below them, rows 4 to 6 are Intune scripts: also encoded, also hidden, but benign, and the scores are almost identical.
So we feed our allowlist in as negative examples through the Recommend API… the lookalikes drop out, and **the three real footholds** stand clearly apart."

**3:15 – SPACE → ④ Cognee**
"Similarity tells us *what*. The graph tells us *who* and *what's next*. Cognee holds the entire ATT&CK knowledge graph. We traverse from the observed techniques to the threat groups that use them, then to the techniques those groups use *next*. And the incident is written back to Cognee as memory, so the next investigation starts with context."

**4:15 – SPACE → ⑤ Report**
"Finally, a grounded incident report plus a Sigma rule that would have caught all four hosts. No cloud, no API key, all running on this laptop."

**4:45 – Close**
"Qdrant for finding similar things fast, Cognee for knowing how things connect. Repo on GitHub, come talk to me!"

## Demo-day checklist
- [ ] Run `./run.sh` in advance and click through once so the models and caches are warm
- [ ] Connect the projector, set the browser zoom to 100%, press F for fullscreen
- [ ] Turn off Wi-Fi and rehearse once to confirm the demo works fully offline
