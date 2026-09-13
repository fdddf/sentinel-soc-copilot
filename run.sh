#!/usr/bin/env bash
# Start everything for the demo: Qdrant (native binary) + FastAPI app on http://localhost:8916
set -euo pipefail
cd "$(dirname "$0")"

mkdir -p storage bin data
[[ -x bin/qdrant ]] || { echo "▶ downloading Qdrant"; curl -sL https://github.com/qdrant/qdrant/releases/download/v1.19.1/qdrant-aarch64-apple-darwin.tar.gz | tar xz -C bin; }
[[ -f data/enterprise-attack.json ]] || { echo "▶ downloading MITRE ATT&CK"; curl -sL -o data/enterprise-attack.json https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json; }
[[ -f data/sigma.zip ]] || { echo "▶ downloading SigmaHQ rules"; curl -sL -o data/sigma.zip https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip; }
[[ -f .env ]] || cp .env.example .env
if ! curl -sf localhost:6333/healthz >/dev/null; then
  echo "▶ starting Qdrant"
  (./bin/qdrant --disable-telemetry >storage/qdrant.log 2>&1 &)  # data in ./storage
  until curl -sf localhost:6333/healthz >/dev/null; do sleep 0.5; done
fi

if [[ "${1:-}" == "--build" ]] || ! curl -sf localhost:6333/collections/endpoint_logs >/dev/null; then
  echo "▶ ingesting ATT&CK, Sigma, telemetry and Cognee graph (first run takes a while)"
  uv run python -m backend.build
fi

if [[ ! -f frontend/dist/assets/main.js ]]; then
  (cd frontend && npm install && node build.mjs)
fi

echo "▶ SOC Copilot on http://localhost:8916"
exec uv run uvicorn backend.app:app --port 8916
