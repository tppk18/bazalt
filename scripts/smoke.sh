#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
PROJECT="${COMPOSE_PROJECT_NAME:-bazalt-smoke}"
COMPOSE=(docker compose -p "$PROJECT" -f docker-compose.yml -f docker-compose.smoke.yml)

command -v docker >/dev/null || { echo "docker is required" >&2; exit 2; }
docker compose version >/dev/null || { echo "docker compose v2 is required" >&2; exit 2; }

cleanup() {
  status=$?
  if [[ $status -ne 0 ]]; then
    echo "--- app logs ---" >&2
    "${COMPOSE[@]}" logs --no-color app >&2 || true
  fi
  if [[ "${KEEP_SMOKE_STACK:-0}" != "1" ]]; then
    "${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap cleanup EXIT

"${COMPOSE[@]}" down -v --remove-orphans >/dev/null 2>&1 || true
rm -rf data/segments/* data/raw/*
python3 scripts/generate_fixture.py
"${COMPOSE[@]}" up --build -d

api() { curl -fsS "$@"; }

for _ in $(seq 1 120); do
  if api http://127.0.0.1:65000/api/status >/tmp/bazalt-status.json 2>/dev/null; then break; fi
  sleep 1
done
api http://127.0.0.1:65000/api/status >/dev/null

# The offline capture worker waits for a configured service before consuming the
# finite fixture. Configure the only allowed fixture port first; packets on 9999
# are intentionally present in the PCAP and must be filtered before flow/storage.
fixture_service="$(api -X POST http://127.0.0.1:65000/api/services \
  -H 'Content-Type: application/json' \
  --data '{"port":8080,"name":"fixture-http","http":true,"urldecode_http_requests":false,"merge_adjacent_packets":false,"parse_websockets":false}')"
python3 -c 'import json,sys; s=json.load(sys.stdin); assert s["port"]==8080 and s["name"]=="fixture-http"' <<<"$fixture_service"

# Live visibility regression: this fixture flow never sends FIN/RST. It must be
# queryable (with content) while still active instead of appearing only after
# idle timeout, service shutdown, or BAZALT shutdown.
LIVE_FLOW_ID=""
for _ in $(seq 1 80); do
  live_json="$(api -G --data-urlencode 'service=fixture-http' --data-urlencode 'user_agent=live-agent/1.0' http://127.0.0.1:65000/api/flows || true)"
  LIVE_FLOW_ID="$(python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("items", [{}])[0].get("flow_id", "") if d.get("items") else "")' <<<"${live_json:-{}}" 2>/dev/null || true)"
  [[ -n "$LIVE_FLOW_ID" ]] && break
  sleep 0.1
done
[[ -n "$LIVE_FLOW_ID" ]] || { echo "open live flow was not visible before close/timeout" >&2; exit 1; }
api http://127.0.0.1:65000/api/status | python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["metrics"]["active_flows"] >= 1, d["metrics"]'
live_content=""
for _ in $(seq 1 80); do
  live_content="$(api "http://127.0.0.1:65000/api/flows/$LIVE_FLOW_ID/content" || true)"
  if python3 -c 'import json,sys; d=json.load(sys.stdin); raise SystemExit(0 if any("/live" in x.get("preview","") for x in d.get("items",[])) else 1)' <<<"${live_content:-{}}" 2>/dev/null; then
    break
  fi
  sleep 0.05
done
python3 -c 'import json,sys; d=json.load(sys.stdin); assert any("/live" in x.get("preview","") for x in d["items"]), "open live flow content not visible"' <<<"$live_content"

# Service CRUD is a first-class acceptance path because services are configured
# interactively from the BAZALT navbar modal.
service_json="$(api -X POST http://127.0.0.1:65000/api/services \
  -H 'Content-Type: application/json' \
  --data '{"port":19090,"name":"smoke-service","http":true,"urldecode_http_requests":true,"merge_adjacent_packets":true,"parse_websockets":false}')"
python3 -c 'import json,sys; s=json.load(sys.stdin); assert s["port"]==19090 and s["name"]=="smoke-service" and s["http"] is True' <<<"$service_json"
api http://127.0.0.1:65000/api/services | python3 -c 'import json,sys; a=json.load(sys.stdin); assert any(s["port"]==19090 for s in a), "created service missing"'
updated_service="$(api -X PUT http://127.0.0.1:65000/api/services/19090 -H 'Content-Type: application/json' --data '{"name":"smoke-service-edited","http":true,"urldecode_http_requests":false,"merge_adjacent_packets":false,"parse_websockets":true}')"
python3 -c 'import json,sys; s=json.load(sys.stdin); assert s["name"]=="smoke-service-edited" and s["parse_websockets"] is True' <<<"$updated_service"
api -X DELETE http://127.0.0.1:65000/api/services/19090 >/dev/null
api http://127.0.0.1:65000/api/services | python3 -c 'import json,sys; a=json.load(sys.stdin); assert not any(s["port"]==19090 for s in a), "deleted service still present"'

# Wait for the fixture flow and verify User-Agent indexing/filtering.
FLOW_ID=""
for _ in $(seq 1 80); do
  json="$(api -G --data-urlencode 'service=fixture-http' --data-urlencode 'user_agent=python-requests' http://127.0.0.1:65000/api/flows || true)"
  FLOW_ID="$(python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("items", [{}])[0].get("flow_id", "") if d.get("items") else "")' <<<"${json:-{}}" 2>/dev/null || true)"
  [[ -n "$FLOW_ID" ]] && break
  sleep 0.25
done
[[ -n "$FLOW_ID" ]] || { echo "fixture flow was not indexed by User-Agent" >&2; exit 1; }

# Port allow-list regression: the same PCAP contains an HTTP payload on 9999.
# It must not create a second flow and its curl User-Agent must not be indexed.
flow_count="$(api -G --data-urlencode 'service=fixture-http' http://127.0.0.1:65000/api/flows | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["items"]))')"
[[ "$flow_count" -eq 2 ]] || { echo "configured-port capture expected exactly two 8080 fixture flows (one closed, one live), got $flow_count" >&2; exit 1; }
noise_count="$(api -G --data-urlencode 'user_agent=curl/9.0' http://127.0.0.1:65000/api/flows | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["items"]))')"
[[ "$noise_count" -eq 0 ]] || { echo "unconfigured port 9999 leaked into flow storage" >&2; exit 1; }

equals_count="$(api -G --data-urlencode 'user_agent_equals=python-requests/2.32' http://127.0.0.1:65000/api/flows | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["items"]))')"
[[ "$equals_count" -ge 1 ]] || { echo "User-Agent equals filter failed" >&2; exit 1; }

not_contains_count="$(api -G --data-urlencode 'user_agent_not_contains=curl' http://127.0.0.1:65000/api/flows | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["items"]))')"
[[ "$not_contains_count" -ge 1 ]] || { echo "User-Agent not-contains filter failed" >&2; exit 1; }

excluded_count="$(api -G --data-urlencode 'user_agent_not_contains=python-requests' http://127.0.0.1:65000/api/flows | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["items"]))')"
[[ "$excluded_count" -eq 0 ]] || { echo "User-Agent not-contains exclusion failed" >&2; exit 1; }

regex_count="$(api -G --data-urlencode 'user_agent_regex=^python-requests/.*' http://127.0.0.1:65000/api/flows | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["items"]))')"
[[ "$regex_count" -ge 1 ]] || { echo "User-Agent regex filter failed" >&2; exit 1; }

# Create the pattern only after old traffic is indexed. The expected match must
# therefore come from automatic historical replay, not live traffic.
pattern_json="$(api -X POST http://127.0.0.1:65000/api/patterns \
  -H 'Content-Type: application/json' \
  --data '{"name":"fixture flag","expression":"FLAG{fixture}","kind":"text","action":"find","service":null,"view":null}')"
PATTERN_ID="$(python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])' <<<"$pattern_json")"

job_status=""
for _ in $(seq 1 120); do
  jobs="$(api http://127.0.0.1:65000/api/replay/jobs || true)"
  job_status="$(python3 -c 'import json,sys; pid=sys.argv[1]; d=json.load(sys.stdin); print(next((j.get("status","") for j in d.get("items",[]) if pid in j.get("pattern_ids",[])), ""))' "$PATTERN_ID" <<<"${jobs:-{}}" 2>/dev/null || true)"
  [[ "$job_status" == "completed" ]] && break
  [[ "$job_status" == "failed" ]] && { echo "replay job failed" >&2; exit 1; }
  sleep 0.25
done
[[ "$job_status" == "completed" ]] || { echo "replay did not complete" >&2; exit 1; }

# Wait for ClickHouse metadata batch visibility.
matched=""
for _ in $(seq 1 80); do
  result="$(api -G --data-urlencode "pattern_id=$PATTERN_ID" http://127.0.0.1:65000/api/flows || true)"
  matched="$(python3 -c 'import json,sys; fid=sys.argv[1]; d=json.load(sys.stdin); print("yes" if any(x.get("flow_id")==fid for x in d.get("items",[])) else "")' "$FLOW_ID" <<<"${result:-{}}" 2>/dev/null || true)"
  [[ "$matched" == "yes" ]] && break
  sleep 0.25
done
[[ "$matched" == "yes" ]] || { echo "historical pattern match did not reach flow query" >&2; exit 1; }

detail="$(api "http://127.0.0.1:65000/api/flows/$FLOW_ID")"
python3 -c 'import json,sys; pid=sys.argv[1]; d=json.load(sys.stdin); assert any(h.get("user_agent")=="python-requests/2.32" for h in d["http"]), "User-Agent metadata missing"; assert any(m.get("pattern_id")==pid and m.get("historical") is True for m in d["matches"]), "historical match flag missing"' "$PATTERN_ID" <<<"$detail"

content="$(api "http://127.0.0.1:65000/api/flows/$FLOW_ID/content")"
python3 -c 'import json,sys; pid=sys.argv[1]; d=json.load(sys.stdin); items=d["items"]; flag=[x for x in items if "FLAG{fixture}" in x.get("preview","")]; assert flag, "payload content not retrievable"; assert all(x.get("view") != "tcp_raw" for x in flag), "HTTP payload still duplicated as tcp_raw"; assert any(any(m.get("pattern_id")==pid for m in x.get("matches",[])) for x in flag), "raw canonical pattern hit was not projected onto visible HTTP content"' "$PATTERN_ID" <<<"$content"

echo "SMOKE PASS: BAZALT live-open-flow + service-port allow-list + service CRUD + HTTP/raw dedupe + projected pattern highlight + flow=$FLOW_ID live=$LIVE_FLOW_ID pattern=$PATTERN_ID UA+historical replay verified"
