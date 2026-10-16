# TrustShield (MVP)
Decision support for spotting impersonation and social-engineering messages. It does **not** verify identities and a Low result never guarantees safety.

## Run
    python3 -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt
    uvicorn app.main:app --reload --port 8000    # open http://localhost:8000
    pytest -q                                    # tests

## Architecture
`app/engine.py` rule engine (rules + thresholds in `RULES`/`CONFIG`; asks × pressure combinations, not keyword counts) · `app/main.py` FastAPI + Pydantic (5000-char limit, no message storage/logging) · `static/index.html` UI (all user text rendered with `textContent`, no XSS).

## API
`POST /api/analyze` {text, claimed_sender?} · `GET /api/health` · `GET /api/examples` · `POST /api/reports/export`

## Config
`TRUSTSHIELD_CORS_ORIGINS` (comma list; set to your production origin). No API keys needed.

## Limitations
Rule-based and English-centric; no URL/sender reputation lookups; Dashboard and Learn pages, React/Vite/Tailwind frontend and frontend tests are not implemented.

## v2 additions
`POST /api/identity/assess`, `GET /api/simulation/scenarios`, `POST /api/simulation/run` (steps through a scenario; each step runs the real engine on the cumulative conversation). `/api/analyze` accepts optional `profile` + `observed_channel`. Verification is **simulated** (demo token `DEMO-VERIFIED`) and labelled as such. Warning/educational phrasing ("never share your OTP") is not treated as a request, which a scammer could imitate.

## Testing and evaluation
- `pytest -q` runs API, trust and detection tests (`tests/test_detection.py` runs without FastAPI).
- `python3 eval/run_eval.py` reports precision/recall/FPR on a 28-message labelled set (14 malicious, 14 benign); latest output in `eval/RESULTS.txt`.
- **Caveat:** the set was written by the rule author, so it is optimistic and small. It is not evidence of real-world performance. Known misses: paraphrases ("furnish the six digits"), remote-access/crypto asks without pressure signals. Known false positive: a legitimate IT message that mentions a password plus urgency.

## Demo Mode (≈2 min)
Open **Demo Mode**, press Next through 7 steps (OTP message → identity gap → combined signals → verification step → interrupt → benign message stays Low → incident report). **Reset Demo** clears it.

## Sentinel (v3)
Open `http://localhost:8000/sentinel`. Trust graph (SVG; pan/zoom/filter/inspect), event stream (polled `GET /api/events`, no SSE), investigation panel separating known facts / inferred risks / missing evidence. Scenarios A, B and C (benign) are **deterministic demo data** and labelled so; the graph is built server-side from the real detector output.

New API: `POST /api/url/assess`, `POST /api/investigations`, `GET /api/investigations/{id}`, `GET /api/events`.

### Browser extension (Manifest V3, `extension/`)
Load unpacked in Chrome/Edge (`chrome://extensions` → Developer mode → Load unpacked). It uses `webNavigation.onBeforeNavigate`, sends the URL (query stripped) to your local backend, and redirects High/Critical results to a warning page with *Return to safety* and a 30-minute per-host exception. Privacy/settings are in the options page; the backend stores host and verdict only.
Harmless test destinations (the reserved `.test` TLD never resolves): `http://g00gle-login.test/verify`, `https://paytm.com.evil.test/`. A normal site such as `https://example.org` passes.

### Limitations
URL checks are heuristics with a small configured brand list and **no threat-intelligence feed**; the extension fails open if the backend is unreachable; the check is asynchronous so a fast page may start loading before the redirect; no OS-level or other-app message inspection; the graph is 2D SVG, not Three.js; no particles/WebSocket; frontend is vanilla JS, not React/TypeScript. The extension and `/sentinel` UI were not exercised in a browser in this environment.
