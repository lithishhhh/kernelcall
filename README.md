<<<<<<< HEAD
# Kernel Call Frontend

Kernel Call is a security investigation dashboard for Android APK analysis. This workspace contains the frontend experience for an evidence-driven Android security and forensic platform.

## Launching the frontend

From the project root, serve the frontend files with a small static server:

```bash
cd frontend
python -m http.server 8080
```

Then open:

```text
http://127.0.0.1:8080/
```

The frontend expects a local FastAPI backend to run on:

```text
http://127.0.0.1:8000
```

If the backend runs on another host or port, update the `API_BASE_URL` constant in `frontend/app.js` before opening the app.

## API contract used by the frontend

The frontend uses the following route families, with graceful fallback handling when specific endpoints are missing or not yet implemented:

- `GET /api/scans` — list scan history
- `POST /api/scans` — upload an APK and start analysis
- `GET /api/scans/{scan_id}` — retrieve a single scan record
- `GET /api/scans/{scan_id}/findings` — fetch finding records for a scan
- `GET /api/scans/{scan_id}/evidence` — fetch evidence metadata for a scan
- `POST /api/compare` — compare two APK results
- `GET /api/relationships` or `GET /api/correlation` — retrieve relationship graph data
- `POST /api/ask` or `POST /api/copilot/ask` — ask the forensic copilot a question
- `GET /api/reports/{scan_id}` — retrieve or generate a report

The frontend checks the HTTP status and handles non-JSON responses safely. It does not assume every backend returns the same field names. Where the backend omits fields, the UI shows an empty or unavailable state rather than inventing values.

## Supported request and response patterns

### Upload

```http
POST /api/scans
Content-Type: multipart/form-data
```

Expected response patterns include:

```json
{"id": "scan-123", "status": "queued"}
```

or

```json
{"scan_id": "scan-123", "scan_status": "processing"}
```

The frontend extracts the scan identifier if present and polls status if the API provides a terminal or processing state.

### Scans

```json
[
  {
    "id": "scan-123",
    "file_name": "sample.apk",
    "package_name": "com.example.app",
    "sha256": "...",
    "status": "completed",
    "timestamp": "2026-10-21T10:25:00Z"
  }
]
```

### Findings

```json
[
  {
    "id": "evidence-1",
    "title": "Suspicious network behavior",
    "severity": "high",
    "confidence": 0.91,
    "observation": "App attempts to contact a remote service without a clearly documented purpose.",
    "rule_id": "ANDR-204"
  }
]
```

### Comparison

The frontend sends a conservative comparison payload:

```json
{
  "first_scan_id": "scan-abc",
  "second_scan_id": "scan-def"
}
```

The backend may respond with any of the following common shapes:

- `application_overview`
- `permissions`
- `components`
- `indicators`
- `findings`
- `interpretation`

### Copilot

```json
{
  "question": "Why did this finding trigger?",
  "scan_id": "scan-abc",
  "context": { "scan_id": "scan-abc" }
}
```

Expected result patterns include:

```json
{
  "answer": "The finding was triggered because...",
  "references": ["EVID-001"]
}
```

## CORS and backend coordination

When the frontend is served from a different origin than the FastAPI backend, the backend must enable CORS for the frontend origin (for example `http://127.0.0.1:8080`). The frontend is intentionally defensive and will continue to function without backend data by showing explicit unavailable states.

## Status of implementation

This frontend includes the full user interface shell, upload flow, scan history, scan details, findings view, comparison workflow, relationship graph, copilot interface, and report handling. It is designed to work with a genuine FastAPI backend when available and to fail gracefully when endpoints are not yet implemented.

Features that still require backend support include:

- Real APK upload validation beyond client-side checks
- Actual scan processing and status progression
- Real findings generation and evidence extraction
- Relationship graph data from the intelligence layer
- AI answer generation from the Copilot API
- Report generation and download via the backend

The application intentionally does not fabricate any detections, findings, graph edges, or AI answers. Empty states, service-unavailable messages, and placeholders ensure the dashboard remains truthful while the backend is being developed.
=======
# kernelcall
>>>>>>> 8b2aea0efd20c12a6a85b1af1c6ac8d09431b8de
