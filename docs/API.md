# ThreatLens REST API Reference

All endpoints are versioned under `/api/v1`.

---

## 1. Investigations

### Start Investigation
Starts a new investigation from a single IOC through the 19-stage pipeline.

- **URL**: `POST /api/v1/investigations`
- **Request Body**:
```json
{
  "ioc": "8.8.8.8",
  "ioc_type": "ipv4",
  "max_depth": 1,
  "providers": ["virustotal", "otx", "shodan"]
}
```
*(Note: `ioc_type`, `max_depth`, and `providers` are optional. Detection and routing occur automatically).*

- **Response (201 Created)**:
```json
{
  "id": "e4f8b912-3490-4c12-9c3f-91a0b12e4f5a",
  "root_ioc_value": "8.8.8.8",
  "root_ioc_type": "ipv4",
  "status": "complete",
  "risk_score": 10.0,
  "pivot_depth": 0,
  "created_at": "2026-03-01T12:00:00Z",
  "updated_at": "2026-03-01T12:00:02Z",
  "layer1": { ... },
  "layer2": { ... },
  "layer3": { ... },
  "graph": { ... },
  "events": [ ... ]
}
```

---

### List Investigations
Returns paginated summaries of past investigations for analyst history.

- **URL**: `GET /api/v1/investigations?limit=50&offset=0`
- **Response (200 OK)**:
```json
[
  {
    "id": "e4f8b912-3490-4c12-9c3f-91a0b12e4f5a",
    "root_ioc_value": "8.8.8.8",
    "root_ioc_type": "ipv4",
    "status": "complete",
    "risk_score": 10.0,
    "pivot_depth": 0,
    "discovered_iocs_count": 8,
    "total_relationships": 8,
    "providers_queried": 10,
    "created_at": "2026-03-01T12:00:00Z",
    "updated_at": "2026-03-01T12:00:02Z"
  }
]
```

---

### Get Investigation Details
Retrieves complete multi-layer investigation state.

- **URL**: `GET /api/v1/investigations/{id}`
- **Response (200 OK)**: Returns full `InvestigationDetailResponse`.

---

### Pivot from an IOC
Expands the investigation graph by pivoting on a specific discovered child IOC.

- **URL**: `POST /api/v1/investigations/{id}/pivot`
- **Request Body**:
```json
{
  "target_ioc": "dns.google",
  "target_type": "domain",
  "depth": 1
}
```
- **Response (200 OK)**: Updated investigation detail with incremented `pivot_depth` and newly discovered child nodes/edges.

---

### Sub-Resource Endpoints

- `GET /api/v1/investigations/{id}/providers`: Layer 1 provider results and statuses.
- `GET /api/v1/investigations/{id}/iocs`: Layer 3 discovered IOCs in the three primary buckets (`hashes`, `ips`, `urls_and_domains`).
- `GET /api/v1/investigations/{id}/relationships`: Deduplicated relationships with provenance.
- `GET /api/v1/investigations/{id}/graph`: React Flow graph representation (`nodes`, `edges`).

---

## 2. Real-Time Utilities

### Detect IOC
Real-time typing detection and canonical normalization.

- **URL**: `POST /api/v1/detect`
- **Request Body**:
```json
{
  "ioc": "  192.168.01.01  "
}
```
- **Response (200 OK)**:
```json
{
  "input_value": "  192.168.01.01  ",
  "detected_type": "ipv4",
  "canonical_value": "192.168.1.1",
  "is_valid": true,
  "message": null
}
```

---

## 3. Providers & Capabilities

### List Providers
Returns capability matrix and documentation references for all 12 providers.

- **URL**: `GET /api/v1/providers`
- **Response (200 OK)**: Array of `ProviderCapability` objects.

---

## 4. Health Check

- **URL**: `GET /api/v1/health`
- **Response (200 OK)**:
```json
{
  "status": "healthy",
  "project": "ThreatLens",
  "environment": "development",
  "provider_mode": "mock",
  "max_pivot_depth": 2,
  "database": "connected"
}
```
