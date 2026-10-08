# ThreatLens Architecture Guide

This document details the architectural design, data pipelines, normalization rules, and engine constraints of **ThreatLens**.

---

## High-Level Architecture

```
                                  [ Analyst UI (React + Tailwind + React Flow) ]
                                                        │
                                                        ▼
                                       [ FastAPI Async REST API (v1) ]
                                                        │
                      ┌─────────────────────────────────┼─────────────────────────────────┐
                      ▼                                 ▼                                 ▼
             [ IOC Service ]                 [ Provider Router ]              [ Investigation Service ]
         (Detect & Normalize)            (Capability Check & Async Gather)     (DB Session & Orchestration)
                                                        │                                 │
                                         ┌──────────────┴──────────────┐                  │
                                         ▼                             ▼                  ▼
                               [ 12 Real Adapters ]          [ Mock Mode Fixtures ]  [ PostgreSQL / SQLite ]
                                (VT, OTX, Shodan...)        (Zero-key evaluation)     (SQLAlchemy + Alembic)
                                                        │
                                                        ▼
                                       [ Global Deduplication & Merging ]
                                                        │
                                                        ▼
                                       [ Layer 1 / 2 / 3 Aggregation ]
                                                        │
                                                        ▼
                                       [ Recursive Pivot Engine & Graph ]
```

---

## 1. IOC Detection & Normalization Engine

Located in `app/services/ioc.py`, the engine processes raw user inputs through automated pattern classification:

1. **IPv4**: Evaluates 4 octets separated by dots (`0-255`), strips leading zeroes per octet to output canonical dotted quad (`192.168.01.01` -> `192.168.1.1`).
2. **IPv6**: Validates through `ipaddress.IPv6Address`, outputs compressed lowercase string (RFC 5952).
3. **Hashes**: Length-specific regex matching for MD5 (32 hex), SHA1 (40 hex), and SHA256 (64 hex), lowercases and strips whitespace/delimiters.
4. **URLs**: Case-insensitive scheme detection, lowercases scheme and host, normalizes path (deduplicating redundant slashes), and preserves query parameters and fragments.
5. **Domains**: Validates RFC 1035/1123 label constraints, strips protocols or path prefixes if entered erroneously, lowercases, and strips trailing FQDN dots.

---

## 2. Provider Abstraction & Router

Located in `app/providers/base.py` and `app/providers/router.py`:

- **`BaseProvider`**: Abstract class enforcing `get_capabilities()`, `is_ioc_supported(ioc_type)`, `_execute_live(ctx)`, and `_execute_mock(ctx)`.
- **Capability Isolation**: Before any network request is initiated, the router checks `is_ioc_supported`. Unsupported types (e.g. submitting a domain to AbuseIPDB or an IP to MalwareBazaar) return `ProviderStatus.UNSUPPORTED` immediately with zero network overhead.
- **Error Isolation**: Individual provider timeouts, HTTP 429s, or HTTP 5xx errors are caught within the provider's execution context and converted to structured status codes without aborting the broader investigation.
- **Bounded Concurrency**: Queries are dispatched concurrently across eligible providers using `asyncio.Semaphore` to prevent socket exhaustion and respect rate limits.

---

## 3. Global Normalization & Deduplication

Located in `app/services/deduplication.py`:

- **Canonical IOC Identity**: An IOC is uniquely identified by `(canonical_value, ioc_type)`. If VirusTotal, urlscan, and OTX all report `example.com`, only a single canonical IOC is generated in Layer 3 and the Graph.
- **Multi-Source Provenance**: When merging duplicate observations, all contributing provider names, evidence descriptions, timestamps, and confidence scores are aggregated on the canonical node.
- **Relationship Deduplication**: Relationships are identified by `(source_canonical, target_canonical, relationship_type)`. Multiple providers witnessing the same resolution or file download reinforce a single canonical edge with an incremented `evidence_count` and combined confidence score.

---

## 4. Transparent Confidence Model

Located in `app/services/confidence.py`:

Rather than displaying arbitrary black-box scores, ThreatLens computes an application-derived confidence score (0-100):

$$\text{Score} = (\text{Base Average} \times 0.6 \times \text{Weight Factor}) + \text{Corroboration Bonus} + \text{Directness Bonus}$$

- **Weight Factor**: Accounts for provider reliability (VirusTotal = 1.0, MalwareBazaar = 0.95, etc.).
- **Corroboration Bonus**: $+10$ points per additional independent provider agreeing on the finding (capped at $+25$).
- **Directness Bonus**: $+10$ points for direct structural relationships (`resolves_to`, `downloads`, `hosts`) vs generic association.
- **Tier Classification**:
  - `0 - 29`: Low
  - `30 - 59`: Medium
  - `60 - 79`: High
  - `80 - 100`: Very High

---

## 5. Recursive Pivot Engine

Located in `app/services/pivot.py`:

The engine performs safe graph expansion from any discovered node:

- **Visited Set Protection**: Maintains an active set of `(canonical_value, ioc_type)` visited nodes. Re-visiting an already explored node short-circuits instantly.
- **Cycle Prevention**: Prevents cyclic ping-pongs (e.g., `Domain A -> IP B -> Domain A`).
- **Hard Guardrails**:
  - `MAX_PIVOT_DEPTH`: Max traversal depth (default: 2)
  - `MAX_PIVOT_NODES`: Max nodes per investigation (default: 25)
  - `MAX_PROVIDER_REQUESTS`: Max total queries allowed (default: 40)

---

## 6. Database Schema (PostgreSQL / SQLite)

Managed via SQLAlchemy Async and Alembic:

- **`investigations`**: ID, root IOC, root type, status, risk score, pivot depth, timestamps.
- **`iocs`**: ID, investigation ID, canonical value, type, is root, depth, confidence, metadata JSON.
- **`provider_results`**: ID, investigation ID, provider name, status, latency, detection counts, infrastructure JSON, raw response.
- **`relationships`**: ID, investigation ID, source, target, relationship type, confidence, providers array JSON, evidence summary.
- **`pivot_runs`**: ID, investigation ID, parent IOC, child IOC, depth, status.
- **`investigation_events`**: Audit log for investigation lifecycle (started, routed, deduplicated, pivoted, completed).
