# ThreatLens Development Guide

This guide outlines setup, extension workflows, adding new threat intelligence providers, and running test suites.

---

## 1. Local Development Setup

### Backend Setup
```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload --port 8000
```

### Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

---

## 2. Adding a New Provider Adapter

To add a 13th provider:

1. **Verify Official Documentation**: Research official endpoints, authentication headers, rate limits, and supported IOC types. Document them in `docs/PROVIDER_CAPABILITIES.md`.
2. **Implement Adapter Class**: In `backend/app/providers/<provider_name>.py`, subclass `BaseProvider` from `app.providers.base`.
   - Implement `get_capabilities()`
   - Implement `_execute_live(ctx)`
   - Implement `_execute_mock(ctx)`
   - Implement `_parse_response(ctx, data)`
3. **Register Adapter**:
   - Add the class instance to `_register_default_providers()` in `app/providers/registry.py`.
   - Add the provider's API key mapping in `app/providers/router.py`.
4. **Create Unit & Fixture Tests**:
   - In `backend/tests/providers/test_all_providers.py`, add a parser test verifying fixture decoding, status handling (`success`, `unsupported`, `not_configured`), and Layer 1/2/3 output.
5. **Run Verification**:
   ```bash
   backend/.venv/Scripts/pytest backend/tests -k "<provider_name>"
   ```

---

## 3. Database Migrations with Alembic

Whenever model definitions in `backend/app/models/models.py` are modified:

```bash
# Generate automatic migration script
backend/.venv/Scripts/alembic revision --autogenerate -m "describe_changes"

# Apply migrations
backend/.venv/Scripts/alembic upgrade head
```

---

## 4. Running Verification Commands

```bash
# Run backend test suite
backend/.venv/Scripts/pytest backend/tests -v

# Run frontend build check
cd frontend
npm run build
```
