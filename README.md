# SafeChat Presidio PII Engine

A lean FastAPI service that exposes Microsoft Presidio's NLP-powered PII detection
and anonymization for **Human PII & Financial Data only**. All developer secrets,
CI/CD tokens, and infrastructure configs are handled by the TypeScript extension
(regex + AST + Shannon entropy).

The VS Code extension calls this server's `/sanitize` endpoint instead of spawning
Python directly — giving you full control over the Python environment and making
the extension dependency-free.

## Active Entities (12)

`PERSON`, `EMAIL_ADDRESS`, `PHONE_NUMBER`, `CREDIT_CARD`, `US_SSN`, `IBAN_CODE`, `US_BANK_NUMBER`, `CRYPTO`, `IP_ADDRESS`, `URL`, `CARD_CVV`, `CARD_EXPIRY`

> **Anti-hallucination:** `US_DRIVER_LICENSE` and `US_ITIN` are intentionally excluded — they cause false positives on source code (e.g. `apiVersion: v1` triggers a driver's license match).

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Liveness check (returns entity count) |
| `POST` | `/sanitize` | Analyze + anonymize in a single call *(used by extension)* |
| `GET` | `/docs` | Interactive Swagger UI (auto-generated) |
| `GET` | `/redoc` | ReDoc API reference (auto-generated) |

## Setup

### 1. Create a virtual environment

```bash
cd presidio_server
python3 -m venv .venv
source .venv/bin/activate        # macOS / Linux
# .venv\Scripts\activate         # Windows
```

### 2. Install dependencies

```bash
pip install -r requirements.txt
python -m spacy download en_core_web_lg
```

### 3. Start the server

```bash
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

Or via Python directly:

```bash
python main.py
```

The server listens on `http://localhost:8000` by default.

To use a different port:

```bash
SAFECHAT_PORT=9000 python main.py
# or
uvicorn main:app --port 9000
```

Then update the VS Code setting:

```json
"safechat.presidioApiUrl": "http://localhost:9000"
```

## API Reference

### `POST /sanitize` *(the only endpoint the extension uses)*

**Request:**
```json
{
  "text": "Hello, John Doe. Email: john@example.com",
  "rules": { "PERSON": "replace", "EMAIL_ADDRESS": "mask" }
}
```

**Response:**
```json
{
  "sanitized_text": "Hello, <PERSON>. Email: ****************",
  "was_modified": true,
  "entities_found": [
    { "entity_type": "PERSON", "start": 7, "end": 15, "score": 0.85, "text_snippet": "John Doe" },
    { "entity_type": "EMAIL_ADDRESS", "start": 24, "end": 40, "score": 1.0, "text_snippet": "john@example.com" }
  ]
}
```

**Request body:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `text` | string | — | Text to process |
| `rules` | object | `{}` | Per-entity operation: `replace`, `mask`, `redact`, or `hash` |

### `GET /health`

```json
{ "status": "ok", "service": "safechat-presidio-pii-engine", "entities": 12 }
```

## Architecture

```
presidio_server/
├── main.py               # FastAPI app — /health + /sanitize only
├── profiles.py           # ACTIVE_ENTITIES list (12 types, no hallucination-prone ones)
├── recognizers/
│   ├── __init__.py       # Exports CardCvvRecognizer, CardExpiryRecognizer
│   └── financial.py      # Card CVV + Card Expiry pattern recognizers
├── requirements.txt
└── bdd/                  # BDD test suite (financial + file format tests)
```

## Testing

The `bdd/` directory contains BDD + regression tests covering financial PII, custom recognizers, file formats, and Splunk logs.

### 1. Install test dependencies

```bash
pip install -r bdd/requirements.txt
```

### 2. Start the server (required before running tests)

```bash
uvicorn main:app --host 0.0.0.0 --port 8000
```

### 3. Run the tests

```bash
cd bdd
pytest tests/ -v
```

Run a specific subset:

```bash
pytest tests/ -v -m financial       # financial PII only
pytest tests/ -v -m smoke           # fast smoke subset
```

## Running with Docker *(optional)*

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt && python -m spacy download en_core_web_lg
COPY . .
CMD ["uvicorn", "presidio_server.main:app", "--host", "0.0.0.0", "--port", "8000"]
```

```bash
docker build -t safechat-presidio .
docker run -p 8000:8000 safechat-presidio
```

## VS Code Extension Integration

```json
"safechat.presidioApiUrl": "http://localhost:8000"
```

If the server is unreachable, the extension automatically falls back to its
built-in regex + AST + Shannon entropy engines (catches all secrets; only
human PII like names requires the NLP server).
