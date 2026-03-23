# SafeChat Presidio Server

A standalone FastAPI service that exposes Microsoft Presidio's PII analysis and
anonymization over HTTP. The VS Code extension calls this server instead of
spawning Python directly — giving you full control over the Python environment
and making the extension dependency-free.

## Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/health` | Liveness check |
| `POST` | `/analyze` | Detect PII entities (no masking) |
| `POST` | `/anonymize` | Mask PII entities, return anonymized text |
| `POST` | `/sanitize` | Analyze + anonymize in a single call *(used by extension)* |
| `GET` | `/docs` | Interactive Swagger UI |
| `GET` | `/redoc` | ReDoc API reference |

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

### `POST /sanitize` *(primary endpoint used by the extension)*

**Request:**
```json
{
  "text": "Hello, John Doe. Email: john@example.com",
  "language": "en",
  "replacement_format": "<{entity_type}>"
}
```

**Response:**
```json
{
  "sanitized_text": "Hello, <PERSON>. Email: <EMAIL_ADDRESS>",
  "was_modified": true,
  "entities_found": [
    { "entity_type": "PERSON", "start": 7, "end": 15, "score": 0.85, "text_snippet": "John Doe" },
    { "entity_type": "EMAIL_ADDRESS", "start": 24, "end": 40, "score": 1.0, "text_snippet": "john@example.com" }
  ]
}
```

### `POST /analyze` *(detection only)*

**Request:**
```json
{
  "text": "My card number is 4111 1111 1111 1111",
  "language": "en"
}
```

**Response:**
```json
{
  "entities_found": [
    { "entity_type": "CREDIT_CARD", "start": 18, "end": 37, "score": 1.0, "text_snippet": "4111 1111 1111 1111" }
  ]
}
```

### `POST /anonymize` *(mask only)*

Same as `/sanitize` but always returns `anonymized_text` — does not return `was_modified`.

## Testing

The `bdd/` directory contains a full BDD + regression test suite (225 tests) covering financial PII, developer secrets, infrastructure credentials, CI/CD tokens, custom recognizers, file formats, and Splunk logs.

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

Reports are written to `bdd/reports/`:
- `test_report.html` — self-contained HTML report
- `allure-results/` — raw data for Allure (generate with `allure serve reports/allure-results`)

Run a specific marker subset:

```bash
pytest tests/ -v -m financial       # financial PII only
pytest tests/ -v -m developer       # developer secrets only
pytest tests/ -v -m smoke           # fast smoke subset
```

## Running with Docker *(optional)*

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt && python -m spacy download en_core_web_lg
COPY main.py .
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
```

```bash
docker build -t safechat-presidio .
docker run -p 8000:8000 safechat-presidio
```

## VS Code Extension Integration

Open VS Code Settings and configure:

```json
"safechat.presidioApiUrl": "http://localhost:8000"
```

If the server is unreachable, the extension automatically falls back to its
built-in regex masking engine (catches API keys, tokens, Bearer headers, etc.)
