"""
Documentation web UI — served at GET /docs/ui
───────────────────────────────────────────────
A single self-contained HTML page (no external dependencies) that:
  1. Lists all built-in Presidio entity types
  2. Lists all custom recognizers grouped by profile
  3. Documents all 5 anonymizer operations
  4. Provides a YAML generator for adding custom recognizer rules
"""

from __future__ import annotations

# ─────────────────────────────────────────────────────────────────────────────
# Entity catalogue — mirrors the recognizers we ship
# ─────────────────────────────────────────────────────────────────────────────

BUILTIN_ENTITIES = [
    {"entity": "CREDIT_CARD",       "description": "Credit/debit card numbers (Visa, MC, Amex, etc.)", "example": "4111 1111 1111 1111"},
    {"entity": "CRYPTO",            "description": "Cryptocurrency wallet addresses (Bitcoin, Ethereum)", "example": "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"},
    {"entity": "DATE_TIME",         "description": "Dates and timestamps",                              "example": "March 22, 2026"},
    {"entity": "EMAIL_ADDRESS",     "description": "Email addresses",                                   "example": "john.doe@example.com"},
    {"entity": "IBAN_CODE",         "description": "International Bank Account Numbers",                 "example": "GB29NWBK60161331926819"},
    {"entity": "IP_ADDRESS",        "description": "IPv4 and IPv6 addresses",                            "example": "203.0.113.42"},
    {"entity": "LOCATION",          "description": "Physical locations, addresses, cities, countries",   "example": "1600 Pennsylvania Avenue"},
    {"entity": "MAC_ADDRESS",       "description": "Network hardware (MAC) addresses",                   "example": "00:1A:2B:3C:4D:5E"},
    {"entity": "MEDICAL_LICENSE",   "description": "Medical license numbers",                            "example": "DEA# AB1234567"},
    {"entity": "NRP",               "description": "Nationalities, religions, political groups",         "example": "British"},
    {"entity": "PERSON",            "description": "Person names (first, last, full)",                   "example": "Jane Smith"},
    {"entity": "PHONE_NUMBER",      "description": "Phone numbers (US and international)",               "example": "+1 (555) 123-4567"},
    {"entity": "URL",               "description": "Web URLs",                                           "example": "https://example.com/api"},
    {"entity": "US_BANK_NUMBER",    "description": "US bank account numbers",                            "example": "1234567890"},
    {"entity": "US_DRIVER_LICENSE", "description": "US driver's license numbers",                        "example": "D12345678"},
    {"entity": "US_ITIN",           "description": "US Individual Taxpayer ID Numbers",                  "example": "900-70-0000"},
    {"entity": "US_PASSPORT",       "description": "US passport numbers",                                "example": "C12345678"},
    {"entity": "US_SSN",            "description": "US Social Security Numbers",                         "example": "123-45-6789"},
]

CUSTOM_ENTITY_GROUPS = {
    "financial": [
        {"entity": "SWIFT_BIC_CODE",    "description": "SWIFT/BIC bank identifier codes (8 or 11 chars)", "example": "CHASUS33XXX", "pattern": r"[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}([A-Z0-9]{3})?"},
        {"entity": "US_ROUTING_NUMBER", "description": "US ABA routing / transit numbers (9 digits, mod-10 checksum)", "example": "021000021", "pattern": r"\d{9}"},
        {"entity": "UK_SORT_CODE",      "description": "UK bank sort codes (XX-XX-XX)", "example": "20-00-00", "pattern": r"\d{2}-\d{2}-\d{2}"},
        {"entity": "BSB_CODE",          "description": "Australian BSB codes (XXX-XXX)", "example": "062-000", "pattern": r"\d{3}-\d{3}"},
        {"entity": "CARD_CVV",          "description": "Card CVV/CVC/CID security codes (3-4 digits)", "example": "cvv: 123", "pattern": r"(cvv|cvc)\s*[:=]\s*\d{3,4}"},
        {"entity": "CARD_EXPIRY",       "description": "Card expiry dates (MM/YY or MM/YYYY)", "example": "12/25", "pattern": r"(0[1-9]|1[0-2])\/\d{2,4}"},
        {"entity": "ISIN_CODE",         "description": "International Securities Identification Numbers", "example": "US0378331005", "pattern": r"[A-Z]{2}[A-Z0-9]{9}[0-9]"},
        {"entity": "CUSIP",             "description": "North-American securities identifiers (9 chars)", "example": "037833100", "pattern": r"[0-9]{3}[A-Z0-9]{5}[0-9]"},
        {"entity": "SEDOL",             "description": "UK/Irish securities identifiers (7 chars)", "example": "B0YBKJ7", "pattern": r"[B-DF-HJ-NP-TV-Z0-9]{7}"},
        {"entity": "TAX_EIN",           "description": "US Employer Identification Numbers (XX-XXXXXXX)", "example": "12-3456789", "pattern": r"\d{2}-\d{7}"},
        {"entity": "VAT_NUMBER",        "description": "EU/UK VAT registration numbers", "example": "GB123456789", "pattern": r"[A-Z]{2}\d{7,12}"},
        {"entity": "PAYMENT_REFERENCE", "description": "Transaction / payment reference IDs", "example": "TX-12345678", "pattern": r"UUID or alpha-numeric ref"},
        {"entity": "LOAN_ACCOUNT",      "description": "Loan / mortgage account numbers", "example": "loan#: LA12345678", "pattern": r"loan/mortgage context + ID"},
    ],
    "developer": [
        {"entity": "AWS_ACCESS_KEY",       "description": "AWS IAM access key IDs (AKIA/ASIA prefix)", "example": "AKIAIOSFODNN7EXAMPLE", "pattern": r"AKIA[0-9A-Z]{16}"},
        {"entity": "AWS_SECRET_KEY",       "description": "AWS IAM secret access keys (40-char)", "example": "aws_secret_access_key=wJalr...", "pattern": r"aws_secret_access_key\s*=\s*[A-Za-z0-9/+]{40}"},
        {"entity": "GITHUB_TOKEN",         "description": "GitHub PATs, OAuth, fine-grained tokens", "example": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12", "pattern": r"ghp_[A-Za-z0-9]{36}"},
        {"entity": "GITLAB_TOKEN",         "description": "GitLab personal/project/deploy tokens", "example": "glpat-XXXXXXXXXXXXXXXXXXXX", "pattern": r"glpat-[A-Za-z0-9_-]{20,}"},
        {"entity": "SLACK_TOKEN",          "description": "Slack bot/user/app tokens & webhooks", "example": "xoxb-1234-5678-abc", "pattern": r"xoxb-[0-9A-Za-z-]+"},
        {"entity": "JWT_TOKEN",            "description": "JSON Web Tokens (three base64url segments)", "example": "eyJhbGciOiJIUzI1NiJ9.eyJ...", "pattern": r"eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]*"},
        {"entity": "STRIPE_KEY",           "description": "Stripe API keys (sk_live/test, pk_, rk_)", "example": "sk_live_abc123...", "pattern": r"sk_(live|test)_[A-Za-z0-9]{24,}"},
        {"entity": "SENDGRID_KEY",         "description": "SendGrid API keys", "example": "SG.xxxxx.yyyyy", "pattern": r"SG\.[A-Za-z0-9-_]{22}\.[A-Za-z0-9-_]{43}"},
        {"entity": "TWILIO_SID",           "description": "Twilio Account SIDs and auth tokens", "example": "AC1234567890abcdef1234567890abcdef", "pattern": r"AC[a-f0-9]{32}"},
        {"entity": "NPM_TOKEN",            "description": "NPM registry tokens", "example": "npm_ABCDEFabcdef1234567890abcdefABCDEF12", "pattern": r"npm_[A-Za-z0-9]{36}"},
        {"entity": "HASHICORP_VAULT_TOKEN","description": "HashiCorp Vault service/batch/recovery tokens", "example": "hvs.CAESIJzYm...", "pattern": r"hvs\.[A-Za-z0-9]+"},
        {"entity": "GENERIC_API_KEY",      "description": "Generic API key/secret/password assignments", "example": "api_key=AbCdEfGhIj...", "pattern": r"api_key\s*=\s*[A-Za-z0-9]{20,}"},
        {"entity": "BEARER_TOKEN",         "description": "Authorization: Bearer tokens", "example": "Authorization: Bearer eyJ...", "pattern": r"Bearer\s+[A-Za-z0-9-._~+/]+=*"},
        {"entity": "PRIVATE_KEY_BLOCK",    "description": "PEM private key headers (RSA, EC, etc.)", "example": "-----BEGIN RSA PRIVATE KEY-----", "pattern": r"-----BEGIN\s+.*PRIVATE\s+KEY-----"},
        {"entity": "CERTIFICATE_BLOCK",    "description": "PEM certificate / CSR block headers", "example": "-----BEGIN CERTIFICATE-----", "pattern": r"-----BEGIN\s+CERTIFICATE-----"},
    ],
    "infrastructure": [
        {"entity": "DB_CONNECTION_STRING",  "description": "SQL/NoSQL database connection URLs", "example": "postgres://user:pass@host/db", "pattern": r"postgres://[^\s]+"},
        {"entity": "AZURE_CONN_STRING",     "description": "Azure Storage/ServiceBus/CosmosDB connection strings", "example": "DefaultEndpointsProtocol=https;AccountName=...", "pattern": r"DefaultEndpointsProtocol=...AccountKey=..."},
        {"entity": "JDBC_URL",              "description": "Java JDBC connection URLs", "example": "jdbc:mysql://host:3306/db", "pattern": r"jdbc:mysql://..."},
        {"entity": "REDIS_URL",             "description": "Redis connection URIs", "example": "redis://:secret@host:6379/0", "pattern": r"redis(s)?://[^\s]+"},
        {"entity": "MONGO_URL",             "description": "MongoDB standard and SRV URIs", "example": "mongodb+srv://user:pass@cluster", "pattern": r"mongodb(\+srv)?://[^\s]+"},
        {"entity": "INTERNAL_HOSTNAME",     "description": "Internal hostnames (*.internal, *.corp, *.prod)", "example": "api.prod.internal", "pattern": r"*.internal, *.corp, *.prod"},
        {"entity": "PRIVATE_IP_ADDRESS",    "description": "RFC 1918 private, loopback, link-local IPs", "example": "10.0.1.42", "pattern": r"10\.\d+\.\d+\.\d+"},
        {"entity": "ENV_VARIABLE_VALUE",    "description": ".env secret variable assignments", "example": "DB_PASSWORD=super_secret", "pattern": r"[A-Z_]+SECRET\s*=\s*..."},
        {"entity": "K8S_SECRET_VALUE",      "description": "Base64 values in Kubernetes Secret manifests", "example": "  password: c3VwZXJzZWNyZXQ=", "pattern": r"base64 in YAML data: blocks"},
        {"entity": "CERTIFICATE_THUMBPRINT","description": "Certificate SHA-1/SHA-256 fingerprints", "example": "A1:B2:C3:D4:...", "pattern": r"([0-9A-Fa-f]{2}:){19}[0-9A-Fa-f]{2}"},
    ],
    "cicd": [
        {"entity": "JENKINS_TOKEN",              "description": "Jenkins API tokens", "example": "JENKINS_TOKEN=abc123...", "pattern": r"jenkins.*token\s*[:=]\s*[A-Za-z0-9]{32,}"},
        {"entity": "CIRCLECI_TOKEN",             "description": "CircleCI personal/project API tokens", "example": "CCIPAT_abcdef1234567890...", "pattern": r"CCIPAT_[A-Za-z0-9_]{40}"},
        {"entity": "GITLAB_CI_TOKEN",            "description": "GitLab CI runner/trigger tokens", "example": "glrt-XXXXXXXXXXXXXXXXXXXX", "pattern": r"glrt-[A-Za-z0-9_-]{20,}"},
        {"entity": "SONARQUBE_TOKEN",            "description": "SonarQube/Cloud analysis tokens", "example": "sqp_abcdef1234567890...", "pattern": r"sqp_[A-Za-z0-9]{40}"},
        {"entity": "OPENSHIFT_TOKEN",            "description": "OpenShift/OCP4 API tokens (sha256~ format)", "example": "sha256~ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmno", "pattern": r"sha256~[A-Za-z0-9-_]{43}"},
        {"entity": "K8S_SA_TOKEN",               "description": "Kubernetes service account bearer tokens", "example": "token: eyJhbGciOiJSUzI1...", "pattern": r"kubeconfig token: field"},
        {"entity": "DOCKER_REGISTRY_CREDENTIAL", "description": "Docker config auth base64 entries", "example": '"auth": "dXNlcjpwYXNz"', "pattern": r'"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}"'},
        {"entity": "HELM_SECRET",                "description": "SOPS-encrypted Helm secret values", "example": "ENC[AES256_GCM,data:...,iv:...,tag:...]", "pattern": r"ENC\[AES256_GCM,...\]"},
        {"entity": "TERRAFORM_TOKEN",            "description": "Terraform Cloud / TFE API tokens", "example": "atlasv1.XXXXXXXXX...", "pattern": r"[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9]{67}"},
        {"entity": "ANSIBLE_VAULT",              "description": "Ansible Vault AES256-encrypted blocks", "example": "$ANSIBLE_VAULT;1.1;AES256\\n3030...", "pattern": r"$ANSIBLE_VAULT;1.1;AES256"},
        {"entity": "GCP_SA_KEY",                 "description": "GCP service account JSON keys & emails", "example": '"type": "service_account"', "pattern": r'"type"\s*:\s*"service_account"'},
        {"entity": "AZURE_SP_SECRET",            "description": "Azure Service Principal secrets & IDs", "example": "AZURE_CLIENT_SECRET=xxx", "pattern": r"AZURE_CLIENT_SECRET\s*=\s*..."},
        {"entity": "BITBUCKET_APP_PASSWORD",     "description": "Bitbucket app passwords & access tokens", "example": "ATBBabcdef1234567890abcdefgh12", "pattern": r"ATBB[A-Za-z0-9]{28}"},
        {"entity": "ARGOCD_TOKEN",               "description": "Argo CD API bearer tokens", "example": "ARGOCD_AUTH_TOKEN=eyJ...", "pattern": r"ARGOCD_AUTH_TOKEN\s*=\s*..."},
    ],
}

ANONYMIZER_OPERATIONS = [
    {
        "name": "replace",
        "description": "Substitute the detected PII with a typed placeholder tag.",
        "example_input": "Call me at 555-1234",
        "example_output": "Call me at <PHONE_NUMBER>",
    },
    {
        "name": "mask",
        "description": "Replace PII characters with a masking character (default: *).",
        "example_input": "Card: 4111111111111111",
        "example_output": "Card: ****",
    },
    {
        "name": "redact",
        "description": "Completely remove the detected PII from the text.",
        "example_input": "Email is john@test.com please",
        "example_output": "Email is  please",
    },
    {
        "name": "hash",
        "description": "Replace PII with a one-way SHA-256 hash of the value.",
        "example_input": "SSN 123-45-6789",
        "example_output": "SSN 01a54629efb952...",
    },
    {
        "name": "encrypt",
        "description": "Replace PII with an AES-encrypted (reversible) value. Requires a server-side encryption key.",
        "example_input": "Name: Jane Smith",
        "example_output": "Name: dGhpcyBpcyBiYXN...",
    },
]


def get_docs_html() -> str:
    """Return the full HTML documentation page as a string."""
    return _DOCS_HTML


# ─────────────────────────────────────────────────────────────────────────────
# HTML template (single string — no Jinja / file dependency)
# ─────────────────────────────────────────────────────────────────────────────

def _entity_rows(entities: list[dict], show_pattern: bool = False) -> str:
    rows = []
    for e in entities:
        pat_col = f'<td class="mono">{_esc(e.get("pattern",""))}</td>' if show_pattern else ""
        rows.append(
            f'<tr><td class="mono entity-name">{_esc(e["entity"])}</td>'
            f'<td>{_esc(e["description"])}</td>'
            f'<td class="mono">{_esc(e["example"])}</td>'
            f'{pat_col}</tr>'
        )
    return "\n".join(rows)


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _build_html() -> str:
    builtin_rows = _entity_rows(BUILTIN_ENTITIES)

    profile_sections = ""
    for profile_name, entities in CUSTOM_ENTITY_GROUPS.items():
        profile_sections += f"""
        <div class="profile-section" id="profile-{profile_name}">
          <h3>{profile_name.title()} Profile</h3>
          <table>
            <thead><tr><th>Entity Type</th><th>Description</th><th>Example</th><th>Pattern Hint</th></tr></thead>
            <tbody>{_entity_rows(entities, show_pattern=True)}</tbody>
          </table>
        </div>"""

    # Build the entity-type <option> list for the YAML generator
    all_entity_types = sorted(
        set(
            [e["entity"] for e in BUILTIN_ENTITIES]
            + [e["entity"] for group in CUSTOM_ENTITY_GROUPS.values() for e in group]
        )
    )
    entity_options = "\n".join(
        f'<option value="{_esc(e)}">{_esc(e)}</option>' for e in all_entity_types
    )

    profile_options = "\n".join(
        f'<option value="{_esc(p)}">{_esc(p.title())}</option>'
        for p in list(CUSTOM_ENTITY_GROUPS.keys()) + ["custom"]
    )

    anonymizer_cards = ""
    for op in ANONYMIZER_OPERATIONS:
        anonymizer_cards += f"""
        <div class="anon-card">
          <h4><code>{_esc(op["name"])}</code></h4>
          <p>{_esc(op["description"])}</p>
          <div class="example-box">
            <div class="label">Input:</div><div class="mono">{_esc(op["example_input"])}</div>
            <div class="label">Output:</div><div class="mono highlight">{_esc(op["example_output"])}</div>
          </div>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SafeChat Sanitizer — Documentation</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --surface2: #21262d; --border: #30363d;
    --text: #c9d1d9; --text2: #8b949e; --accent: #58a6ff; --accent2: #3fb950;
    --red: #f85149; --orange: #d29922; --purple: #bc8cff;
    --font: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial;
    --mono: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
  }}
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family:var(--font); background:var(--bg); color:var(--text); line-height:1.6; }}
  .container {{ max-width:1100px; margin:0 auto; padding:2rem 1.5rem; }}
  h1 {{ color:#fff; font-size:2rem; margin-bottom:.5rem; }}
  h1 span {{ color:var(--accent); }}
  .subtitle {{ color:var(--text2); font-size:1.05rem; margin-bottom:2.5rem; }}
  h2 {{ color:#fff; font-size:1.4rem; margin:2.5rem 0 1rem; padding-bottom:.5rem; border-bottom:1px solid var(--border); }}
  h3 {{ color:var(--accent); font-size:1.15rem; margin:1.5rem 0 .75rem; }}
  h4 {{ color:var(--accent2); margin-bottom:.3rem; }}

  /* Nav pills */
  .nav {{ display:flex; flex-wrap:wrap; gap:.5rem; margin-bottom:1.5rem; }}
  .nav a {{ display:inline-block; padding:.4rem .9rem; border-radius:6px; background:var(--surface2);
            color:var(--text); text-decoration:none; font-size:.85rem; transition:background .2s; }}
  .nav a:hover {{ background:var(--accent); color:#fff; }}

  /* Tables */
  table {{ width:100%; border-collapse:collapse; margin-bottom:1.5rem; font-size:.9rem; }}
  th {{ text-align:left; padding:.6rem .8rem; background:var(--surface2); color:var(--accent);
       font-weight:600; border-bottom:2px solid var(--border); }}
  td {{ padding:.55rem .8rem; border-bottom:1px solid var(--border); vertical-align:top; }}
  tr:hover td {{ background:var(--surface); }}
  .mono {{ font-family:var(--mono); font-size:.82rem; }}
  .entity-name {{ color:var(--orange); font-weight:600; white-space:nowrap; }}

  /* Anonymizer cards */
  .anon-grid {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(320px,1fr)); gap:1rem; }}
  .anon-card {{ background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:1.2rem; }}
  .anon-card code {{ color:var(--accent2); font-size:1rem; }}
  .example-box {{ margin-top:.6rem; background:var(--surface2); border-radius:6px; padding:.7rem; font-size:.85rem; }}
  .label {{ color:var(--text2); font-size:.78rem; text-transform:uppercase; margin-bottom:.15rem; }}
  .highlight {{ color:var(--accent); }}

  /* YAML Generator */
  .generator {{ background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:1.5rem; margin-top:1rem; }}
  .form-grid {{ display:grid; grid-template-columns:1fr 1fr; gap:1rem; margin-bottom:1rem; }}
  @media(max-width:640px) {{ .form-grid {{ grid-template-columns:1fr; }} }}
  label {{ display:block; color:var(--text2); font-size:.82rem; margin-bottom:.3rem; }}
  input,select,textarea {{ width:100%; padding:.5rem .7rem; border:1px solid var(--border); border-radius:6px;
    background:var(--surface2); color:var(--text); font-family:var(--mono); font-size:.85rem; }}
  input:focus,select:focus,textarea:focus {{ outline:none; border-color:var(--accent); }}
  textarea {{ resize:vertical; min-height:60px; }}
  .btn {{ display:inline-block; padding:.55rem 1.2rem; border:none; border-radius:6px; cursor:pointer;
    font-size:.9rem; font-weight:600; transition:background .2s; }}
  .btn-primary {{ background:var(--accent); color:#fff; }}
  .btn-primary:hover {{ background:#79c0ff; }}
  .btn-secondary {{ background:var(--surface2); color:var(--text); border:1px solid var(--border); margin-left:.5rem; }}
  .btn-secondary:hover {{ background:var(--border); }}
  #yaml-output {{ margin-top:1rem; background:var(--bg); border:1px solid var(--border); border-radius:6px;
    padding:1rem; font-family:var(--mono); font-size:.82rem; white-space:pre-wrap; display:none; color:var(--accent2); }}
  .badge {{ display:inline-block; padding:.15rem .5rem; border-radius:4px; font-size:.72rem;
    font-weight:600; text-transform:uppercase; margin-left:.5rem; }}
  .badge-builtin {{ background:#1f3a2e; color:var(--accent2); }}
  .badge-custom  {{ background:#2a1f3a; color:var(--purple); }}

  /* Profile section */
  .profile-section {{ margin-bottom:2rem; }}
</style>
</head>
<body>
<div class="container">

  <h1><span>SafeChat</span> Sanitizer Documentation</h1>
  <p class="subtitle">
    Complete reference for all PII entity types, anonymizer operations, and custom recognizer configuration.
  </p>

  <div class="nav">
    <a href="#builtin">Built-in Entities</a>
    <a href="#custom">Custom Recognizers</a>
    <a href="#anonymizers">Anonymizer Operations</a>
    <a href="#generator">YAML Config Generator</a>
    <a href="#api">API Reference</a>
  </div>

  <!-- ─────────────── BUILT-IN ENTITIES ─────────────── -->
  <h2 id="builtin">Built-in Presidio Entities <span class="badge badge-builtin">Presidio Core</span></h2>
  <p style="color:var(--text2);margin-bottom:1rem;">
    These entity types are detected by Microsoft Presidio's built-in NLP and pattern recognizers.
    They are always available in every profile.
  </p>
  <table>
    <thead><tr><th>Entity Type</th><th>Description</th><th>Example</th></tr></thead>
    <tbody>{builtin_rows}</tbody>
  </table>

  <!-- ─────────────── CUSTOM RECOGNIZERS ─────────────── -->
  <h2 id="custom">Custom Recognizers <span class="badge badge-custom">SafeChat Custom</span></h2>
  <p style="color:var(--text2);margin-bottom:1rem;">
    These recognizers are built by SafeChat on top of Presidio using regex patterns with context boosting.
    Each recognizer belongs to one or more profiles.
  </p>

  <div class="nav" style="margin-bottom:.5rem;">
    <a href="#profile-financial">Financial</a>
    <a href="#profile-developer">Developer</a>
    <a href="#profile-infrastructure">Infrastructure</a>
    <a href="#profile-cicd">CI/CD</a>
  </div>

  {profile_sections}

  <!-- ─────────────── ANONYMIZER OPERATIONS ─────────────── -->
  <h2 id="anonymizers">Anonymizer Operations</h2>
  <p style="color:var(--text2);margin-bottom:1rem;">
    Choose how each detected entity is transformed. Set per-entity in <code>safechat-rules.yaml</code>.
  </p>
  <div class="anon-grid">
    {anonymizer_cards}
  </div>

  <!-- ─────────────── YAML GENERATOR ─────────────── -->
  <h2 id="generator">Custom Recognizer &amp; Rule Generator</h2>
  <p style="color:var(--text2);margin-bottom:1rem;">
    Use this form to generate YAML configuration for your <code>.vscode/safechat-rules.yaml</code> file.
    You can add new custom regex recognizers or set anonymizer rules for existing entity types.
  </p>

  <div class="generator">
    <h3 style="margin-top:0;">Add New Custom Recognizer</h3>
    <p style="color:var(--text2);font-size:.85rem;margin-bottom:1rem;">
      Define a custom regex pattern that the analyzer will use to detect a specific PII type.
    </p>
    <div class="form-grid">
      <div>
        <label for="cr-name">Entity Name (e.g. EMPLOYEE_ID)</label>
        <input id="cr-name" type="text" placeholder="EMPLOYEE_ID" />
      </div>
      <div>
        <label for="cr-profile">Target Profile</label>
        <select id="cr-profile">{profile_options}</select>
      </div>
      <div>
        <label for="cr-pattern">Regex Pattern</label>
        <input id="cr-pattern" type="text" placeholder="EMP-\\d{{6}}" />
      </div>
      <div>
        <label for="cr-score">Confidence Score (0.0 – 1.0)</label>
        <input id="cr-score" type="number" min="0" max="1" step="0.05" value="0.85" />
      </div>
      <div style="grid-column:1/-1;">
        <label for="cr-context">Context Words (comma-separated)</label>
        <input id="cr-context" type="text" placeholder="employee, staff, id, badge" />
      </div>
    </div>

    <h3>Set Anonymizer Rule</h3>
    <div class="form-grid">
      <div>
        <label for="rule-entity">Entity Type</label>
        <select id="rule-entity">
          <option value="">— use custom name above —</option>
          {entity_options}
        </select>
      </div>
      <div>
        <label for="rule-action">Anonymizer Operation</label>
        <select id="rule-action">
          <option value="replace">Replace — &lt;ENTITY_TYPE&gt;</option>
          <option value="mask">Mask — ****</option>
          <option value="redact">Redact — remove entirely</option>
          <option value="hash">Hash — SHA-256 digest</option>
          <option value="encrypt">Encrypt — AES reversible</option>
        </select>
      </div>
      <div>
        <label for="rule-mask-char">Mask Character (if mask)</label>
        <input id="rule-mask-char" type="text" maxlength="1" value="*" />
      </div>
      <div>
        <label for="rule-mask-len">Mask Length (if mask, 0=auto)</label>
        <input id="rule-mask-len" type="number" min="0" value="0" />
      </div>
    </div>

    <button class="btn btn-primary" onclick="generateYaml()">Generate YAML</button>
    <button class="btn btn-secondary" onclick="copyYaml()">Copy to Clipboard</button>
    <pre id="yaml-output"></pre>
  </div>

  <!-- ─────────────── API REFERENCE ─────────────── -->
  <h2 id="api">API Reference</h2>
  <table>
    <thead><tr><th>Endpoint</th><th>Method</th><th>Description</th></tr></thead>
    <tbody>
      <tr><td class="mono">/health</td><td>GET</td><td>Liveness check</td></tr>
      <tr><td class="mono">/profiles</td><td>GET</td><td>List available sanitization profiles</td></tr>
      <tr><td class="mono">/docs/ui</td><td>GET</td><td>This documentation page</td></tr>
      <tr><td class="mono">/docs/entities</td><td>GET</td><td>JSON catalogue of all entity types</td></tr>
      <tr><td class="mono">/analyze</td><td>POST</td><td>Detect PII — returns findings without masking</td></tr>
      <tr><td class="mono">/anonymize</td><td>POST</td><td>Detect + anonymize PII — returns masked text</td></tr>
      <tr><td class="mono">/sanitize</td><td>POST</td><td>Detect + anonymize (recommended single-call endpoint)</td></tr>
    </tbody>
  </table>

  <h3>Request Body (POST /sanitize)</h3>
  <pre style="background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:1rem;font-size:.82rem;color:var(--accent2);overflow-x:auto;">{{
  "text": "string (required) — the text to sanitize",
  "language": "en (default)",
  "profile": "financial | developer | infrastructure | cicd | full (optional)",
  "entities": ["ENTITY_TYPE", "..."]  // explicit override (optional),
  "rules": {{
    "ENTITY_TYPE": "replace | mask | redact | hash | encrypt"
  }},
  "custom_recognizers": [
    {{
      "name": "EMPLOYEE_ID",
      "pattern": "EMP-\\\\d{{6}}",
      "score": 0.85,
      "context": ["employee", "staff", "id"]
    }}
  ]
}}</pre>

</div>

<script>
function generateYaml() {{
  const name = document.getElementById('cr-name').value.trim().toUpperCase().replace(/[\\s-]/g, '_');
  const profile = document.getElementById('cr-profile').value;
  const pattern = document.getElementById('cr-pattern').value.trim();
  const score = parseFloat(document.getElementById('cr-score').value) || 0.85;
  const context = document.getElementById('cr-context').value.trim();
  const ruleEntity = document.getElementById('rule-entity').value || name;
  const action = document.getElementById('rule-action').value;
  const maskChar = document.getElementById('rule-mask-char').value || '*';
  const maskLen = parseInt(document.getElementById('rule-mask-len').value) || 0;

  let yaml = '# Add this to your .vscode/safechat-rules.yaml\\n';
  yaml += '# ── SafeChat Configuration ──\\n\\n';

  // Rules section
  yaml += 'rules:\\n';
  if (action === 'mask' && (maskChar !== '*' || maskLen > 0)) {{
    yaml += '  ' + ruleEntity + ':\\n';
    yaml += '    action: mask\\n';
    if (maskChar !== '*') yaml += '    mask_char: "' + maskChar + '"\\n';
    if (maskLen > 0) yaml += '    mask_length: ' + maskLen + '\\n';
  }} else {{
    yaml += '  ' + ruleEntity + ': ' + action + '\\n';
  }}

  // Custom recognizer section
  if (name && pattern) {{
    yaml += '\\n# ── Custom Recognizers ──\\n';
    yaml += 'custom_recognizers:\\n';
    yaml += '  - name: ' + name + '\\n';
    yaml += '    pattern: "' + pattern.replace(/"/g, '\\\\"') + '"\\n';
    yaml += '    score: ' + score + '\\n';
    if (profile !== 'custom') yaml += '    profile: ' + profile + '\\n';
    if (context) {{
      const words = context.split(',').map(w => w.trim()).filter(Boolean);
      yaml += '    context:\\n';
      words.forEach(w => {{ yaml += '      - ' + w + '\\n'; }});
    }}
  }}

  const out = document.getElementById('yaml-output');
  out.textContent = yaml;
  out.style.display = 'block';
}}

function copyYaml() {{
  const text = document.getElementById('yaml-output').textContent;
  if (!text) {{ generateYaml(); }}
  navigator.clipboard.writeText(document.getElementById('yaml-output').textContent)
    .then(() => {{ alert('Copied to clipboard!'); }})
    .catch(() => {{ alert('Copy failed — select and copy manually.'); }});
}}
</script>

</body>
</html>"""

_DOCS_HTML = _build_html()
