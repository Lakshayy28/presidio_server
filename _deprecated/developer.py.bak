"""
Developer secrets & API key recognizers
────────────────────────────────────────
Covers credentials and tokens that appear in source code, config files, and
environment variables.  Only recognizers with distinctive prefixes or structural
patterns are included — generic env-var secrets are handled by
GenericApiKeyRecognizer and EnvVariableValueRecognizer.

  AwsAccessKeyRecognizer      AWS_ACCESS_KEY           – IAM access key IDs (AKIA/ASIA/ARIA)
  AwsSecretKeyRecognizer      AWS_SECRET_KEY           – 40-char IAM secret access keys
  GithubTokenRecognizer       GITHUB_TOKEN             – PATs, OAuth, fine-grained tokens
  GitlabTokenRecognizer       GITLAB_TOKEN             – Personal / project / deploy tokens
  SlackTokenRecognizer        SLACK_TOKEN              – Bot/user/app tokens + webhook URLs
  JwtTokenRecognizer          JWT_TOKEN                – JSON Web Tokens (three-part base64url)
  StripeKeyRecognizer         STRIPE_KEY               – sk_live/test, pk_live/test, rk_
  SendgridKeyRecognizer       SENDGRID_KEY             – SG.<22>.<43> format
  NpmTokenRecognizer          NPM_TOKEN                – npm_<36> + .npmrc _authToken
  VaultTokenRecognizer        HASHICORP_VAULT_TOKEN    – hvs./hvb./hvr./s. tokens
  GenericApiKeyRecognizer     GENERIC_API_KEY          – Any key/secret/password assignment
  BearerTokenRecognizer       BEARER_TOKEN             – Authorization: Bearer <token>
  PrivateKeyBlockRecognizer   PRIVATE_KEY_BLOCK        – PEM private key headers
  CertificateBlockRecognizer  CERTIFICATE_BLOCK        – PEM certificate / CSR headers
"""

from presidio_analyzer import Pattern, PatternRecognizer


class AwsAccessKeyRecognizer(PatternRecognizer):
    """AWS IAM Access Key IDs (AKIA / ASIA / ARIA prefixes)."""

    PATTERNS = [
        Pattern("AWS Access Key (IAM User)",    r"\bAKIA[0-9A-Z]{16}\b", 0.95),
        Pattern("AWS Access Key (Assumed Role)", r"\bASIA[0-9A-Z]{16}\b", 0.95),
        Pattern("AWS Access Key (Root)",        r"\bARIA[0-9A-Z]{16}\b", 0.9),
    ]
    CONTEXT = ["aws", "access key", "access_key_id", "aws_access_key_id", "amazon", "iam"]

    def __init__(self):
        super().__init__(
            supported_entity="AWS_ACCESS_KEY",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class AwsSecretKeyRecognizer(PatternRecognizer):
    """AWS IAM Secret Access Keys — 40-char base64-like strings in key-named assignments.

    Uses variable-length lookbehind so only the secret value is matched.
    """

    PATTERNS = [
        Pattern(
            "AWS Secret Key (assignment)",
            r"(?i)(?<=(?:aws_secret_access_key|aws_secret|secret_access_key)[\"']?\s{0,10}[:=]\s{0,10}[\"']?)[A-Za-z0-9/+]{40}",
            0.95,
        ),
    ]
    CONTEXT = ["aws_secret", "secret_access_key", "aws_secret_access_key", "aws secret"]

    def __init__(self):
        super().__init__(
            supported_entity="AWS_SECRET_KEY",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class GithubTokenRecognizer(PatternRecognizer):
    """GitHub personal access tokens, OAuth tokens, fine-grained PATs, and app tokens."""

    PATTERNS = [
        Pattern("GitHub PAT (classic)",          r"\bghp_[A-Za-z0-9]{36}\b",            0.97),
        Pattern("GitHub OAuth Token",            r"\bgho_[A-Za-z0-9]{36}\b",            0.97),
        Pattern("GitHub User-to-Server",         r"\bghu_[A-Za-z0-9]{36}\b",            0.97),
        Pattern("GitHub Server-to-Server",       r"\bghs_[A-Za-z0-9]{36}\b",            0.97),
        Pattern("GitHub Refresh Token",          r"\bghr_[A-Za-z0-9]{76}\b",            0.97),
        Pattern("GitHub Fine-Grained PAT",       r"\bgithub_pat_[A-Za-z0-9_]{82}\b",    0.97),
    ]
    CONTEXT = ["github", "git", "token", "personal access", "oauth", "GITHUB_TOKEN"]

    def __init__(self):
        super().__init__(
            supported_entity="GITHUB_TOKEN",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class GitlabTokenRecognizer(PatternRecognizer):
    """GitLab personal access tokens, project tokens, deploy tokens, and agent tokens."""

    PATTERNS = [
        Pattern("GitLab Personal Access Token", r"\bglpat-[A-Za-z0-9_\-]{20,}\b",   0.97),
        Pattern("GitLab Deploy Token",          r"\bgldt-[A-Za-z0-9_\-]{20,}\b",    0.97),
        Pattern("GitLab Runner Token",          r"\bglrt-[A-Za-z0-9_\-]{20,}\b",    0.97),
        Pattern("GitLab OAuth App Secret",      r"\bgloas-[A-Za-z0-9_\-]{64}\b",    0.97),
        Pattern("GitLab CI Build Token",        r"\bglcbt-[A-Za-z0-9_\-]{20,}\b",   0.9),
        Pattern("GitLab Feed/Trigger Token",    r"\bglft-[A-Za-z0-9_\-]{20,}\b",    0.9),
        Pattern("GitLab Pipeline Trigger",      r"\bglptt-[A-Za-z0-9_\-]{20,}\b",   0.97),
        Pattern("GitLab Agent Token",           r"\bglagent-[A-Za-z0-9_\-]{50,}\b", 0.97),
    ]
    CONTEXT = ["gitlab", "git", "token", "runner", "ci", "GITLAB_TOKEN"]

    def __init__(self):
        super().__init__(
            supported_entity="GITLAB_TOKEN",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class SlackTokenRecognizer(PatternRecognizer):
    """Slack bot/user/app tokens and incoming webhook URLs."""

    PATTERNS = [
        Pattern("Slack Bot Token",             r"\bxoxb-[0-9A-Za-z\-]+\b",                                                          0.95),
        Pattern("Slack User Token",            r"\bxoxp-[0-9A-Za-z\-]+\b",                                                          0.95),
        Pattern("Slack App-Level Token",       r"\bxapp-[0-9A-Za-z\-]+\b",                                                          0.95),
        Pattern("Slack Webhook URL",           r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+",           0.97),
    ]
    CONTEXT = ["slack", "webhook", "token", "bot", "channel", "SLACK_TOKEN"]

    def __init__(self):
        super().__init__(
            supported_entity="SLACK_TOKEN",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class JwtTokenRecognizer(PatternRecognizer):
    """JSON Web Tokens — three base64url-encoded segments separated by dots."""

    PATTERNS = [
        Pattern(
            "JWT Token",
            r"\beyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*\b",
            0.85,
        ),
    ]
    CONTEXT = ["jwt", "bearer", "token", "authorization", "auth", "id_token", "access_token", "refresh_token"]

    def __init__(self):
        super().__init__(
            supported_entity="JWT_TOKEN",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class StripeKeyRecognizer(PatternRecognizer):
    """Stripe API keys — secret (sk_), publishable (pk_), and restricted (rk_)."""

    PATTERNS = [
        Pattern("Stripe Secret Key",      r"\bsk_(live|test)_[A-Za-z0-9]{24,}\b", 0.97),
        Pattern("Stripe Publishable Key", r"\bpk_(live|test)_[A-Za-z0-9]{24,}\b", 0.95),
        Pattern("Stripe Restricted Key",  r"\brk_(live|test)_[A-Za-z0-9]{24,}\b", 0.97),
    ]
    CONTEXT = ["stripe", "payment", "api key", "STRIPE_KEY", "STRIPE_SECRET"]

    def __init__(self):
        super().__init__(
            supported_entity="STRIPE_KEY",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class SendgridKeyRecognizer(PatternRecognizer):
    """SendGrid API keys (SG.<22>.<43> format)."""

    PATTERNS = [
        Pattern("SendGrid API Key", r"\bSG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}\b", 0.97),
    ]
    CONTEXT = ["sendgrid", "email", "api key", "SENDGRID_API_KEY"]

    def __init__(self):
        super().__init__(
            supported_entity="SENDGRID_KEY",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class NpmTokenRecognizer(PatternRecognizer):
    """NPM registry tokens (npm_<36> format)."""

    PATTERNS = [
        Pattern("NPM Token", r"\bnpm_[A-Za-z0-9]{36}\b", 0.97),
    ]
    CONTEXT = ["npm", "registry", "npmrc", "token", "package", "NODE_AUTH_TOKEN"]

    def __init__(self):
        super().__init__(
            supported_entity="NPM_TOKEN",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class VaultTokenRecognizer(PatternRecognizer):
    """HashiCorp Vault service, batch, and recovery tokens."""

    PATTERNS = [
        Pattern("Vault Service Token",  r"\bhvs\.[A-Za-z0-9]+\b",    0.95),
        Pattern("Vault Batch Token",    r"\bhvb\.[A-Za-z0-9]+\b",    0.95),
        Pattern("Vault Recovery Token", r"\bhvr\.[A-Za-z0-9]+\b",    0.95),
        Pattern("Vault Legacy Token",   r"\bs\.[A-Za-z0-9]{24}\b",   0.5),
    ]
    CONTEXT = ["vault", "hashicorp", "vault_token", "VAULT_TOKEN", "hvault"]

    def __init__(self):
        super().__init__(
            supported_entity="HASHICORP_VAULT_TOKEN",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class GenericApiKeyRecognizer(PatternRecognizer):
    """Generic high-entropy secrets assigned to common key/secret/password variable names.

    Uses variable-length lookbehinds (supported by the regex module that
    Presidio uses internally) so that only the VALUE portion is matched,
    preserving key names in the sanitized output.
    """

    PATTERNS = [
        Pattern(
            "API Key / Secret assignment",
            r"(?i)(?<=(?:api[_\-]?key|apikey|api[_\-]?secret|client[_\-]?secret|app[_\-]?secret|"
            r"access[_\-]?token|auth[_\-]?token|private[_\-]?key)[\"']?\s{0,5}[:=]\s{0,5}[\"']?)[A-Za-z0-9\-_/+]{20,}",
            0.75,
        ),
        Pattern(
            "Password assignment",
            r"(?i)(?<=(?:password|passwd|pwd|db[_\-]?pass(?:word)?)[\"']?\s{0,5}[:=]\s{0,5}[\"']?)[^\s\"',;\n]{8,}",
            0.7,
        ),
        Pattern(
            "Generic secret/token assignment",
            r"(?i)(?<=\b(?:secret|token)(?:[-_.]\w+)*[\"']?\s{0,5}[:=]\s{0,5}[\"']?)[A-Za-z0-9\-_/+.]{16,}",
            0.55,
        ),
    ]
    CONTEXT = ["key", "secret", "api", "password", "token", "credential", "auth"]

    def __init__(self):
        super().__init__(
            supported_entity="GENERIC_API_KEY",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class BearerTokenRecognizer(PatternRecognizer):
    """Bearer tokens in Authorization headers or variable assignments."""

    PATTERNS = [
        Pattern(
            "Bearer Token (header)",
            r"(?i)(?:Authorization|Auth)\s*:\s*Bearer\s+([A-Za-z0-9\-._~+\/]+=*)",
            0.95,
        ),
        Pattern(
            "Bearer Token (assignment)",
            r"(?i)bearer\s+([A-Za-z0-9\-._~+\/]{20,}=*)",
            0.75,
        ),
    ]
    CONTEXT = ["authorization", "bearer", "auth", "header", "token"]

    def __init__(self):
        super().__init__(
            supported_entity="BEARER_TOKEN",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class PrivateKeyBlockRecognizer(PatternRecognizer):
    """PEM private key headers (RSA, EC, OpenSSH, DSA, PKCS#8, encrypted)."""

    PATTERNS = [
        Pattern(
            "PEM Private Key Block",
            r"-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+|ENCRYPTED\s+)?PRIVATE\s+KEY-----",
            0.99,
        ),
    ]
    CONTEXT = ["private key", "pem", "rsa", "ec", "ssh", "certificate", "tls", "ssl", "key file"]

    def __init__(self):
        super().__init__(
            supported_entity="PRIVATE_KEY_BLOCK",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class CertificateBlockRecognizer(PatternRecognizer):
    """PEM certificate and CSR block headers."""

    PATTERNS = [
        Pattern("PEM Certificate", r"-----BEGIN\s+CERTIFICATE-----",             0.95),
        Pattern("PEM CSR",         r"-----BEGIN\s+CERTIFICATE\s+REQUEST-----",   0.9),
    ]
    CONTEXT = ["certificate", "cert", "tls", "ssl", "x509", "pem", "ca bundle"]

    def __init__(self):
        super().__init__(
            supported_entity="CERTIFICATE_BLOCK",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )
