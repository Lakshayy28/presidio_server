"""
Infrastructure & environment configuration recognizers
───────────────────────────────────────────────────────
Covers secrets and sensitive identifiers that appear in infrastructure-as-code,
environment files, container configs, and Kubernetes manifests.

Presidio built-in IP_ADDRESS and URL cover general network identifiers.
These custom recognizers handle database connection strings, private network
addresses, and environment-variable secrets that Presidio cannot detect.

  DbConnectionStringRecognizer    DB_CONNECTION_STRING   – SQL/NoSQL connection URLs with credentials
  AzureConnectionStringRecognizer AZURE_CONN_STRING      – Azure Storage / ServiceBus / CosmosDB / SQL
  JdbcUrlRecognizer               JDBC_URL               – Java JDBC connection URLs
  RedisUrlRecognizer              REDIS_URL              – Redis/Valkey connection URIs
  MongoUrlRecognizer              MONGO_URL              – MongoDB standard + SRV URIs
  InternalHostnameRecognizer      INTERNAL_HOSTNAME      – *.internal, *.corp, *.prod, *.staging, etc.
  PrivateIpAddressRecognizer      PRIVATE_IP_ADDRESS     – RFC 1918 + loopback + link-local
  EnvVariableValueRecognizer      ENV_VARIABLE_VALUE     – .env assignments with sensitive values
"""

from presidio_analyzer import Pattern, PatternRecognizer


class DbConnectionStringRecognizer(PatternRecognizer):
    """SQL and NoSQL database connection strings with embedded credentials."""

    PATTERNS = [
        Pattern("PostgreSQL URL",   r"postgres(?:ql)?://[^\s\"'\n]+",           0.9),
        Pattern("MySQL URL",        r"mysql(?:\+[a-z]+)?://[^\s\"'\n]+",        0.9),
        Pattern("MSSQL URL",        r"mssql(?:\+[a-z]+)?://[^\s\"'\n]+",        0.9),
        Pattern("Oracle URL",       r"oracle(?:\+[a-z]+)?://[^\s\"'\n]+",       0.9),
        Pattern("SQLite URL",       r"sqlite(?:3)?:///[^\s\"'\n]+",             0.75),
    ]
    CONTEXT = ["database", "db", "connection", "dsn", "data source", "connection string", "sqlalchemy"]

    def __init__(self):
        super().__init__(
            supported_entity="DB_CONNECTION_STRING",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class AzureConnectionStringRecognizer(PatternRecognizer):
    """Azure service connection strings (Storage, Service Bus, Event Hub, CosmosDB, SQL)."""

    PATTERNS = [
        Pattern(
            "Azure Storage Connection String",
            r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[^;\"'\n]+(?:;[^\s\"'\n]*)?",
            0.97,
        ),
        Pattern(
            "Azure Service Bus / Event Hub",
            r"Endpoint=sb://[^;]+;SharedAccessKeyName=[^;]+;SharedAccessKey=[^;\"'\n]+",
            0.97,
        ),
        Pattern(
            "Azure CosmosDB",
            r"AccountEndpoint=https://[^;]+;AccountKey=[^;\"'\n]+",
            0.97,
        ),
        Pattern(
            "Azure SQL Connection String",
            r"(?i)Server=[^;]+;(?:Database|Initial Catalog)=[^;]+;(?:User Id|UID)=[^;]+;Password=[^;\"'\n]+",
            0.9,
        ),
    ]
    CONTEXT = ["azure", "connection string", "storage", "servicebus", "eventhub", "cosmos", "AZURE_STORAGE"]

    def __init__(self):
        super().__init__(
            supported_entity="AZURE_CONN_STRING",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class JdbcUrlRecognizer(PatternRecognizer):
    """Java JDBC connection URLs (may contain embedded credentials)."""

    PATTERNS = [
        Pattern(
            "JDBC URL",
            r"jdbc:(?:mysql|postgresql|oracle|sqlserver|db2|h2|mariadb|sybase|jtds):(?://)?[^\s\"'\n]+",
            0.88,
        ),
    ]
    CONTEXT = ["jdbc", "java", "datasource", "connection", "database", "spring.datasource", "hibernate"]

    def __init__(self):
        super().__init__(
            supported_entity="JDBC_URL",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class RedisUrlRecognizer(PatternRecognizer):
    """Redis / Valkey / Upstash / ElastiCache connection URIs."""

    PATTERNS = [
        Pattern(
            "Redis URL (with credentials)",
            r"redis(?:s)?://(?::[^@\s]+@|[^:@\s]+:[^@\s]+@)[^\s\"'\n]+",
            0.95,
        ),
        Pattern(
            "Redis URL (any)",
            r"redis(?:s)?://[^\s\"'\n]+",
            0.65,
        ),
    ]
    CONTEXT = ["redis", "cache", "valkey", "elasticache", "upstash", "REDIS_URL", "CELERY_BROKER"]

    def __init__(self):
        super().__init__(
            supported_entity="REDIS_URL",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class MongoUrlRecognizer(PatternRecognizer):
    """MongoDB standard and SRV connection URIs."""

    PATTERNS = [
        Pattern("MongoDB URL",     r"mongodb://[^\s\"'\n]+",         0.88),
        Pattern("MongoDB SRV URL", r"mongodb\+srv://[^\s\"'\n]+",    0.95),
    ]
    CONTEXT = ["mongodb", "mongo", "atlas", "database", "MONGO_URI", "MONGODB_URL"]

    def __init__(self):
        super().__init__(
            supported_entity="MONGO_URL",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class InternalHostnameRecognizer(PatternRecognizer):
    """Internal / private hostnames with enterprise environment suffixes."""

    PATTERNS = [
        Pattern(
            "Internal Hostname (.internal/.corp/.private)",
            r"\b[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.(?:internal|corp|private|intranet|local|lan)(?:\.[a-zA-Z0-9\-\.]+)?\b",
            0.78,
        ),
        Pattern(
            "Internal Hostname (env suffix)",
            r"\b[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.(?:prod|production|staging|stage|stg|dev|development|uat|qa|test|sandbox)(?:\.[a-zA-Z0-9\-\.]+)?\b",
            0.6,
        ),
    ]
    CONTEXT = ["host", "hostname", "server", "endpoint", "fqdn", "domain", "service", "DB_HOST"]

    def __init__(self):
        super().__init__(
            supported_entity="INTERNAL_HOSTNAME",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class PrivateIpAddressRecognizer(PatternRecognizer):
    """RFC 1918 private IPs, loopback (127.x), and link-local (169.254.x) addresses."""

    PATTERNS = [
        Pattern("Class A Private (10.x.x.x)",       r"\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",                          0.88),
        Pattern("Class B Private (172.16-31.x.x)",  r"\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b",           0.9),
        Pattern("Class C Private (192.168.x.x)",    r"\b192\.168\.\d{1,3}\.\d{1,3}\b",                             0.95),
        Pattern("Loopback (127.x.x.x)",             r"\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",                        0.8),
        Pattern("Link-Local (169.254.x.x)",          r"\b169\.254\.\d{1,3}\.\d{1,3}\b",                             0.75),
    ]
    CONTEXT = ["ip", "address", "host", "server", "network", "subnet", "gateway", "node", "ip address"]

    def __init__(self):
        super().__init__(
            supported_entity="PRIVATE_IP_ADDRESS",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class EnvVariableValueRecognizer(PatternRecognizer):
    """Environment variable assignments whose names suggest sensitive values.

    Uses variable-length lookbehinds (supported by the regex module that
    Presidio uses internally) so that only the VALUE portion is matched,
    preserving key names in the sanitized output.
    """

    PATTERNS = [
        Pattern(
            "Env Var (sensitive name + value)",
            r"(?m)(?<=(?:^|[\s;])[A-Z][A-Z0-9_]{2,}(?:SECRET|KEY|TOKEN|PASSWORD|PASS|PWD|CREDENTIAL|CERT|PRIVATE|API)\s{0,5}=\s{0,5}[\"']?)[^\s\"'\n]{8,}",
            0.82,
        ),
        Pattern(
            "Exported secret (shell)",
            r"(?im)(?<=export\s{1,10}[A-Z_]{3,}(?:SECRET|KEY|TOKEN|PASSWORD|PASS)\s{0,5}=\s{0,5}[\"']?)[^\s\"'\n]{8,}",
            0.85,
        ),
    ]
    CONTEXT = ["env", "environment", ".env", "export", "dotenv", "config", "envvar", "shell", "bash", "zsh"]

    def __init__(self):
        super().__init__(
            supported_entity="ENV_VARIABLE_VALUE",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )
