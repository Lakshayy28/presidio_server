from .financial import (
    CardCvvRecognizer,
    CardExpiryRecognizer,
)
from .developer import (
    AwsAccessKeyRecognizer,
    AwsSecretKeyRecognizer,
    GithubTokenRecognizer,
    GitlabTokenRecognizer,
    SlackTokenRecognizer,
    JwtTokenRecognizer,
    StripeKeyRecognizer,
    SendgridKeyRecognizer,
    NpmTokenRecognizer,
    VaultTokenRecognizer,
    GenericApiKeyRecognizer,
    BearerTokenRecognizer,
    PrivateKeyBlockRecognizer,
    CertificateBlockRecognizer,
)
from .infrastructure import (
    DbConnectionStringRecognizer,
    AzureConnectionStringRecognizer,
    JdbcUrlRecognizer,
    RedisUrlRecognizer,
    MongoUrlRecognizer,
    InternalHostnameRecognizer,
    PrivateIpAddressRecognizer,
    EnvVariableValueRecognizer,
)
from .cicd import (
    SonarqubeTokenRecognizer,
    OpenshiftTokenRecognizer,
    DockerRegistryCredentialRecognizer,
    HelmSecretRecognizer,
    TerraformTokenRecognizer,
    AnsibleVaultRecognizer,
    GcpServiceAccountKeyRecognizer,
    BitbucketAppPasswordRecognizer,
)

# Single list — pass to analyzer.registry.add_recognizer() at startup.
# Only recognizers with distinctive patterns (unique prefixes, structural
# formats) are registered here.  Generic key=value secrets are covered by
# GenericApiKeyRecognizer and EnvVariableValueRecognizer.
# Users can add additional recognizers via custom_recognizers in safechat-rules.yaml.
ALL_CUSTOM_RECOGNIZERS = [
    # ── Financial ─────────────────────────────────────────────────────────
    CardCvvRecognizer(),
    CardExpiryRecognizer(),
    # ── Developer secrets ─────────────────────────────────────────────────
    AwsAccessKeyRecognizer(),
    AwsSecretKeyRecognizer(),
    GithubTokenRecognizer(),
    GitlabTokenRecognizer(),
    SlackTokenRecognizer(),
    JwtTokenRecognizer(),
    StripeKeyRecognizer(),
    SendgridKeyRecognizer(),
    NpmTokenRecognizer(),
    VaultTokenRecognizer(),
    GenericApiKeyRecognizer(),
    BearerTokenRecognizer(),
    PrivateKeyBlockRecognizer(),
    CertificateBlockRecognizer(),
    # ── Infrastructure ────────────────────────────────────────────────────
    DbConnectionStringRecognizer(),
    AzureConnectionStringRecognizer(),
    JdbcUrlRecognizer(),
    RedisUrlRecognizer(),
    MongoUrlRecognizer(),
    InternalHostnameRecognizer(),
    PrivateIpAddressRecognizer(),
    EnvVariableValueRecognizer(),
    # ── CI/CD & Platform ─────────────────────────────────────────────────
    SonarqubeTokenRecognizer(),
    OpenshiftTokenRecognizer(),
    DockerRegistryCredentialRecognizer(),
    HelmSecretRecognizer(),
    TerraformTokenRecognizer(),
    AnsibleVaultRecognizer(),
    GcpServiceAccountKeyRecognizer(),
    BitbucketAppPasswordRecognizer(),
]

__all__ = ["ALL_CUSTOM_RECOGNIZERS"]
