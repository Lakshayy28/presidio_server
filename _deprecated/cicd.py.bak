"""
CI/CD & container platform recognizers
───────────────────────────────────────
Focused set of CI/CD recognizers with distinctive token prefixes.
Generic env-var assignments (DOCKER_PASSWORD=, TERRAFORM_TOKEN=, etc.)
are already caught by GenericApiKeyRecognizer and EnvVariableValueRecognizer.

  SonarqubeTokenRecognizer            SONARQUBE_TOKEN             – sqp_/squ_/sqa_ tokens
  OpenshiftTokenRecognizer            OPENSHIFT_TOKEN             – OCP4 sha256~ tokens
  DockerRegistryCredentialRecognizer  DOCKER_REGISTRY_CREDENTIAL  – Docker config auth base64 entries
  HelmSecretRecognizer                HELM_SECRET                 – SOPS-encrypted Helm values
  TerraformTokenRecognizer            TERRAFORM_TOKEN             – Terraform Cloud atlasv1 tokens
  AnsibleVaultRecognizer              ANSIBLE_VAULT               – $ANSIBLE_VAULT AES256 blocks
  GcpServiceAccountKeyRecognizer      GCP_SA_KEY                  – GCP SA JSON key + service account emails
  BitbucketAppPasswordRecognizer      BITBUCKET_APP_PASSWORD      – ATBB / ATCTT Bitbucket tokens
"""

from presidio_analyzer import Pattern, PatternRecognizer


class SonarqubeTokenRecognizer(PatternRecognizer):
    """SonarQube and SonarCloud analysis / user / project tokens."""

    PATTERNS = [
        Pattern("SonarQube Analysis Token",  r"\bsqp_[A-Za-z0-9]{40}\b", 0.97),
        Pattern("SonarQube User Token",      r"\bsqu_[A-Za-z0-9]{40}\b", 0.97),
        Pattern("SonarQube Project Token",   r"\bsqa_[A-Za-z0-9]{40}\b", 0.97),
    ]
    CONTEXT = ["sonar", "sonarqube", "sonarcloud", "code analysis", "quality gate", "SONAR_TOKEN"]

    def __init__(self):
        super().__init__(
            supported_entity="SONARQUBE_TOKEN",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class OpenshiftTokenRecognizer(PatternRecognizer):
    """OpenShift / OCP API tokens (sha256~ format for OCP 4.x)."""

    PATTERNS = [
        Pattern(
            "OCP4 API Token (sha256~)",
            r"\bsha256~[A-Za-z0-9\-_]{43}\b",
            0.97,
        ),
    ]
    CONTEXT = ["openshift", "ocp", "oc login", "token", "kubeconfig", "namespace", "cluster", "OCP_TOKEN"]

    def __init__(self):
        super().__init__(
            supported_entity="OPENSHIFT_TOKEN",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class DockerRegistryCredentialRecognizer(PatternRecognizer):
    """Docker registry credentials in config.json and imagePullSecrets."""

    PATTERNS = [
        Pattern(
            "Docker auth base64 value",
            r'"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}"',
            0.88,
        ),
        Pattern(
            "Docker auths block",
            r'"auths"\s*:\s*\{[^}]*"auth"\s*:\s*"[A-Za-z0-9+/=]+"',
            0.93,
        ),
    ]
    CONTEXT = ["docker", "registry", "image", "pull secret", "dockerhub", "quay", "ecr", "gcr", "auths", "imagePullSecrets"]

    def __init__(self):
        super().__init__(
            supported_entity="DOCKER_REGISTRY_CREDENTIAL",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class HelmSecretRecognizer(PatternRecognizer):
    """SOPS-encrypted Helm secret values (helm-secrets plugin format)."""

    PATTERNS = [
        Pattern(
            "SOPS Encrypted Value",
            r"ENC\[AES[0-9]+_[A-Z]+,data:[A-Za-z0-9+/=]+,iv:[A-Za-z0-9+/=]+,tag:[A-Za-z0-9+/=]+\]",
            0.97,
        ),
    ]
    CONTEXT = ["helm", "sops", "helm-secrets", "values.yaml", "secrets.yaml", "chart", "encrypted"]

    def __init__(self):
        super().__init__(
            supported_entity="HELM_SECRET",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class TerraformTokenRecognizer(PatternRecognizer):
    """Terraform Cloud / HCP Terraform / TFE API tokens."""

    PATTERNS = [
        Pattern(
            "Terraform Cloud Token",
            r"\b[A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9]{67}\b",
            0.97,
        ),
    ]
    CONTEXT = ["terraform", "tfc", "tfe", "atlas", "hashicorp", "hcl", "provider", "backend", "remote state"]

    def __init__(self):
        super().__init__(
            supported_entity="TERRAFORM_TOKEN",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class AnsibleVaultRecognizer(PatternRecognizer):
    """Ansible Vault encrypted blocks (AES256 header + hex body)."""

    PATTERNS = [
        Pattern(
            "Ansible Vault Header",
            r"\$ANSIBLE_VAULT;[0-9.]+;AES256(?:;[^\n]*)?\n[0-9a-f\n]+",
            0.99,
        ),
    ]
    CONTEXT = ["ansible", "vault", "ansible-vault", "playbook", "encrypted", "ANSIBLE_VAULT_PASSWORD"]

    def __init__(self):
        super().__init__(
            supported_entity="ANSIBLE_VAULT",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class GcpServiceAccountKeyRecognizer(PatternRecognizer):
    """GCP service account JSON keys and service account email addresses."""

    PATTERNS = [
        Pattern(
            "GCP SA JSON type field",
            r'"type"\s*:\s*"service_account"',
            0.88,
        ),
        Pattern(
            "GCP SA email",
            r"\b[a-z0-9\-]+@[a-z0-9\-]+\.iam\.gserviceaccount\.com\b",
            0.95,
        ),
    ]
    CONTEXT = ["gcp", "google", "service account", "gcloud", "firebase", "bigquery", "gke", "cloud run"]

    def __init__(self):
        super().__init__(
            supported_entity="GCP_SA_KEY",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )


class BitbucketAppPasswordRecognizer(PatternRecognizer):
    """Bitbucket app passwords (ATBB) and repository access tokens (ATCTT)."""

    PATTERNS = [
        Pattern("Bitbucket App Password",  r"\bATBB[A-Za-z0-9]{28}\b",    0.97),
        Pattern("Bitbucket Access Token",  r"\bATCTT[A-Za-z0-9]{171,}\b", 0.97),
    ]
    CONTEXT = ["bitbucket", "atlassian", "app password", "bb", "stash", "pipeline", "BITBUCKET"]

    def __init__(self):
        super().__init__(
            supported_entity="BITBUCKET_APP_PASSWORD",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
        )
