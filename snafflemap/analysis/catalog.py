"""Built-in detector/extractor catalog and (later) custom-catalog loading."""

from __future__ import annotations

import tomllib
from pathlib import Path

from snafflemap.analysis.models import Catalog, Detector, Extractor

DETECTORS: tuple[Detector, ...] = (
    Detector(
        id="gpp-cpassword",
        label="GPP cpassword",
        category="credentials",
        why="AES-encrypted local-admin password in SYSVOL; the key is public.",
        action="gpp-decrypt '<cpassword>'",
        crackable=True,
        weight=30,
        remediation="Remove cpassword from SYSVOL GPP, rotate the account, apply MS14-025.",
        filename_patterns=(
            r"^(Groups|Services|ScheduledTasks|DataSources|Printers|Drives)\.xml$",
        ),
        context_patterns=("cpassword",),
    ),
    Detector(
        id="kdbx",
        label="KeePass database",
        category="credentials",
        why="KeePass vault; crackable offline if the master password is weak.",
        action="keepass2john file.kdbx > h && hashcat -m 13400 h wordlist",
        crackable=True,
        weight=25,
        remediation="Enforce a strong KeePass master password / key file.",
        ext=(".kdbx",),
    ),
    Detector(
        id="keepass-kdb",
        label="KeePass 1.x database",
        category="credentials",
        why="Legacy KeePass vault; crackable offline.",
        action="keepass2john file.kdb > h && hashcat -m 13400 h wordlist",
        crackable=True,
        weight=22,
        ext=(".kdb",),
    ),
    Detector(
        id="private-key",
        label="Private key",
        category="key",
        why="Private key material; may grant SSH/TLS/code-signing access.",
        action="Identify the key type; if encrypted, ssh2john/putty2john then hashcat.",
        crackable=True,
        weight=25,
        remediation="Rotate the key pair and revoke the exposed key.",
        ext=(".pem", ".key", ".ppk"),
        filename_patterns=(r"^id_(rsa|dsa|ecdsa|ed25519)$",),
        rule_names=("KeepInlinePrivateKey", "KeepSSHKeysByFileName"),
        context_patterns=(
            r"BEGIN [A-Z ]*PRIVATE KEY",
            r"PuTTY-User-Key-File",
            r"\bid_(rsa|dsa|ecdsa|ed25519)\b",
        ),
    ),
    Detector(
        id="pkcs12",
        label="PKCS#12 / PFX bundle",
        category="key",
        why="Certificate + private key bundle, often password protected.",
        action="pfx2john file.pfx > h && hashcat -m 13410 h wordlist",
        crackable=True,
        weight=22,
        ext=(".pfx", ".p12"),
    ),
    Detector(
        id="web-config-connstring",
        label="web.config connection string",
        category="database",
        why="ASP.NET config often holds DB credentials.",
        action="Read the connectionStrings section; reuse the DB creds.",
        weight=22,
        filename_patterns=(r"^web\.config$",),
        context_patterns=("connectionString", r"(?i)password\s*="),
    ),
    Detector(
        id="appsettings",
        label="appsettings.json secrets",
        category="config",
        why=".NET Core config may hold connection strings / API keys.",
        action="Read ConnectionStrings / secret values.",
        weight=18,
        filename_patterns=(r"^appsettings.*\.json$",),
        context_patterns=("ConnectionString", r"(?i)password", "Secret"),
    ),
    Detector(
        id="unattend",
        label="unattend / sysprep answer file",
        category="credentials",
        why="Provisioning answer files embed local admin passwords.",
        action="Read the <Password> element (may be base64).",
        weight=25,
        filename_patterns=(r"^(unattend|autounattend|sysprep)\.xml$",),
        context_patterns=("Password",),
        remediation="Strip credentials from answer files; rotate the account.",
    ),
    Detector(
        id="git-credentials",
        label="git stored credentials",
        category="source-control",
        why="git credential store keeps plaintext https creds.",
        action="Read user:pass from the URL.",
        weight=22,
        filename_patterns=(r"^\.git-credentials$",),
        path_patterns=(r"\\\.git\\",),
        context_patterns=(r"https?://[^:@\s/]+:[^@\s/]+@",),
    ),
    Detector(
        id="kubeconfig",
        label="kubeconfig",
        category="cloud",
        why="Kubernetes client config with tokens / client certs.",
        action="export KUBECONFIG=...; kubectl get pods",
        weight=20,
        path_patterns=(r"\\\.kube\\",),
        context_patterns=("client-key-data", "client-certificate-data", "token:"),
    ),
    Detector(
        id="aws-credentials",
        label="AWS credentials file",
        category="cloud",
        why="Long-term AWS access keys.",
        action="aws sts get-caller-identity with the keys.",
        weight=25,
        path_patterns=(r"\\\.aws\\",),
        context_patterns=("aws_secret_access_key", "AKIA"),
    ),
    Detector(
        id="azure-publishsettings",
        label="Azure publish settings",
        category="cloud",
        why="Azure deployment credentials.",
        action="Import the .publishsettings into Azure tooling.",
        weight=20,
        ext=(".publishsettings",),
    ),
    Detector(
        id="dotenv",
        label=".env secrets",
        category="config",
        why="Environment files commonly hold API keys and DB passwords.",
        action="Read SECRET/PASSWORD/TOKEN/KEY assignments.",
        weight=18,
        filename_patterns=(r"^\.env(\..+)?$",),
        context_patterns=("SECRET", "PASSWORD", "TOKEN", "KEY"),
    ),
    Detector(
        id="ps1-securestring",
        label="PowerShell inline credential",
        category="credentials",
        why="Scripts using ConvertTo-SecureString -AsPlainText embed passwords.",
        action="Read the plaintext passed to ConvertTo-SecureString.",
        weight=15,
        ext=(".ps1",),
        context_patterns=("ConvertTo-SecureString", "-AsPlainText"),
    ),
    Detector(
        id="rdp-file",
        label="RDP connection file",
        category="credentials",
        why="Saved RDP files may carry a DPAPI-encrypted password blob.",
        action="Decrypt the 'password 51:b:' blob with the user's DPAPI key.",
        weight=15,
        ext=(".rdp",),
        context_patterns=("password 51:b:",),
    ),
    Detector(
        id="database-file",
        label="Database file",
        category="database",
        why="Raw database file; may be readable offline.",
        action="Open with the matching DB engine / sqlite3.",
        weight=15,
        ext=(".mdf", ".sdf", ".sqlite", ".db"),
    ),
    Detector(
        id="backup-archive",
        label="Backup / archive",
        category="backup",
        why="Backups frequently contain configs and secrets.",
        action="Extract and triage the contents.",
        weight=12,
        ext=(".bak", ".zip", ".7z", ".gz", ".tar"),
    ),
    Detector(
        id="docker-config",
        label="Docker config.json",
        category="cloud",
        why="Docker registry auth tokens (base64 user:pass).",
        action="base64 -d the auth value.",
        weight=15,
        path_patterns=(r"\\\.docker\\",),
        context_patterns=(r'"auth"',),
    ),
)

EXTRACTORS: tuple[Extractor, ...] = (
    Extractor(
        id="gpp-cpassword",
        type="gpp-cpassword",
        regex=r'cpassword\s*=\s*["\'](?P<secret>[A-Za-z0-9+/=]+)["\']',
        crackable=True,
    ),
    Extractor(
        id="connstring-pwd",
        type="connection-string-password",
        regex=r"(?i)(?:password|pwd)\s*=\s*(?P<secret>[^;\s\"']{3,})",
    ),
    Extractor(
        id="assignment-pwd",
        type="password-assignment",
        regex=r"(?i)(?:password|passwd)\s*[:=]\s*[\"']?(?P<secret>[^\"'\s,;]{3,})",
    ),
    Extractor(
        id="aws-akia", type="aws-access-key", regex=r"(?P<secret>AKIA[0-9A-Z]{16})"
    ),
    Extractor(
        id="aws-secret",
        type="aws-secret-key",
        regex=r"(?i)aws_secret_access_key\s*=\s*(?P<secret>[A-Za-z0-9/+=]{40})",
    ),
    Extractor(
        id="private-key-block",
        type="private-key",
        regex=r"(?P<secret>-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----)",
        crackable=True,
    ),
    Extractor(
        id="git-cred-url",
        type="git-credential-url",
        regex=r"https?://(?P<user>[^:@\s/]+):(?P<secret>[^\s/]+)@(?P<host>[^@\s/]+)",
    ),
    Extractor(
        id="db-uri",
        type="db-uri",
        regex=r"(?:mongodb|postgres|postgresql|mysql|redis|amqp)://"
        r"(?P<user>[^:@\s]+):(?P<secret>[^\s]+)@(?P<host>[^@\s:/]+)",
    ),
)


def builtin_catalog() -> Catalog:
    """Return the built-in Catalog (detectors + extractors)."""
    return Catalog(detectors=DETECTORS, extractors=EXTRACTORS)


class CatalogError(Exception):
    """Raised when a custom catalog file is invalid."""


_DETECTOR_REQUIRED = ("id", "label", "category", "why", "action")
_EXTRACTOR_REQUIRED = ("id", "type", "regex")
_DETECTOR_TUPLE_FIELDS = (
    "filename_patterns",
    "ext",
    "path_patterns",
    "context_patterns",
    "rule_names",
)


def _build_detector(raw: dict) -> Detector:
    for key in _DETECTOR_REQUIRED:
        if key not in raw:
            raise CatalogError(
                f"detector {raw.get('id', '?')!r} missing required '{key}'"
            )
    kwargs = dict(raw)
    for f in _DETECTOR_TUPLE_FIELDS:
        if f in kwargs:
            kwargs[f] = tuple(kwargs[f])
    try:
        return Detector(**kwargs)
    except TypeError as exc:
        raise CatalogError(f"detector {raw.get('id')!r}: {exc}") from exc


def _build_extractor(raw: dict) -> Extractor:
    for key in _EXTRACTOR_REQUIRED:
        if key not in raw:
            raise CatalogError(
                f"extractor {raw.get('id', '?')!r} missing required '{key}'"
            )
    if "(?P<secret>" not in raw["regex"]:
        raise CatalogError(
            f"extractor {raw['id']!r} regex needs a 'secret' named group"
        )
    try:
        return Extractor(**raw)
    except TypeError as exc:
        raise CatalogError(f"extractor {raw.get('id')!r}: {exc}") from exc


def load_catalog(path) -> Catalog:
    """Load a TOML catalog and merge it over the built-ins (same id overrides).

    Raises CatalogError on malformed input.
    """
    path = Path(path)
    try:
        with path.open("rb") as fh:
            data = tomllib.load(fh)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise CatalogError(f"cannot read catalog {path}: {exc}") from exc

    custom_detectors = [_build_detector(d) for d in data.get("detector", [])]
    custom_extractors = [_build_extractor(e) for e in data.get("extractor", [])]

    det_by_id = {d.id: d for d in DETECTORS}
    for d in custom_detectors:
        det_by_id[d.id] = d
    ext_by_id = {e.id: e for e in EXTRACTORS}
    for e in custom_extractors:
        ext_by_id[e.id] = e

    return Catalog(
        detectors=tuple(det_by_id.values()),
        extractors=tuple(ext_by_id.values()),
    )
