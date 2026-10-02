"""Google Cloud secrets: gcp-sm:// references resolved at run time with gcloud (the value never touches disk), and the
Google Cloud credential forms the store refuses.

A reference is the secret's resource name: gcp-sm://projects/<project>/secrets/<name> (a global secret) or
gcp-sm://projects/<project>/locations/<location>/secrets/<name> (a regional one).
"""
import re

from opsdir.core.contract import SecretPattern

# Google Cloud credential forms the store refuses (SPEC R4)
SECRET_PATTERNS = (
    SecretPattern("gcp-service-account-key", r"\"private_key_id\"\s*:\s*\"[0-9a-f]{40}\"",
                  "A Google Cloud service account key (JSON key file)"),
    SecretPattern("gcp-api-key", r"AIza[0-9A-Za-z_-]{35}", "A Google Cloud API key"),
    SecretPattern("gcp-oauth-client-secret", r"GOCSPX-[0-9A-Za-z_-]{28}", "A Google OAuth client secret"),
)
_NAME = re.compile(r"^projects/([^/]+)/(?:locations/([^/]+)/)?secrets/([^/]+)$")


def secret_manager_command(rest):
    project, location, name = _NAME.match(rest).groups()
    where = f" --location='{location}'" if location else ""
    return f"gcloud secrets versions access latest --secret='{name}' --project='{project}'{where}"
