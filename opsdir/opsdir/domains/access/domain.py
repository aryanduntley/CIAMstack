"""Access domain: who and what may act on the platform. Permission sets (neutral verbs on binding roles) and the
principals that hold them (workloads, deployers, operators, break-glass accounts) are intent; the cloud identity each
environment gives a principal, the organization guardrails over it and the ways operators come in are bindings,
read in by the cloud importers and rendered by the cloud adapters. Vendor-neutral."""
from ...core.contract import Domain, directory_report
from .identities import (ACCESS_PATH_HEADERS, GUARDRAIL_HEADERS, IDENTITY_HEADERS, access_path_rows,
                         check_identities, guardrail_rows, identity_rows)
from .imports import IMPORT_KINDS
from .principals import PRINCIPAL_HEADERS, check_principals, principal_rows
from .schema import FRAGMENT
from .settings import SETTINGS

DOMAIN = Domain(name="access", schema=FRAGMENT, required_roles=(), sql=(),
                reports={"principals": directory_report(PRINCIPAL_HEADERS, principal_rows, dated=True),
                         "identities": directory_report(IDENTITY_HEADERS, identity_rows),
                         "guardrails": directory_report(GUARDRAIL_HEADERS, guardrail_rows),
                         "access-paths": directory_report(ACCESS_PATH_HEADERS, access_path_rows)},
                checks=(check_principals, check_identities), order=62, vocabulary={},
                import_kinds=IMPORT_KINDS, settings=SETTINGS)
