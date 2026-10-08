"""AWS Service Quotas (core estate: quotas). A quota's id here is <service code>.<quota code>: what a need names as its
ciamProviderRef when no quota kind fits. The kinds, by the quota codes AWS's own quota tables give:

  vcpus                ec2.L-1216C47A                  Running On-Demand Standard (A, C, D, H, I, M, R, T, Z) instances
                                                       (vCPUs)
  public-ips           ec2.L-0263D0A3                  EC2-VPC Elastic IPs
  networks             vpc.L-F678F1CE                  VPCs per Region
  load-balancers       elasticloadbalancing.L-53DA6B97 Application Load Balancers per Region
  database-instances   rds.L-7B6409FD                  DB instances (RDS, Aurora, Neptune, DocumentDB)
  kubernetes-clusters  eks.L-1194D53C                  Clusters

Fetched (`opsdir import aws/quotas --run`, under the operator's own AWS login, its account given by
`aws sts get-caller-identity`) per region the record's AWS clouds needing quotas run in and per service the needs
name: `aws service-quotas list-service-quotas` (the values applied to the account) and
`list-aws-default-service-quotas` (AWS's defaults: list-service-quotas leaves out quotas without an applied value),
an applied value taking precedence. The quota codes are the commercial partition's; GovCloud's lists are read the same
way (a code its list lacks is named by the planner as a quota to confirm).

An increase the operator decided to request (ciamQuotaDecision request) is rendered as aws_servicequotas_service_quota
in the environment's root, at ciamQuotaRequested (else what the environments on the account and region need): it asks
AWS when the value is above the applied one (destroying it changes nothing). Pure."""
from functools import partial

from opsdir.core.contract import Importer, Prerequisite
from opsdir.core.directory import one, rdn_value
from opsdir.core.sources import json_document
from opsdir.domains.estate.quotas import (QuotaRow, limits_fetched, need_key, needed, quota_import, quota_needs,
                                          quota_regions, wanted_quotas)
from opsdir_format_terraform.hcl import block, tf_name
from .inventory import PROVIDER

KIND_QUOTAS = {"vcpus": "ec2.L-1216C47A", "public-ips": "ec2.L-0263D0A3", "networks": "vpc.L-F678F1CE",
               "load-balancers": "elasticloadbalancing.L-53DA6B97", "database-instances": "rds.L-7B6409FD",
               "kubernetes-clusters": "eks.L-1194D53C"}
QUOTA_KINDS = {q: k for k, q in KIND_QUOTAS.items()}
CALLER = "quotas/caller.json"
QUOTA = "aws_servicequotas_service_quota"


def quota_id(kind_or_id):
    """The AWS quota id (service.code) a need key names: a kind's, or the key itself."""
    return KIND_QUOTAS.get(kind_or_id, kind_or_id)


def quota_commands(d):
    """The provider commands fetching what the record's AWS environments need: the caller's account, then per region
    and service the applied and default quotas."""
    kinds, ids = wanted_quotas(d, PROVIDER)
    services = sorted({quota_id(k).split(".", 1)[0] for k in (*kinds, *ids)})
    regions = quota_regions(d, PROVIDER)
    return (((CALLER, ("aws", "sts", "get-caller-identity", "--output", "json")),) if regions and services else ()) + \
        tuple((f"quotas/{r}/{s}{suffix}.json", ("aws", "service-quotas", command, "--service-code", s, "--region", r,
                                                "--output", "json"))
              for r in regions for s in services
              for suffix, command in (("-defaults", "list-aws-default-service-quotas"), ("", "list-service-quotas")))


def _arn_parts(arn):
    """(region, account) of a Service Quotas ARN (arn:<partition>:servicequotas:<region>:<account>:<service>/<code>);
    a default quota's has no account."""
    parts = (arn or "").split(":")
    return (parts[3], parts[4]) if len(parts) > 5 else (None, None)


def _row(q):
    qid = f"{q.get('ServiceCode')}.{q.get('QuotaCode')}"
    value = q.get("Value")
    return QuotaRow(qid, int(round(value)) if isinstance(value, (int, float)) else None, q.get("QuotaName"), None,
                    QUOTA_KINDS.get(qid))


def quota_rows_of(docs):
    """{region: {quota id: QuotaRow}} of list-service-quotas / list-aws-default-service-quotas documents in order,
    a later one replacing an earlier one's quota (pass defaults first)."""
    found = [(_arn_parts(q.get("QuotaArn"))[0], _row(q)) for doc in docs for q in doc.get("Quotas") or ()
             if isinstance(q, dict) and q.get("ServiceCode") and q.get("QuotaCode")]
    regions = dict.fromkeys(r for r, _ in found if r)
    return {r: {row.id: row for region, row in found if region == r and row.value is not None} for r in regions}


def _account(docs, caller):
    applied = next((a for doc in docs for q in doc.get("Quotas") or () if isinstance(q, dict)
                    for _, a in (_arn_parts(q.get("QuotaArn")),) if a), None)
    return (caller or {}).get("Account") or applied


def read_quotas(files, d, patterns, at=None):
    """Imported: the quota catalogs of the account the export is of (sts get-caller-identity, else the applied
    quotas' ARNs) in each region the lists cover, defaults first and applied values over them. Refused when nothing
    tells the account."""
    docs = {p: json_document(t, dict) for p, t in sorted(files.items())}
    lists = {p: doc for p, doc in docs.items() if doc is not None and "Quotas" in doc}
    ordered = [doc for p, doc in sorted(lists.items(), key=lambda pd: (not pd[0].endswith("-defaults.json"), pd[0]))]
    caller = next((doc for doc in docs.values() if doc is not None and "Account" in doc), None)
    account = _account(ordered, caller)
    if account is None:
        raise SystemExit("aws/quotas: nothing in the export tells the account (add `aws sts get-caller-identity "
                         f"--output json > {CALLER}`); nothing imported")
    imported = quota_import(d, PROVIDER, {(account, r): tuple(rows.values())
                                          for r, rows in quota_rows_of(ordered).items()})
    return imported._replace(notices=(*imported.notices, *(f"{p}: not Service Quotas output; not read"
                                                            for p, doc in docs.items()
                                                            if p not in lists and doc is not caller)))


QUOTAS = Importer("quotas", "the limits AWS grants the account in each region the record's AWS environments needing "
                            "quotas run in (Service Quotas: applied values over AWS's defaults)",
                  read_quotas, quota_commands)
PREREQUISITE = Prerequisite("aws-quotas", "AWS's quota limits for the accounts and regions whose environments record "
                                          "quota needs, for the planner's quota check", QUOTAS.name,
                            partial(limits_fetched, provider=PROVIDER))


def render_quota_requests(m):
    """aws_servicequotas_service_quota for each of environment m's needs whose increase the operator decided to
    request (at ciamQuotaRequested, else what the environments on the account and region need)."""
    return tuple(
        block("resource", [QUOTA, tf_name(f"{rdn_value(n)}_{key}")], [
            ("#", f"{key}: requested by decision (ciamQuotaDecision); the quota is the account's in this region"),
            ("service_code", qid.split(".", 1)[0]), ("quota_code", qid.split(".", 1)[1]),
            ("value", int(one(n, "ciamQuotaRequested") or needed(m, key)))])
        for n in quota_needs(m) if one(n, "ciamQuotaDecision") == "request"
        for key in (need_key(n),) for qid in (quota_id(key),) if "." in qid)
