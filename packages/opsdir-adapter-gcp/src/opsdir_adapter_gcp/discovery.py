"""Data discovery on Google Cloud (core estate: ciamDataDiscovery) as Sensitive Data Protection. Pure.

For each data discovery the platform team keeps (one someone else keeps is named in a comment): its own data types as
custom regular-expression info types of a google_data_loss_prevention_inspect_template (named by their names in upper
case), and a google_data_loss_prevention_discovery_config in the project and the cloud's region, running, profiling the
Cloud Storage buckets of the object stores it examines (a bucket-name regular expression) with that template. Profile
events (new, changed) go to the Pub/Sub topic of
the binding ciamFindingsRole names (ciamProviderRef projects/<p>/topics/<t>; another binding is a NOTE). Other stores it
examines (databases, volumes) are a comment: only Cloud Storage targets are rendered. It exports detailed profiles to
BigQuery only: a ciamResultsRole is a comment.

How often is the record's ciamRescanDays, never rounded (core estate discovery: rescan_plan). Sensitive Data Protection
refreshes profiles daily or monthly: 1 or 30 days (none recorded: monthly) is the config's own refresh, running. Any
other interval is a scheduler (decision 2514): the config is rendered PAUSED (Terraform ignores its status after
creation) with a daily refresh, and Cloud Scheduler (google_cloud_scheduler_job, daily at 06:00 UTC) starts a Workflows
workflow (google_workflows_workflow, terraform/discovery/sdp-rescan.yaml) that lists the buckets' file store profiles
and keeps the config RUNNING while it is due (a bucket never profiled, or whose last profile failed, or that many
calendar days since the oldest of the buckets' last successful profiles: core estate discovery's rescan_due) and PAUSED
otherwise, so it pauses again once every bucket has been profiled anew. Least privilege: the workflow's service account
holds a custom role with dlp.jobTriggers.get and .update (a discovery config is a job trigger to IAM) and
dlp.fileStoreProfiles.list; the scheduler's may only invoke workflows (roles/workflows.invoker: Workflows has no
per-workflow IAM). Its environment and labels carry the interval for the reader. Where the environment requires DoD
IL4 or IL5, Cloud Scheduler and Workflows aren't on Assured Workloads' lists (research note 2513): nothing is added,
the config keeps the refresh nearest the interval that is at least as often (daily under 30 days, monthly above), a
comment says so, and the plan names it (check_discovery_cadence). The plan names which mechanism applies elsewhere.

Read back from Terraform state: google_data_loss_prevention_discovery_config (its buckets from the bucket-name
expression, daily or monthly as days, or the interval of the workflow whose CONFIG names it, its template's custom info
types as own data types, the topic its Pub/Sub notifications go to) -> data discovery (kind discovery)."""
import re

from opsdir.core.directory import get, is_kind, one, rdn_value, values
from opsdir.core.findings import findings, responsible
from opsdir.core.formats import YAML
from opsdir.core.inventory import of_types, resource
from opsdir.core.manifest import header
from opsdir.domains.estate.authorizations import required_levels
from opsdir.domains.estate.discovery import (custom_identifiers, destination, discovery_services, rescan_line,
                                             rescan_plan)
from opsdir_format_terraform.hcl import Block, comment, from_entry, ref, tf_block, tf_name
from .storage import bucket_of

TEMPLATE, CONFIG = "google_data_loss_prevention_inspect_template", "google_data_loss_prevention_discovery_config"
PARENT = "projects/${var.project_id}/locations/${var.region}"
EVENTS = ("NEW_PROFILE", "CHANGED_PROFILE")
MONTHLY = 30                        # days from which a monthly refresh is as often as the record asks
OFFERED = (1, MONTHLY)              # what Sensitive Data Protection's own refresh honours exactly
WORKFLOW, SCHEDULER = "google_workflows_workflow", "google_cloud_scheduler_job"
WORKFLOW_FILE = "discovery/sdp-rescan.yaml"
NO_SCHEDULER = frozenset(("dod-il4", "dod-il5"))     # levels whose Assured Workloads lists lack Scheduler, Workflows
RESCAN_PERMISSIONS = ("dlp.jobTriggers.get", "dlp.jobTriggers.update", "dlp.fileStoreProfiles.list")
API = "https://dlp.googleapis.com/v2/"
# The workflow every scheduled discovery runs (its own CONFIG, PARENT, RESCAN_DAYS and BUCKETS in its environment;
# CONFIG is the config's Terraform id, whose last part is the config's id under PARENT): the config should run exactly
# while it is due (a bucket never profiled or whose last profile failed, or the oldest of the buckets' last successful
# profiles RESCAN_DAYS or more whole UTC days old) and be paused otherwise; it is patched only when it differs. Days are
# whole days since the epoch (UTC), so a profile finished after the run's hour isn't a day short. The workflow keeps no
# state of its own (research note 2515: whether the service touches updateTime is unverified).
RESCAN_WORKFLOW = r"""main:
  steps:
    - init:
        assign:
          - parent: ${sys.get_env("PARENT")}
          - parts: ${text.split(sys.get_env("CONFIG"), "/")}
          - config: ${parent + "/discoveryConfigs/" + parts[len(parts) - 1]}
          - days: ${int(sys.get_env("RESCAN_DAYS"))}
          - buckets: ${text.split(sys.get_env("BUCKETS"), ",")}
          - today: ${int(sys.now()) // 86400}
          - oldest: -1
          - unprofiled: false
    - read_config:
        call: http.get
        args:
          url: ${"%(api)s" + config}
          auth:
            type: OAuth2
        result: cfg
    - each_bucket:
        for:
          value: bucket
          in: ${buckets}
          steps:
            - list:
                call: http.get
                args:
                  url: ${"%(api)s" + parent + "/fileStoreDataProfiles"}
                  auth:
                    type: OAuth2
                  query:
                    filter: '${"file_store_path = \"gs://" + bucket + "\""}'
                result: page
            - found:
                assign:
                  - profiles: ${default(map.get(page.body, "fileStoreDataProfiles"), [])}
            - none:
                switch:
                  - condition: ${len(profiles) == 0 or not ("profileLastGenerated" in profiles[0])}
                    assign:
                      - unprofiled: true
                    next: continue
            - outcome:
                assign:
                  - attempt: ${default(map.get(profiles[0], "profileStatus"), {})}
                  - code: ${default(map.get(default(map.get(attempt, "status"), {}), "code"), 0)}
            - failed:
                switch:
                  - condition: ${code != 0}
                    assign:
                      - unprofiled: true
                    next: continue
            - generated:
                assign:
                  - day: ${int(time.parse(profiles[0].profileLastGenerated)) // 86400}
            - older:
                switch:
                  - condition: ${oldest == -1 or day < oldest}
                    assign:
                      - oldest: ${day}
    - decide:
        assign:
          - due: ${unprofiled or oldest == -1 or today - oldest >= days}
          - wanted: PAUSED
    - when_due:
        switch:
          - condition: ${due}
            assign:
              - wanted: RUNNING
    - unchanged:
        switch:
          - condition: ${cfg.body.status == wanted}
            next: done
    - set_status:
        call: http.patch
        args:
          url: ${"%(api)s" + config}
          auth:
            type: OAuth2
          body:
            discoveryConfig:
              status: ${wanted}
            updateMask: status
    - done:
        return: ${wanted}
""" % {"api": API}


def _binding(m, role):
    return next((x for x in m.bindings if one(x, "ciamBindingRole") == role), None)


def _buckets(m, s):
    """(Cloud Storage buckets of the stores discovery s examines, the roles that aren't buckets)."""
    found = [(r, b) for r in values(s, "ciamScansRole") for b in (_binding(m, r),)]
    names = [bucket_of(one(b, "ciamStorageRef")) if b is not None and is_kind(m.d, b, "ciamObjectStore") else None
             for _, b in found]
    return [x for x in names if x], [r for (r, _), x in zip(found, names) if not x]


def info_type(name):
    """The custom info type name of an own data type (cui-marking -> CUI_MARKING)."""
    return re.sub(r"[^A-Z0-9_]", "_", name.upper())


def _template(s, n):
    own = custom_identifiers(s)
    return (tf_block("resource", [TEMPLATE, n], [
        ("parent", PARENT), ("template_id", f"ciam-{rdn_value(s)}"),
        ("display_name", f"{rdn_value(s)}: own data types"),
        ("inspect_config", Block(tuple(("custom_info_types", Block((
            ("info_type", Block((("name", info_type(name)),))), ("likelihood", "LIKELY"),
            ("regex", Block((("pattern", rx),)))))) for name, rx in own)))]),) if own else ()


def scheduler_blocked(m):
    """Whether environment m requires an authorization level whose Assured Workloads lists lack Cloud Scheduler and
    Workflows (DoD IL4, IL5)."""
    return bool(NO_SCHEDULER & set(required_levels(m)))


def scheduled(m, s):
    """Whether data discovery s of environment m is rendered with the scheduler (an interval the refresh doesn't offer,
    where Scheduler and Workflows may run)."""
    plan = rescan_plan(s, OFFERED)
    return plan is not None and not plan.native and not scheduler_blocked(m)


def _refresh(m, s):
    """(refresh frequency, status, comments) of data discovery s's config."""
    plan = rescan_plan(s, OFFERED)
    d = plan.days if plan is not None else MONTHLY
    frequency = "UPDATE_FREQUENCY_MONTHLY" if d >= MONTHLY else "UPDATE_FREQUENCY_DAILY"
    if plan is None or plan.native:
        return frequency, "RUNNING", ()
    if scheduled(m, s):
        return "UPDATE_FREQUENCY_DAILY", "PAUSED", (
            comment(f"{rdn_value(s)}: every {d} days: Sensitive Data Protection refreshes daily or monthly, so the "
                    f"config stays paused and workflow {workflow_name(s)} resumes it daily once {d} days have passed "
                    "since the buckets' last successful profiles, and pauses it once they are profiled again"),)
    return frequency, "RUNNING", (
        comment(f"{rdn_value(s)}: every {d} days: Sensitive Data Protection refreshes daily or monthly, and Cloud "
                "Scheduler and Workflows aren't on Assured Workloads' DoD IL4/IL5 supported products: profiled "
                f"{'daily' if frequency.endswith('DAILY') else 'monthly'}, more often than the record asks"),)


def workflow_name(s):
    """The rescan workflow (and its scheduler job) of data discovery s: sdp-rescan-<name>, lower case."""
    return re.sub(r"[^a-z0-9-]", "-", f"sdp-rescan-{rdn_value(s).lower()}")[:64]


def _account_id(s, suffix):
    base = re.sub(r"[^a-z0-9-]", "-", f"rescan-{rdn_value(s).lower()}")
    return f"{base[:29 - len(suffix)].rstrip('-')}-{suffix}"


def _scheduler(s, n, buckets):
    """The scheduler of data discovery s (blocks named n_*): service accounts, the workflow's custom role and grants,
    the workflow and its daily Cloud Scheduler job."""
    cn, name = rdn_value(s), workflow_name(s)
    worker, starter = f"{n}_rescan", f"{n}_rescan_scheduler"
    return (tf_block("resource", ["google_service_account", worker], [
                ("account_id", _account_id(s, "wf")), ("display_name", f"{cn}: resumes and pauses its discovery")]),
            tf_block("resource", ["google_project_iam_custom_role", n], [
                ("role_id", f"ciamSdpRescan_{n}"), ("title", f"{cn}: rescan discovery"),
                ("permissions", list(RESCAN_PERMISSIONS))]),
            tf_block("resource", ["google_project_iam_member", worker], [
                ("project", ref("var.project_id")), ("role", ref(f"google_project_iam_custom_role.{n}.name")),
                ("member", f"serviceAccount:${{google_service_account.{worker}.email}}")]),
            tf_block("resource", ["google_service_account", starter], [
                ("account_id", _account_id(s, "run")), ("display_name", f"{cn}: starts its rescan workflow")]),
            tf_block("resource", ["google_project_iam_member", starter], [
                ("#", "Workflows has no per-workflow IAM: invoking is granted on the project"),
                ("project", ref("var.project_id")), ("role", "roles/workflows.invoker"),
                ("member", f"serviceAccount:${{google_service_account.{starter}.email}}")]),
            tf_block("resource", [WORKFLOW, n], [
                ("name", name), ("region", ref("var.region")),
                ("description", f"Resumes and pauses discovery {cn} every {rescan_plan(s, OFFERED).days} days"),
                ("service_account", ref(f"google_service_account.{worker}.id")),
                ("source_contents", ref(f'file("${{path.module}}/{WORKFLOW_FILE}")')),
                ("user_env_vars", {"CONFIG": ref(f"{CONFIG}.{n}.id"), "PARENT": PARENT,
                                   "RESCAN_DAYS": str(rescan_plan(s, OFFERED).days), "BUCKETS": ",".join(buckets)}),
                ("labels", {"realizes": re.sub(r"[^a-z0-9_-]", "-", cn.lower()),
                            "rescan-days": str(rescan_plan(s, OFFERED).days)})]),
            tf_block("resource", [SCHEDULER, n], [
                ("name", name), ("region", ref("var.region")), ("schedule", "0 6 * * *"), ("time_zone", "Etc/UTC"),
                ("http_target", Block((
                    ("http_method", "POST"),
                    ("uri", f"https://workflowexecutions.googleapis.com/v1/${{{WORKFLOW}.{n}.id}}/executions"),
                    ("oauth_token", Block((("service_account_email", ref(f"google_service_account.{starter}.email")),
                                           ("scope", "https://www.googleapis.com/auth/cloud-platform")))))))]))


def workflow_file(m):
    """The rescan workflow's YAML, with its do-not-edit header."""
    return header(m, "Workflows: resume and pause a Sensitive Data Protection discovery config every N days",
                  YAML) + RESCAN_WORKFLOW


def _topic(m, s):
    dest = destination(m, s, "ciamFindingsRole")
    pref = one(dest, "ciamProviderRef") if dest is not None else None
    return dest, (pref if pref and "/topics/" in pref else None)


def _config(m, s):
    cn, n = rdn_value(s), tf_name(rdn_value(s))
    buckets, others = _buckets(m, s)
    frequency, status, note = _refresh(m, s)
    dest, topic = _topic(m, s)
    notes = (*note,
             *((comment(f"{cn}: only Cloud Storage targets are rendered: {', '.join(others)} not examined here"),)
               if others else ()),
             *((comment(f"NOTE: {cn}'s findings to {one(s, 'ciamFindingsRole')}: not rendered: {rdn_value(dest)} names "
                        "no Pub/Sub topic (ciamProviderRef projects/<p>/topics/<t>)"),)
               if dest is not None and not topic else ()),
             *((comment(f"{cn}: Sensitive Data Protection exports detailed profiles to BigQuery only: "
                        f"{one(s, 'ciamResultsRole')} isn't written to"),) if one(s, "ciamResultsRole") else ()))
    if not buckets:
        return (*notes, comment(f"NOTE: data discovery {cn}: no discovery config: it examines no Cloud Storage bucket "
                                "here"))
    regex = "^(" + "|".join(re.escape(b) for b in buckets) + ")$"
    return (*notes, *_template(s, n), tf_block("resource", [CONFIG, n], [
        ("parent", PARENT), ("location", ref("var.region")), ("display_name", cn), ("status", status),
        *((("inspect_templates", [ref(f"{TEMPLATE}.{n}.id")]),) if custom_identifiers(s) else ()),
        ("targets", Block((("cloud_storage_target", Block((
            ("filter", Block((("collection", Block((("include_regexes", Block((("patterns", Block((
                ("cloud_storage_regex", Block((("project_id_regex", "^${var.project_id}$"),
                                               ("bucket_name_regex", regex)))),))),))),))),))),
            ("generation_cadence", Block((("refresh_frequency", frequency),)))))),))),
        *(("actions", Block((("pub_sub_notification", Block((("topic", topic), ("event", e)))),)))
          for e in (EVENTS if topic else ())),
        *((("lifecycle", Block((("ignore_changes", [ref("status")]),))),) if status == "PAUSED" else ())]),
        *(_scheduler(s, n, buckets) if status == "PAUSED" else ()))


def render_discovery(m):
    """(HCL and comments, {path: file}) for environment m's data discovery (whoever keeps each service, stamped with
    its entry: the render places it by keeper): the rescan workflow when one is used (carried into a keeper root that
    reads it)."""
    kept = discovery_services(m)
    hcl = tuple(x for s in kept for x in from_entry(s.dn, _config(m, s)))
    used = any(scheduled(m, s) and _buckets(m, s)[0] for s in kept)
    return hcl, ({f"terraform/{WORKFLOW_FILE}": workflow_file(m)} if used else {})


def check_discovery_cadence(ctx):
    """How each data discovery the target keeps honours its interval (OK lines: the refresh, or the scheduler); an
    action for one whose interval can't be honoured exactly where the target requires DoD IL4 or IL5."""
    m = ctx.dst
    kept = [(s, rescan_plan(s, OFFERED)) for s in discovery_services(m) if not one(s, "ciamManagedBy")]
    kept = [(s, plan) for s, plan in kept if plan is not None]
    blocked = [(s, plan) for s, plan in kept if not plan.native and scheduler_blocked(m)]
    return findings(
        actions=[("Data discovery", f"{m.label}'s data discovery `{rdn_value(s)}` asks for every {plan.days} days: "
                                    "Sensitive Data Protection refreshes daily or monthly, and Cloud Scheduler and "
                                    "Workflows aren't on Assured Workloads' DoD IL4/IL5 supported products, so it is "
                                    f"profiled {'daily' if plan.days < MONTHLY else 'monthly'} (more often than "
                                    "asked). Accept it, or record an interval the refresh offers (1 or 30).",
                  responsible(ctx.d, s, m.env), ctx.cutover) for s, plan in blocked],
        ok=tuple(rescan_line(m, s, plan, f"the discovery config's own {'daily' if plan.days == 1 else 'monthly'} "
                                         "refresh",
                             f"Cloud Scheduler starts workflow {workflow_name(s)} daily, which resumes the paused "
                             f"config once {plan.days} days have passed since the buckets' last successful profiles")
                 for s, plan in kept if (s, plan) not in blocked))


# ------------------------------------------------------------------ read back
def _first(v):
    return (v or [{}])[0] or {}


def _regex_buckets(rx):
    """The bucket names a ^(a|b)$ expression names (escapes undone), else ()."""
    found = re.fullmatch(r"\^\((.*)\)\$", rx or "")
    return tuple(re.sub(r"\\(.)", r"\1", b) for b in found.group(1).split("|")) if found else ()


def _config_buckets(a):
    target = _first(_first(a.get("targets")).get("cloud_storage_target"))
    patterns = _first(_first(_first(target.get("filter")).get("collection")).get("include_regexes")).get("patterns")
    return tuple(dict.fromkeys(b for p in patterns or () for b in _regex_buckets(
        _first(p.get("cloud_storage_regex")).get("bucket_name_regex")))), target


def _own(templates, a):
    """name: regex of the custom info types of the templates a discovery config uses."""
    used = [templates[t] for t in a.get("inspect_templates") or () if t in templates]
    return tuple(f"{_first(c.get('info_type')).get('name', '').lower().replace('_', '-')}: "
                 f"{_first(c.get('regex')).get('pattern')}"
                 for t in used for c in _first(t.get("inspect_config")).get("custom_info_types") or ()
                 if _first(c.get("regex")).get("pattern"))


def _discovery(a, templates, intervals):
    buckets, target = _config_buckets(a)
    frequency = _first(target.get("generation_cadence")).get("refresh_frequency")
    scheduled_days = intervals.get(a.get("id"))
    topic = next((n.get("topic") for x in a.get("actions") or () for n in x.get("pub_sub_notification") or ()
                  if n.get("topic")), None)
    return resource("discovery", a.get("id"), {
        "ciamRescanDays": scheduled_days or {"UPDATE_FREQUENCY_DAILY": 1, "UPDATE_FREQUENCY_MONTHLY": MONTHLY}.get(
            frequency),
        "ciamCustomIdentifier": _own(templates, a)},
        links={"ciamScansRole": buckets, "ciamFindingsRole": topic}, name=a.get("display_name") or "sdp")


def _intervals(pairs):
    """{discovery config id: days} of the rescan workflows (their environment's CONFIG and RESCAN_DAYS)."""
    return {env["CONFIG"]: int(env["RESCAN_DAYS"]) for w in of_types(pairs, WORKFLOW)
            for env in (w.get("user_env_vars") or {},) if env.get("CONFIG") and env.get("RESCAN_DAYS")}


def discovery_resources(pairs):
    """Data discovery of (google type, attributes) pairs."""
    templates = {t.get("id"): t for t in of_types(pairs, TEMPLATE) if t.get("id")}
    intervals = _intervals(pairs)
    return tuple(_discovery(a, templates, intervals) for a in of_types(pairs, CONFIG) if a.get("id"))
