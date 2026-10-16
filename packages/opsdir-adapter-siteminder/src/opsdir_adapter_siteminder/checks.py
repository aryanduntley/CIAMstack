"""The planner's checks for a plan whose source runs SiteMinder (Adapter.source_checks): the user directories whose
directory consumer the record doesn't hold. What stops being protected when the target doesn't run the agents that
protect it is the web access domain's check, over the realms projected onto the neutral protected-application layer
(neutral.py); the partnerships its identity service serves (the federation domain's check), its header contracts (the
edge domain's) and its source objects (governance) are checked by the core. Pure."""
from opsdir.core.directory import children, follow, one, rdn_value
from opsdir.core.findings import findings, responsible
from .naming import AGENT, USER_DIRECTORIES

AREA = "SiteMinder"


def realm_role(d, realm):
    """The server role a realm's agent runs on (a web agent when its agent names none)."""
    agent = follow(d, realm, "smAgent")
    return (one(agent, "ciamTargetRole") if agent is not None else None) or AGENT


def check_user_directories(ctx):
    """An action for every user directory SiteMinder binds to as an account no directory consumer records: the
    directory's consumers don't show it, so nobody tracks its retirement."""
    return findings(actions=[(
        AREA, f"SiteMinder's user directory `{rdn_value(u)}` binds as an account no directory consumer records: record "
        "the consumer (its bind DN, owner, migration status) and link it (smConsumer), so the directory's consumers "
        "show SiteMinder until it is retired.", responsible(ctx.d, u), ctx.cutover)
        for u in children(ctx.d, USER_DIRECTORIES, "smUserDirectory") if one(u, "smConsumer") is None])
