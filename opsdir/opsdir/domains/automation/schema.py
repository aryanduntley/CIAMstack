"""Automation domain schema: the platform's hidden automation as entries. A job is intent (what runs, when, on what,
with which secrets, from which code), the same in every environment; where an environment runs a function or a
pipeline is a binding (ciamJobBinding), like any other per-environment resource."""
from ...core.standard import AttributeDef, ClassDef, fragment

ATTRIBUTES = (
    AttributeDef(219, 'ciamJobKind', 'enum:cron|timer|scheduled-task|function|pipeline|other', 'intent', True,
                 'What a job is: a cron entry, a systemd timer, a scheduled task, a serverless function, a pipeline'),
    AttributeDef(220, 'ciamSchedule', 'string', 'intent', False,
                 'When a job runs, as its system writes it (a cron expression, rate(1 hour), OnCalendar=daily, ...)'),
    AttributeDef(221, 'ciamTrigger', 'string', 'intent', False,
                 'What else starts a job: manual, push, pull-request, http, queue, event, boot, ...'),
    AttributeDef(222, 'ciamCommand', 'string', 'intent', True,
                 'What a job runs (a command line, a handler, an entry point); never stored when it holds a secret'),
    AttributeDef(223, 'ciamRunsAs', 'string', 'intent', True,
                 'The account a job runs as (an OS user, a service account, a runner)'),
    AttributeDef(224, 'ciamRuntime', 'string', 'intent', True,
                 "What a job runs in: a language runtime (python3.12), a runner image (ubuntu-24.04), ..."),
    AttributeDef(225, 'ciamJobRole', 'string', 'intent', True,
                 'The binding role that realizes the job in each environment (its function, its pipeline)'),
    AttributeDef(226, 'ciamUsesRole', 'string', 'intent', False,
                 'A binding role the job uses (a secret, a service name, a storage location): each environment binds it'),
    AttributeDef(227, 'ciamSecretName', 'string', 'meta', False,
                 "A secret the job expects by name in its own system (a CI secret, an environment variable from a "
                 "secret store): the name, never the value"),
    AttributeDef(228, 'ciamCodeBundle', 'dn', 'intent', True,
                 'The bundle holding the code the job runs'),
    AttributeDef(229, 'ciamRepoUrl', 'url', 'meta', True,
                 'The repository a job is defined in'),
    AttributeDef(230, 'ciamDeploysTo', 'string', 'intent', False,
                 'An environment a pipeline deploys to, as its CI system names it'),
    AttributeDef(231, 'ciamFoundOn', 'dn', 'observed', False,
                 'A server a job was found on'),
)
CLASSES = (
    ClassDef(48, 'ciamJob', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamJobKind'),
             ('ciamSchedule', 'ciamTrigger', 'ciamCommand', 'ciamRunsAs', 'ciamRuntime', 'ciamTargetRole',
              'ciamJobRole', 'ciamUsesRole', 'ciamSecretName', 'ciamCodeBundle', 'ciamRepoPath', 'ciamRepoUrl',
              'ciamDeploysTo', 'ciamFoundOn', 'ciamCriticality'),
             'A piece of the platform\'s automation: what runs, when, on what, with which secrets, from which code'),
    ClassDef(49, 'ciamJobBinding', 'ciamBinding', 'STRUCTURAL', ('ciamProviderRef',),
             ('ciamSchedule', 'ciamRuntime'),
             "Where an environment runs a job (a function, a pipeline): the provider's reference for it"),
)

FRAGMENT = fragment(ATTRIBUTES, CLASSES)
