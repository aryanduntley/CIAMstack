"""configuration domain schema fragment: config files held in the record (OIDs pinned by number).

A bundle (code, scripts, templates, a package) is recorded by where it lives in version control and its SHA-256; its
content is not held in the record. A captured file is one entry (its format, where it lives in version control, the servers it is deployed to, its
layout) and one child entry per setting (its locator in the file, its value or a link to a value in the record).
"""
from ...core.standard import AttributeDef, ClassDef, fragment

ATTRIBUTES = (
    AttributeDef(173, 'ciamRepoPath', 'string', 'meta', True,
                 "Where the file lives in version control (the same for every environment)"),
    AttributeDef(174, 'ciamDeployPath', 'string', 'intent', True,
                 'Where the file is written on the servers it is deployed to'),
    AttributeDef(175, 'ciamCaptureLevel', 'enum:settings|whole-file|reference', 'meta', True,
                 'How the record holds the file: its settings one by one, its whole text, or only a reference to it'),
    AttributeDef(176, 'ciamSkeleton', 'string', 'intent', True,
                 "The file's text with each setting's place marked (settings), or its whole text (whole-file)"),
    AttributeDef(177, 'ciamSha256', 'string', 'observed', True,
                 'SHA-256 of the file as captured', (("X-PATTERN", "^[0-9a-f]{64}$"),)),
    AttributeDef(178, 'ciamCaptureProblem', 'string', 'meta', False,
                 'Why the file is not held as settings, or why a value was withheld'),
    AttributeDef(179, 'ciamLocator', 'string', 'intent', True,
                 "Where a setting is in its file (key, section.key, JSON pointer, XPath, dn|attribute)"),
    AttributeDef(180, 'ciamSettingValue', 'string', 'intent', True,
                 'The value of a setting'),
    AttributeDef(181, 'ciamSettingRaw', 'string', 'intent', True,
                 "The setting's text exactly as the file wrote it when captured (its quoting and type are kept)"),
    AttributeDef(182, 'ciamValueFrom', 'string', 'intent', True,
                 "Where the value comes from instead of a literal: role#attribute, a binding of the environment the "
                 "file is rendered for (a secret reference renders as ${secret:<ref-uri>})",
                 (("X-PATTERN", "^[A-Za-z0-9._-]+#[A-Za-z][A-Za-z0-9-]*$"),)),
    AttributeDef(183, 'ciamSecretRequired', 'bool', 'meta', True,
                 'The value was withheld at capture: it must come from a secret reference (ciamValueFrom)'),
    AttributeDef(184, 'ciamBundleKind', 'enum:code|script|template|package|dashboard|other', 'meta', True,
                 'What a bundle is'),
    AttributeDef(185, 'ciamBundleVersion', 'string', 'meta', True,
                 'The version of a bundle (a release, a tag, a package version)'),
)
CLASSES = (
    ClassDef(39, 'ciamConfigFile', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamFormat', 'ciamRepoPath', 'ciamCaptureLevel'),
             ('ciamTargetRole', 'ciamDeployPath', 'ciamSkeleton', 'ciamSha256', 'ciamCaptureProblem'),
             'A config file held in the record'),
    ClassDef(40, 'ciamConfigSetting', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamLocator'),
             ('ciamSettingValue', 'ciamSettingRaw', 'ciamValueFrom', 'ciamSecretRequired', 'ciamCaptureProblem'),
             'One setting of a captured config file'),
    ClassDef(41, 'ciamBundle', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamRepoPath', 'ciamBundleKind', 'ciamSha256'),
             ('ciamFormat', 'ciamBundleVersion', 'ciamTargetRole', 'ciamDeployPath'),
             'Code, scripts, templates or a package, deployed as a unit: recorded where it lives, not held in the record'),
)

FRAGMENT = fragment(ATTRIBUTES, CLASSES)
