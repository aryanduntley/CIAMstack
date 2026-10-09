"""Compute domain schema: what the platform's servers and containers run, beyond its products. A server role's host
baseline and a workload are intent, the same in every environment; the compute an environment runs a role on (an
autoscaling group, a scale set), the managed Kubernetes cluster it runs workloads in and how it runs each workload
there (images, replicas, resources, storage: its workload binding) are bindings."""
from ...core.standard import AttributeDef, ClassDef, fragment
from .naming import QUANTITY, WORKLOAD_SECRET

ATTRIBUTES = (
    # ------------------------------------------------------------------ host baseline (per server role)
    AttributeDef(232, 'ciamOs', 'string', 'intent', True,
                 "The operating system a server role runs: distribution and version, as os-release names them"),
    AttributeDef(233, 'ciamJdk', 'string', 'intent', True,
                 'The Java runtime a server role runs: vendor and version'),
    AttributeDef(234, 'ciamTrustsCertificate', 'dn', 'intent', False,
                 "A certificate the role's Java truststore (cacerts) adds to the runtime's own: lost silently when a "
                 "server is rebuilt from a stock image"),
    AttributeDef(235, 'ciamTrustedFingerprint', 'string', 'observed', False,
                 'SHA-256 fingerprint of a certificate the truststore adds that the record holds no certificate for'),
    AttributeDef(236, 'ciamOsLimit', 'string', 'intent', False,
                 'A resource limit, as limits.conf writes it: domain type item value (ds soft nofile 65536)'),
    AttributeDef(237, 'ciamKernelSetting', 'string', 'intent', False,
                 'A kernel setting, as sysctl writes it: name=value'),
    AttributeDef(238, 'ciamHugePages', 'enum:always|madvise|never', 'intent', True,
                 'Transparent huge pages (directory servers and JVMs usually want never)'),
    AttributeDef(239, 'ciamFipsMode', 'bool', 'intent', True,
                 'Whether the OS runs in FIPS mode: it decides which crypto providers the products may use'),
    AttributeDef(240, 'ciamSelinuxMode', 'enum:enforcing|permissive|disabled', 'intent', True,
                 'SELinux mode'),
    AttributeDef(241, 'ciamHostAgent', 'string', 'intent', False,
                 "An agent on the role's servers: name and version (an EDR sensor, a vulnerability scanner, a log "
                 "forwarder, a cloud agent)"),
    AttributeDef(242, 'ciamServiceUnit', 'string', 'intent', False,
                 "A service unit of the role's servers: name, the user it runs as, its restart policy"),
    AttributeDef(243, 'ciamPinnedHost', 'string', 'observed', False,
                 'A name pinned in /etc/hosts: address and names. Pinned names are migration landmines'),
    AttributeDef(244, 'ciamSearchDomain', 'string', 'observed', False,
                 'A DNS search domain of the role\'s servers (resolv.conf)'),
    # ------------------------------------------------------------------ compute groups and clusters (per environment)
    AttributeDef(245, 'ciamImageBuild', 'string', 'binding', True,
                 'What builds the image a compute group runs (an image pipeline, a recipe, a template)'),
    AttributeDef(246, 'ciamMinSize', 'int', 'binding', True, 'Fewest instances a compute group scales to'),
    AttributeDef(247, 'ciamMaxSize', 'int', 'binding', True, 'Most instances a compute group scales to'),
    AttributeDef(248, 'ciamDesiredSize', 'int', 'binding', True, 'Instances a compute group runs'),
    AttributeDef(249, 'ciamSpansZone', 'string', 'binding', False,
                 'An availability zone a compute group, a cluster or a node pool places instances in'),
    AttributeDef(250, 'ciamMetadataTokens', 'bool', 'binding', True,
                 'Whether the instance metadata service requires session tokens: without them a '
                 'request forged through the server reads its credentials'),
    AttributeDef(251, 'ciamClusterVersion', 'string', 'binding', True, 'The Kubernetes version a cluster runs'),
    AttributeDef(252, 'ciamClusterAddon', 'string', 'binding', False,
                 'An add-on a managed cluster runs: name and version'),
    AttributeDef(253, 'ciamNodePool', 'string', 'binding', False,
                 "A cluster's node pool: name: instance size, min-max nodes"),
    # ------------------------------------------------------------------ workloads (containerized server roles)
    AttributeDef(254, 'ciamWorkloadKind', 'enum:statefulset|deployment|daemonset|other', 'intent', True,
                 'How a workload runs: a StatefulSet, a Deployment, a DaemonSet'),
    AttributeDef(255, 'ciamNamespace', 'string', 'intent', True, 'The Kubernetes namespace a workload runs in'),
    AttributeDef(256, 'ciamContainerImage', 'string', 'binding', False,
                 "A container image an environment runs for a workload: container=repository:tag or "
                 "container=repository@sha256:digest (sidecars included)"),
    AttributeDef(257, 'ciamStorageSize', 'string', 'binding', True,
                 'The persistent storage each replica claims, as Kubernetes writes it (100Gi)',
                 (("X-PATTERN", QUANTITY),)),
    AttributeDef(258, 'ciamStorageClass', 'string', 'binding', True,
                 'The storage class a workload claims its storage from in an environment'),
    AttributeDef(259, 'ciamServiceAccount', 'string', 'intent', True,
                 'The Kubernetes service account a workload runs as'),
    AttributeDef(260, 'ciamIdentityRole', 'string', 'intent', True,
                 "The binding role whose cloud identity a workload assumes (workload identity): each environment "
                 "binds it"),
    AttributeDef(261, 'ciamClusterRole', 'string', 'intent', True,
                 'The binding role of the cluster a workload runs in'),
    AttributeDef(262, 'ciamPodSecurity', 'string', 'intent', False,
                 "A security fact of a workload's pods: runAsNonRoot, readOnlyRootFilesystem, privileged, "
                 "level=restricted"),
    AttributeDef(263, 'ciamNetworkPolicy', 'string', 'intent', False,
                 'A network policy that selects a workload: its name and what it allows'),
    AttributeDef(264, 'ciamIngressHost', 'fqdn', 'contract', False,
                 "A host name an ingress serves a workload at"),
    AttributeDef(609, 'ciamWorkloadRole', 'string', 'intent', True,
                 "The binding role of a workload's workload binding: an environment that binds it runs the workload "
                 "on Kubernetes, with the binding's images, replicas, resources and storage"),
    AttributeDef(615, 'ciamWorkloadSecret', 'string', 'intent', False,
                 "A Kubernetes Secret key a workload reads and the secret role that fills it: "
                 "<secret name>/<key> <- <secret role> (each environment binds the role to its secret store's "
                 "reference; values never. Not key=role: a key named like a password would read as one)",
                 (("X-PATTERN", WORKLOAD_SECRET),)),
    # ------------------------------------------------------------------ workload bindings (per environment)
    AttributeDef(610, 'ciamWorkloadReplicas', 'int', 'binding', True,
                 'The replicas an environment runs of a workload'),
    AttributeDef(611, 'ciamCpuRequest', 'string', 'binding', True,
                 "The CPU a workload's main container requests, as Kubernetes writes it (500m, 2)",
                 (("X-PATTERN", QUANTITY),)),
    AttributeDef(612, 'ciamCpuLimit', 'string', 'binding', True,
                 "The CPU a workload's main container is limited to, as Kubernetes writes it",
                 (("X-PATTERN", QUANTITY),)),
    AttributeDef(613, 'ciamMemoryRequest', 'string', 'binding', True,
                 "The memory a workload's main container requests, as Kubernetes writes it (2Gi)",
                 (("X-PATTERN", QUANTITY),)),
    AttributeDef(614, 'ciamMemoryLimit', 'string', 'binding', True,
                 "The memory a workload's main container is limited to, as Kubernetes writes it",
                 (("X-PATTERN", QUANTITY),)),
)
CLASSES = (
    ClassDef(50, 'ciamHostBaseline', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamTargetRole'),
             ('ciamOs', 'ciamJdk', 'ciamTrustsCertificate', 'ciamTrustedFingerprint', 'ciamOsLimit',
              'ciamKernelSetting', 'ciamHugePages', 'ciamFipsMode', 'ciamSelinuxMode', 'ciamHostAgent',
              'ciamServiceUnit', 'ciamPinnedHost', 'ciamSearchDomain', 'ciamFoundOn'),
             "What a server role's servers run beyond its product: OS, Java runtime and truststore additions, "
             "limits, kernel settings, agents, service units"),
    ClassDef(51, 'ciamComputeGroup', 'ciamBinding', 'STRUCTURAL', ('ciamProviderRef', 'ciamTargetRole'),
             ('ciamImageRef', 'ciamImageBuild', 'ciamInstanceSize', 'ciamMinSize', 'ciamMaxSize', 'ciamDesiredSize',
              'ciamSpansZone', 'ciamMetadataTokens'),
             "Where an environment runs a server role's instances as a group (an autoscaling group, a scale set): "
             "image, size, scale, zones"),
    ClassDef(52, 'ciamCluster', 'ciamBinding', 'STRUCTURAL', ('ciamProviderRef',),
             ('ciamClusterVersion', 'ciamClusterAddon', 'ciamNodePool', 'ciamSpansZone', 'ciamSubnetRole'),
             'A managed Kubernetes cluster an environment runs workloads in: version, add-ons, node pools, the '
             'subnets its nodes sit in'),
    ClassDef(53, 'ciamWorkload', 'ciamObject', 'STRUCTURAL', ('cn', 'ciamWorkloadKind', 'ciamTargetRole'),
             ('ciamNamespace', 'ciamWorkloadRole', 'ciamServiceAccount', 'ciamIdentityRole', 'ciamClusterRole',
              'ciamPodSecurity', 'ciamNetworkPolicy', 'ciamWorkloadSecret', 'ciamSecretName', 'ciamIngressHost',
              'ciamRepoPath'),
             'A server role run as containers: how, where, with which identity, security and secrets'),
    ClassDef(130, 'ciamWorkloadBinding', 'ciamBinding', 'STRUCTURAL', (),
             ('ciamContainerImage', 'ciamWorkloadReplicas', 'ciamCpuRequest', 'ciamCpuLimit', 'ciamMemoryRequest',
              'ciamMemoryLimit', 'ciamStorageSize', 'ciamStorageClass', 'ciamProviderRef', 'ciamProductVersion'),
             "How an environment runs a workload on Kubernetes (its role is the workload's ciamWorkloadRole): "
             "images, the product version they run, replicas, resources, storage"),
)

FRAGMENT = fragment(ATTRIBUTES, CLASSES)
