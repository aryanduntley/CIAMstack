# Compute

*Domain · OID arc `1.3.6.1.4.1.32473.1` · 5 object classes · 42 attributes. Generated from the schema fragments by `opsdir/scripts/gen-schema-docs.py`: don't edit by hand. How to read it: [SCHEMA.md](../SCHEMA.md).*

Compute domain schema: what the platform's servers and containers run, beyond its products. A server role's host baseline and a workload are intent, the same in every environment; the compute an environment runs a role on (an autoscaling group, a scale set), the managed Kubernetes cluster it runs workloads in and how it runs each workload there (images, replicas, resources, storage: its workload binding) are bindings.

**Branches:** `ou=baselines,dc=ciam-ops`, `ou=workloads,dc=ciam-ops`

## Object classes

<a id="c-ciamcluster"></a>
### ciamCluster

A managed Kubernetes cluster an environment runs workloads in: version, add-ons, node pools, the subnets its nodes sit in

OID `1.3.6.1.4.1.32473.1.2.52` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamProviderRef`](infrastructure.md#a-ciamproviderref) | yes | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |
| [`ciamClusterVersion`](#a-ciamclusterversion) |  | `string` | single | The Kubernetes version a cluster runs |
| [`ciamClusterAddon`](#a-ciamclusteraddon) |  | `string` | multi | An add-on a managed cluster runs: name and version |
| [`ciamNodePool`](#a-ciamnodepool) |  | `string` | multi | A cluster's node pool: name: instance size, min-max nodes |
| [`ciamSpansZone`](#a-ciamspanszone) |  | `string` | multi | An availability zone a compute group, a cluster or a node pool places instances in |
| [`ciamSubnetRole`](network.md#a-ciamsubnetrole) |  | `string` | multi | Binding role of a subnet this applies to |

<a id="c-ciamcomputegroup"></a>
### ciamComputeGroup

Where an environment runs a server role's instances as a group (an autoscaling group, a scale set): image, size, scale, zones, the subnets its instances sit in; designed (rendered) or adopted (its provider ref)

OID `1.3.6.1.4.1.32473.1.2.51` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamTargetRole`](infrastructure.md#a-ciamtargetrole) | yes | `vocab` | single | Server role a service or rule targets |
| [`ciamProviderRef`](infrastructure.md#a-ciamproviderref) |  | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |
| [`ciamImageRef`](infrastructure.md#a-ciamimageref) |  | `string` | single | Machine image reference |
| [`ciamImageBuild`](#a-ciamimagebuild) |  | `string` | single | What builds the image a compute group runs (an image pipeline, a recipe, a template) |
| [`ciamInstanceSize`](infrastructure.md#a-ciaminstancesize) |  | `string` | single | Instance / VM size |
| [`ciamMinSize`](#a-ciamminsize) |  | `int` | single | Fewest instances a compute group scales to |
| [`ciamMaxSize`](#a-ciammaxsize) |  | `int` | single | Most instances a compute group scales to |
| [`ciamDesiredSize`](#a-ciamdesiredsize) |  | `int` | single | Instances a compute group runs |
| [`ciamSpansZone`](#a-ciamspanszone) |  | `string` | multi | An availability zone a compute group, a cluster or a node pool places instances in |
| [`ciamSubnetRole`](network.md#a-ciamsubnetrole) |  | `string` | multi | Binding role of a subnet this applies to |
| [`ciamMetadataTokens`](#a-ciammetadatatokens) |  | `bool` | single | Whether the instance metadata service requires session tokens: without them a request forged through the server reads its credentials |

<a id="c-ciamhostbaseline"></a>
### ciamHostBaseline

What a server role's servers run beyond its product: OS, Java runtime and truststore additions, limits, kernel settings, agents, service units

OID `1.3.6.1.4.1.32473.1.2.50` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamTargetRole`](infrastructure.md#a-ciamtargetrole) | yes | `vocab` | single | Server role a service or rule targets |
| [`ciamOs`](#a-ciamos) |  | `string` | single | The operating system a server role runs: distribution and version, as os-release names them |
| [`ciamJdk`](#a-ciamjdk) |  | `string` | single | The Java runtime a server role runs: vendor and version |
| [`ciamTrustsCertificate`](#a-ciamtrustscertificate) |  | `dn` | multi | A certificate the role's Java truststore (cacerts) adds to the runtime's own: lost silently when a server is rebuilt from a stock image |
| [`ciamTrustedFingerprint`](#a-ciamtrustedfingerprint) |  | `string` | multi | SHA-256 fingerprint of a certificate the truststore adds that the record holds no certificate for |
| [`ciamOsLimit`](#a-ciamoslimit) |  | `string` | multi | A resource limit, as limits.conf writes it: domain type item value (ds soft nofile 65536) |
| [`ciamKernelSetting`](#a-ciamkernelsetting) |  | `string` | multi | A kernel setting, as sysctl writes it: name=value |
| [`ciamHugePages`](#a-ciamhugepages) |  | `enum` | single | Transparent huge pages (directory servers and JVMs usually want never) |
| [`ciamFipsMode`](#a-ciamfipsmode) |  | `bool` | single | Whether the OS runs in FIPS mode: it decides which crypto providers the products may use |
| [`ciamSelinuxMode`](#a-ciamselinuxmode) |  | `enum` | single | SELinux mode |
| [`ciamHostAgent`](#a-ciamhostagent) |  | `string` | multi | An agent on the role's servers: name and version (an EDR sensor, a vulnerability scanner, a log forwarder, a cloud agent) |
| [`ciamServiceUnit`](#a-ciamserviceunit) |  | `string` | multi | A service unit of the role's servers: name, the user it runs as, its restart policy |
| [`ciamPinnedHost`](#a-ciampinnedhost) |  | `string` | multi | A name pinned in /etc/hosts: address and names. Pinned names are migration landmines |
| [`ciamSearchDomain`](#a-ciamsearchdomain) |  | `string` | multi | A DNS search domain of the role's servers (resolv.conf) |
| [`ciamFoundOn`](automation.md#a-ciamfoundon) |  | `dn` | multi | A server a job was found on |
| [`ciamHardeningProfile`](#a-ciamhardeningprofile) |  | `vocab` | single | A hardening profile the role's servers are configured to beyond the baseline (e.g. disa-stig), as the configuration-management adapter names it; applied alongside what the baseline records |
| [`ciamInEnvironment`](infrastructure.md#a-ciaminenvironment) |  | `dn` | multi | An environment a shared entry (a host baseline, a job) applies in; an overlay of it too. With neither this nor ciamOnProvider, the entry applies in every environment |
| [`ciamOnProvider`](infrastructure.md#a-ciamonprovider) |  | `vocab` | multi | A provider (a ciamCloudProvider value) in whose environments a shared entry (a host baseline, a job) applies |

<a id="c-ciamworkload"></a>
### ciamWorkload

A server role run as containers: how, where, with which identity, security and secrets

OID `1.3.6.1.4.1.32473.1.2.53` · structural · inherits [`ciamObject`](core.md#c-ciamobject)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`cn`](../SCHEMA.md#standard-cn) | yes | `string` |  | Common name / RDN |
| [`ciamWorkloadKind`](#a-ciamworkloadkind) | yes | `enum` | single | How a workload runs: a StatefulSet, a Deployment, a DaemonSet |
| [`ciamTargetRole`](infrastructure.md#a-ciamtargetrole) | yes | `vocab` | single | Server role a service or rule targets |
| [`ciamNamespace`](#a-ciamnamespace) |  | `string` | single | The Kubernetes namespace a workload runs in |
| [`ciamWorkloadRole`](#a-ciamworkloadrole) |  | `string` | single | The binding role of a workload's workload binding: an environment that binds it runs the workload on Kubernetes, with the binding's images, replicas, resources and storage |
| [`ciamServiceAccount`](#a-ciamserviceaccount) |  | `string` | single | The Kubernetes service account a workload runs as |
| [`ciamIdentityRole`](#a-ciamidentityrole) |  | `string` | single | The binding role whose cloud identity a workload assumes (workload identity): each environment binds it |
| [`ciamClusterRole`](#a-ciamclusterrole) |  | `string` | single | The binding role of the cluster a workload runs in |
| [`ciamPodSecurity`](#a-ciampodsecurity) |  | `string` | multi | A security fact of a workload's pods: runAsNonRoot, readOnlyRootFilesystem, privileged, level=restricted |
| [`ciamNetworkPolicy`](#a-ciamnetworkpolicy) |  | `string` | multi | A network policy that selects a workload: its name and what it allows |
| [`ciamWorkloadSecret`](#a-ciamworkloadsecret) |  | `string` | multi | A Kubernetes Secret key a workload reads and the secret role that fills it: <secret name>/<key> <- <secret role> (each environment binds the role to its secret store's reference; values never. Not key=role: a key named like a password would read as one) |
| [`ciamSecretName`](automation.md#a-ciamsecretname) |  | `string` | multi | A secret the job expects by name in its own system (a CI secret, an environment variable from a secret store): the name, never the value |
| [`ciamIngressHost`](#a-ciamingresshost) |  | `fqdn` | multi | A host name an ingress serves a workload at |
| [`ciamRepoPath`](configuration.md#a-ciamrepopath) |  | `string` | single | Where the file lives in version control (the same for every environment) |

<a id="c-ciamworkloadbinding"></a>
### ciamWorkloadBinding

How an environment runs a workload on Kubernetes (its role is the workload's ciamWorkloadRole): images, the product version they run, replicas, resources, storage, where its configuration profile is kept

OID `1.3.6.1.4.1.32473.1.2.130` · structural · inherits [`ciamBinding`](infrastructure.md#c-ciambinding)

| Field | Required | Type | Values | Description |
| --- | --- | --- | --- | --- |
| [`ciamContainerImage`](#a-ciamcontainerimage) |  | `string` | multi | A container image an environment runs for a workload: container=repository:tag or container=repository@sha256:digest (sidecars included) |
| [`ciamWorkloadReplicas`](#a-ciamworkloadreplicas) |  | `int` | single | The replicas an environment runs of a workload |
| [`ciamCpuRequest`](#a-ciamcpurequest) |  | `string` | single | The CPU a workload's main container requests, as Kubernetes writes it (500m, 2) |
| [`ciamCpuLimit`](#a-ciamcpulimit) |  | `string` | single | The CPU a workload's main container is limited to, as Kubernetes writes it |
| [`ciamMemoryRequest`](#a-ciammemoryrequest) |  | `string` | single | The memory a workload's main container requests, as Kubernetes writes it (2Gi) |
| [`ciamMemoryLimit`](#a-ciammemorylimit) |  | `string` | single | The memory a workload's main container is limited to, as Kubernetes writes it |
| [`ciamStorageSize`](#a-ciamstoragesize) |  | `string` | single | The persistent storage each replica claims, as Kubernetes writes it (100Gi) |
| [`ciamStorageClass`](#a-ciamstorageclass) |  | `string` | single | The storage class a workload claims its storage from in an environment |
| [`ciamProviderRef`](infrastructure.md#a-ciamproviderref) |  | `string` | single | Provider identifier of the resource (network, subnet, DNS zone, encryption key set) |
| [`ciamProductVersion`](infrastructure.md#a-ciamproductversion) |  | `string` | single | Product and version |
| [`ciamProfileRepo`](#a-ciamprofilerepo) |  | `string` | single | Where an environment keeps a workload's configuration profile for its containers to fetch at start (a Ping server profile): <git URL>[#<path>][@<branch>]; its credentials, if any, are Secret keys the workload reads (ciamWorkloadSecret). None: the profile is built into the image |

## Attributes

| Attribute | OID | Type | Portability | Values | Rules | Description |
| --- | --- | --- | --- | --- | --- | --- |
| <a id="a-ciamclusteraddon"></a>`ciamClusterAddon` | `1.3.6.1.4.1.32473.1.1.252` | `string` | binding | multi |  | An add-on a managed cluster runs: name and version |
| <a id="a-ciamclusterrole"></a>`ciamClusterRole` | `1.3.6.1.4.1.32473.1.1.261` | `string` | intent | single |  | The binding role of the cluster a workload runs in |
| <a id="a-ciamclusterversion"></a>`ciamClusterVersion` | `1.3.6.1.4.1.32473.1.1.251` | `string` | binding | single |  | The Kubernetes version a cluster runs |
| <a id="a-ciamcontainerimage"></a>`ciamContainerImage` | `1.3.6.1.4.1.32473.1.1.256` | `string` | binding | multi |  | A container image an environment runs for a workload: container=repository:tag or container=repository@sha256:digest (sidecars included) |
| <a id="a-ciamcpulimit"></a>`ciamCpuLimit` | `1.3.6.1.4.1.32473.1.1.612` | `string` | binding | single | X-PATTERN `^[0-9]+(\.[0-9]+)?(m\|k\|M\|G\|T\|P\|E\|Ki\|Mi\|Gi\|Ti\|Pi\|Ei)?$` | The CPU a workload's main container is limited to, as Kubernetes writes it |
| <a id="a-ciamcpurequest"></a>`ciamCpuRequest` | `1.3.6.1.4.1.32473.1.1.611` | `string` | binding | single | X-PATTERN `^[0-9]+(\.[0-9]+)?(m\|k\|M\|G\|T\|P\|E\|Ki\|Mi\|Gi\|Ti\|Pi\|Ei)?$` | The CPU a workload's main container requests, as Kubernetes writes it (500m, 2) |
| <a id="a-ciamdesiredsize"></a>`ciamDesiredSize` | `1.3.6.1.4.1.32473.1.1.248` | `int` | binding | single |  | Instances a compute group runs |
| <a id="a-ciamfipsmode"></a>`ciamFipsMode` | `1.3.6.1.4.1.32473.1.1.239` | `bool` | intent | single |  | Whether the OS runs in FIPS mode: it decides which crypto providers the products may use |
| <a id="a-ciamhardeningprofile"></a>`ciamHardeningProfile` | `1.3.6.1.4.1.32473.1.1.625` | vocab: `disa-stig` (ansible) | intent | single |  | A hardening profile the role's servers are configured to beyond the baseline (e.g. disa-stig), as the configuration-management adapter names it; applied alongside what the baseline records |
| <a id="a-ciamhostagent"></a>`ciamHostAgent` | `1.3.6.1.4.1.32473.1.1.241` | `string` | intent | multi |  | An agent on the role's servers: name and version (an EDR sensor, a vulnerability scanner, a log forwarder, a cloud agent) |
| <a id="a-ciamhugepages"></a>`ciamHugePages` | `1.3.6.1.4.1.32473.1.1.238` | enum: `always`, `madvise`, `never` | intent | single |  | Transparent huge pages (directory servers and JVMs usually want never) |
| <a id="a-ciamidentityrole"></a>`ciamIdentityRole` | `1.3.6.1.4.1.32473.1.1.260` | `string` | intent | single |  | The binding role whose cloud identity a workload assumes (workload identity): each environment binds it |
| <a id="a-ciamimagebuild"></a>`ciamImageBuild` | `1.3.6.1.4.1.32473.1.1.245` | `string` | binding | single |  | What builds the image a compute group runs (an image pipeline, a recipe, a template) |
| <a id="a-ciamingresshost"></a>`ciamIngressHost` | `1.3.6.1.4.1.32473.1.1.264` | `fqdn` | contract | multi |  | A host name an ingress serves a workload at |
| <a id="a-ciamjdk"></a>`ciamJdk` | `1.3.6.1.4.1.32473.1.1.233` | `string` | intent | single |  | The Java runtime a server role runs: vendor and version |
| <a id="a-ciamkernelsetting"></a>`ciamKernelSetting` | `1.3.6.1.4.1.32473.1.1.237` | `string` | intent | multi |  | A kernel setting, as sysctl writes it: name=value |
| <a id="a-ciammaxsize"></a>`ciamMaxSize` | `1.3.6.1.4.1.32473.1.1.247` | `int` | binding | single |  | Most instances a compute group scales to |
| <a id="a-ciammemorylimit"></a>`ciamMemoryLimit` | `1.3.6.1.4.1.32473.1.1.614` | `string` | binding | single | X-PATTERN `^[0-9]+(\.[0-9]+)?(m\|k\|M\|G\|T\|P\|E\|Ki\|Mi\|Gi\|Ti\|Pi\|Ei)?$` | The memory a workload's main container is limited to, as Kubernetes writes it |
| <a id="a-ciammemoryrequest"></a>`ciamMemoryRequest` | `1.3.6.1.4.1.32473.1.1.613` | `string` | binding | single | X-PATTERN `^[0-9]+(\.[0-9]+)?(m\|k\|M\|G\|T\|P\|E\|Ki\|Mi\|Gi\|Ti\|Pi\|Ei)?$` | The memory a workload's main container requests, as Kubernetes writes it (2Gi) |
| <a id="a-ciammetadatatokens"></a>`ciamMetadataTokens` | `1.3.6.1.4.1.32473.1.1.250` | `bool` | binding | single |  | Whether the instance metadata service requires session tokens: without them a request forged through the server reads its credentials |
| <a id="a-ciamminsize"></a>`ciamMinSize` | `1.3.6.1.4.1.32473.1.1.246` | `int` | binding | single |  | Fewest instances a compute group scales to |
| <a id="a-ciamnamespace"></a>`ciamNamespace` | `1.3.6.1.4.1.32473.1.1.255` | `string` | intent | single |  | The Kubernetes namespace a workload runs in |
| <a id="a-ciamnetworkpolicy"></a>`ciamNetworkPolicy` | `1.3.6.1.4.1.32473.1.1.263` | `string` | intent | multi |  | A network policy that selects a workload: its name and what it allows |
| <a id="a-ciamnodepool"></a>`ciamNodePool` | `1.3.6.1.4.1.32473.1.1.253` | `string` | binding | multi |  | A cluster's node pool: name: instance size, min-max nodes |
| <a id="a-ciamos"></a>`ciamOs` | `1.3.6.1.4.1.32473.1.1.232` | `string` | intent | single |  | The operating system a server role runs: distribution and version, as os-release names them |
| <a id="a-ciamoslimit"></a>`ciamOsLimit` | `1.3.6.1.4.1.32473.1.1.236` | `string` | intent | multi |  | A resource limit, as limits.conf writes it: domain type item value (ds soft nofile 65536) |
| <a id="a-ciampinnedhost"></a>`ciamPinnedHost` | `1.3.6.1.4.1.32473.1.1.243` | `string` | observed | multi |  | A name pinned in /etc/hosts: address and names. Pinned names are migration landmines |
| <a id="a-ciampodsecurity"></a>`ciamPodSecurity` | `1.3.6.1.4.1.32473.1.1.262` | `string` | intent | multi |  | A security fact of a workload's pods: runAsNonRoot, readOnlyRootFilesystem, privileged, level=restricted |
| <a id="a-ciamprofilerepo"></a>`ciamProfileRepo` | `1.3.6.1.4.1.32473.1.1.657` | `string` | binding | single | X-PATTERN `^(https://\|ssh://\|git@)[^\s#@]+(@[^\s#@]+)?[^\s#]*(#[^\s@]+)?(@[^\s#@/]+)?$` | Where an environment keeps a workload's configuration profile for its containers to fetch at start (a Ping server profile): <git URL>[#<path>][@<branch>]; its credentials, if any, are Secret keys the workload reads (ciamWorkloadSecret). None: the profile is built into the image |
| <a id="a-ciamsearchdomain"></a>`ciamSearchDomain` | `1.3.6.1.4.1.32473.1.1.244` | `string` | observed | multi |  | A DNS search domain of the role's servers (resolv.conf) |
| <a id="a-ciamselinuxmode"></a>`ciamSelinuxMode` | `1.3.6.1.4.1.32473.1.1.240` | enum: `enforcing`, `permissive`, `disabled` | intent | single |  | SELinux mode |
| <a id="a-ciamserviceaccount"></a>`ciamServiceAccount` | `1.3.6.1.4.1.32473.1.1.259` | `string` | intent | single |  | The Kubernetes service account a workload runs as |
| <a id="a-ciamserviceunit"></a>`ciamServiceUnit` | `1.3.6.1.4.1.32473.1.1.242` | `string` | intent | multi |  | A service unit of the role's servers: name, the user it runs as, its restart policy |
| <a id="a-ciamspanszone"></a>`ciamSpansZone` | `1.3.6.1.4.1.32473.1.1.249` | `string` | binding | multi |  | An availability zone a compute group, a cluster or a node pool places instances in |
| <a id="a-ciamstorageclass"></a>`ciamStorageClass` | `1.3.6.1.4.1.32473.1.1.258` | `string` | binding | single |  | The storage class a workload claims its storage from in an environment |
| <a id="a-ciamstoragesize"></a>`ciamStorageSize` | `1.3.6.1.4.1.32473.1.1.257` | `string` | binding | single | X-PATTERN `^[0-9]+(\.[0-9]+)?(m\|k\|M\|G\|T\|P\|E\|Ki\|Mi\|Gi\|Ti\|Pi\|Ei)?$` | The persistent storage each replica claims, as Kubernetes writes it (100Gi) |
| <a id="a-ciamtrustedfingerprint"></a>`ciamTrustedFingerprint` | `1.3.6.1.4.1.32473.1.1.235` | `string` | observed | multi |  | SHA-256 fingerprint of a certificate the truststore adds that the record holds no certificate for |
| <a id="a-ciamtrustscertificate"></a>`ciamTrustsCertificate` | `1.3.6.1.4.1.32473.1.1.234` | `dn` | intent | multi |  | A certificate the role's Java truststore (cacerts) adds to the runtime's own: lost silently when a server is rebuilt from a stock image |
| <a id="a-ciamworkloadkind"></a>`ciamWorkloadKind` | `1.3.6.1.4.1.32473.1.1.254` | enum: `statefulset`, `deployment`, `daemonset`, `other` | intent | single |  | How a workload runs: a StatefulSet, a Deployment, a DaemonSet |
| <a id="a-ciamworkloadreplicas"></a>`ciamWorkloadReplicas` | `1.3.6.1.4.1.32473.1.1.610` | `int` | binding | single |  | The replicas an environment runs of a workload |
| <a id="a-ciamworkloadrole"></a>`ciamWorkloadRole` | `1.3.6.1.4.1.32473.1.1.609` | `string` | intent | single |  | The binding role of a workload's workload binding: an environment that binds it runs the workload on Kubernetes, with the binding's images, replicas, resources and storage |
| <a id="a-ciamworkloadsecret"></a>`ciamWorkloadSecret` | `1.3.6.1.4.1.32473.1.1.615` | `string` | intent | multi | X-PATTERN `^[a-z0-9]([-a-z0-9.]*[a-z0-9])?/[-._A-Za-z0-9]+ <- [^\s]+$` | A Kubernetes Secret key a workload reads and the secret role that fills it: <secret name>/<key> <- <secret role> (each environment binds the role to its secret store's reference; values never. Not key=role: a key named like a password would read as one) |
