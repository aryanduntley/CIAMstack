# opsdir-adapter-azure

opsdir adapter for Microsoft Azure: Terraform for Azure environments and azkv:// secret references.

Applies to environments whose cloud has `ciamCloudProvider: azure` (commercial or government partition, `ciamCloudEnvironment`). Renders the environment-specific Terraform (virtual network, subnets, VMs, load balancers, network security rules with pinned priorities, DNS) and resolves `azkv://` secret references with the Azure CLI at run time. Owns the reference schemes `azkv`, `azkv-key`, `azblob`.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `azure`); nothing in the opsdir core changes. In this repository: `scripts/dev-install.sh`.
