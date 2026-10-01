# opsdir-adapter-kubernetes

opsdir adapter for Kubernetes: k8s-secret:// secret references.

A secret-store adapter: owns the `k8s-secret://<namespace>/<secret>/<key>` reference scheme and resolves it with `kubectl` at run time (the key's value, base64-decoded). The secret value never reaches the database or a rendered file.

Installing the package registers it with opsdir (entry point `opsdir.adapters`: `kubernetes`); nothing in the opsdir core changes. In this repository: `opsdir/scripts/dev-install.sh`.
