![Baton Logo](./baton-logo.png)

# `baton-kubernetes` [![Go Reference](https://pkg.go.dev/badge/github.com/conductorone/baton-kubernetes.svg)](https://pkg.go.dev/github.com/conductorone/baton-kubernetes) ![main ci](https://github.com/conductorone/baton-kubernetes/actions/workflows/main.yaml/badge.svg)

`baton-kubernetes` is a connector for built using the [Baton SDK](https://github.com/conductorone/baton-sdk).

Check out [Baton](https://github.com/conductorone/baton) to learn more the project in general.

# Getting Started

## brew

```
brew install conductorone/baton/baton conductorone/baton/baton-kubernetes
baton-kubernetes
baton resources
```

## docker

```
docker run --rm -v $(pwd):/out -e BATON_DOMAIN_URL=domain_url -e BATON_API_KEY=apiKey -e BATON_USERNAME=username ghcr.io/conductorone/baton-kubernetes:latest -f "/out/sync.c1z"
docker run --rm -v $(pwd):/out ghcr.io/conductorone/baton:latest -f "/out/sync.c1z" resources
```

## source

```
go install github.com/conductorone/baton/cmd/baton@main
go install github.com/conductorone/baton-kubernetes/cmd/baton-kubernetes@main

baton-kubernetes

baton resources
```

# Data Model

`baton-kubernetes` syncs identity and access data from the Kubernetes API. The following resource types are supported:

| Resource Type | Description | Entitlements |
| --- | --- | --- |
| Namespace | Kubernetes namespace | — |
| Role | Namespaced RBAC role | `member` — granted to users, groups, and service accounts via RoleBindings |
| ClusterRole | Cluster-scoped RBAC role | `all:member` (cluster-wide) and `<namespace>:member` (namespace-scoped via RoleBindings) |
| ServiceAccount | Kubernetes service account | — |
| Kubernetes User (`kube_user`) | User identity referenced in RBAC bindings | — |
| Kubernetes Group (`kube_group`) | Group identity referenced in RBAC bindings | `member` — see limitations below |
| Node | Cluster node | — |
| Pod | Running pod | — |
| Deployment | Deployment resource | — |
| StatefulSet | StatefulSet resource | — |
| DaemonSet | DaemonSet resource | — |
| ConfigMap | ConfigMap resource | — |
| Secret | Secret resource | — |

Role and ClusterRole resources carry their RBAC rules in the resource profile: the structured `rules` (apiGroups, resources, resourceNames, verbs, nonResourceURLs), the unions across all rules, and a risk summary — `canModify`, `modifiableVerbs`, `modifiableVerbCount` — where a modifiable verb is any of `create, update, patch, delete, deletecollection, bind, escalate, impersonate, *`. Aggregated ClusterRoles are marked `aggregated: true`; their rules are the effective set, because the Kubernetes aggregation controller materializes them into the object.

By default only the core RBAC resource types are synced (namespace, service_account, role, cluster_role, kube_user, kube_group). Workload and configuration types (node, pod, deployment, statefulset, daemonset, configmap, secret) are opt-in via the standard `--sync-resource-types` flag (`BATON_SYNC_RESOURCE_TYPES`). An explicit selection replaces the default set, so list every resource type ID you want, e.g. `--sync-resource-types namespace,service_account,role,cluster_role,kube_user,kube_group,pod`.

## Group Membership

Kubernetes group membership is not a native API object. Groups exist only as claims in authentication credentials and are never persisted in the cluster. The connector discovers group membership by one method only:

**x509 client certificates in kubeconfig Secrets** — when a Secret contains a kubeconfig with embedded client certificate data, the connector parses the certificate's `O=` (Organization) fields as group names and the `CN=` (Common Name) field as the username, then emits a `kube_group:<group>:member → kube_user:<cn>` grant.

### Limitations

The following authentication methods are **not supported** for group membership discovery. Users authenticating via these methods will appear in RBAC bindings but their group memberships will not be visible:

- **OIDC / OAuth2** — group claims live in the ID token, which the cluster never stores
- **Webhook authenticators** — group assignment happens at auth time outside the cluster
- **Bootstrap tokens** — no user or group identity is stored in the cluster
- **In-cluster service account tokens** — group is always `system:serviceaccounts` and `system:serviceaccounts:<namespace>`, inferred from the token's namespace, not from a parseable credential

### What this means for access auditing

RBAC bindings to groups are fully visible. If `ClusterRole:admin` is bound to group `developers`, that grant is synced. However, **the list of users in `developers` is only complete if those users authenticate via x509 client certificates stored as kubeconfig Secrets in the cluster**. Users authenticating via OIDC or webhook will appear as grant targets on Roles and ClusterRoles (if they have direct bindings) but not as members of their groups.

# Contributing, Support and Issues

We started Baton because we were tired of taking screenshots and manually
building spreadsheets. We welcome contributions, and ideas, no matter how
small&mdash;our goal is to make identity and permissions sprawl less painful for
everyone. If you have questions, problems, or ideas: Please open a GitHub Issue!

See [CONTRIBUTING.md](https://github.com/ConductorOne/baton/blob/main/CONTRIBUTING.md) for more details.

# `baton-kubernetes` Command Line Usage

```
baton-kubernetes

Usage:
  baton-kubernetes [flags]
  baton-kubernetes [command]

Available Commands:
  capabilities       Get connector capabilities
  completion         Generate the autocompletion script for the specified shell
  help               Help about any command

Flags:
      --client-id string             The client ID used to authenticate with ConductorOne ($BATON_CLIENT_ID)
      --client-secret string         The client secret used to authenticate with ConductorOne ($BATON_CLIENT_SECRET)
  -f, --file string                  The path to the c1z file to sync with ($BATON_FILE) (default "sync.c1z")
  -h, --help                         help for baton-kubernetes
      --log-format string            The output format for logs: json, console ($BATON_LOG_FORMAT) (default "json")
      --log-level string             The log level: debug, info, warn, error ($BATON_LOG_LEVEL) (default "info")
  -p, --provisioning                 If this connector supports provisioning, this must be set in order for provisioning actions to be enabled ($BATON_PROVISIONING)
      --ticketing                    This must be set to enable ticketing support ($BATON_TICKETING)
  -v, --version                      version for baton-kubernetes

Use "baton-kubernetes [command] --help" for more information about a command.
```
