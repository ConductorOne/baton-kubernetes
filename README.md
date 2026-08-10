![Baton Logo](./baton-logo.png)

# `baton-kubernetes` [![Go Reference](https://pkg.go.dev/badge/github.com/conductorone/baton-kubernetes.svg)](https://pkg.go.dev/github.com/conductorone/baton-kubernetes) ![main ci](https://github.com/conductorone/baton-kubernetes/actions/workflows/main.yaml/badge.svg)

`baton-kubernetes` is a connector for Kubernetes built using the [Baton SDK](https://github.com/conductorone/baton-sdk). It syncs identity and access data from a cluster's RBAC objects.

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
docker run --rm -v $(pwd):/out -v ~/.kube/config:/kubeconfig:ro -e BATON_KUBECONFIG=/kubeconfig ghcr.io/conductorone/baton-kubernetes:latest -f "/out/sync.c1z"
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
| Cluster (`cluster`) | Singleton standing for the cluster itself; the scope a cluster-wide role assignment points at | — |
| Role Assignment (`role_assignment`) | One (cluster role, scope) pair that has at least one binding — see below | `assigned` — granted to users, groups, and service accounts |

Role and ClusterRole resources carry their RBAC rules in the resource profile: the structured `rules` (apiGroups, resources, resourceNames, verbs, nonResourceURLs), the unions across all rules, and a risk summary — `canModify`, `modifiableVerbs`, `modifiableVerbCount` — where a modifiable verb is any of `create, update, patch, delete, deletecollection, bind, escalate, impersonate, *`. Aggregated ClusterRoles are marked `aggregated: true`; their rules are the effective set, because the Kubernetes aggregation controller materializes them into the object.

By default only the core RBAC resource types are synced (namespace, service_account, role, cluster_role, kube_user, kube_group). Workload and configuration types (node, pod, deployment, statefulset, daemonset, configmap, secret) are opt-in via the standard `--sync-resource-types` flag (`BATON_SYNC_RESOURCE_TYPES`). An explicit selection replaces the default set, so list every resource type ID you want, e.g. `--sync-resource-types namespace,service_account,role,cluster_role,kube_user,kube_group,pod`.

## Cluster Role Assignments

By default a ClusterRole declares one entitlement per namespace plus one cluster-wide: `all:member` and `<namespace>:member`. That is O(cluster roles × namespaces) entitlements, and nearly all of them are permanently empty — a cluster with 70 cluster roles and 50 namespaces declares ~3,500 entitlements to express a few dozen real bindings.

`--use-role-assignments` (`BATON_USE_ROLE_ASSIGNMENTS`) switches to a sparse model: one `role_assignment` resource per (cluster role, scope) pair that actually has a binding, each carrying a single `assigned` entitlement. On a 71-cluster-role, 9-namespace test cluster this took 710 declared cluster role entitlements down to 54 while expressing exactly the same access.

| Kubernetes object | role | scope |
| --- | --- | --- |
| ClusterRoleBinding | the ClusterRole | the cluster |
| RoleBinding referencing a ClusterRole | the ClusterRole | that namespace |

The two models are mutually exclusive. With the flag on, `cluster_role` stops emitting entitlements and grants, so the same access is never counted twice. Namespaced `role` resources are unaffected either way: a Role can only be bound in its own namespace, so (role, scope) is 1:1 with the Role and the sparse form would produce slightly more objects, not fewer.

Because pairs are deduplicated by (cluster role, scope), several bindings granting the same cluster role in the same scope collapse into one resource. The contributing binding names, kinds and creation timestamps are kept in the resource profile under `contributingBindings`, so the individual objects behind the access stay visible. Bindings whose `roleRef` names a cluster role that does not exist are skipped — they are legal in Kubernetes and simply inert.

<a id="role-assignment-opt-in"></a>
**Both `role_assignment` and `cluster` are opt-in resource types.** If you narrow the sync with `--sync-resource-types` (or, in ConductorOne, by selecting resource types on the connector), you must include them alongside the flag, or `cluster_role` will suppress its entitlements and grants while nothing emits the assignments meant to replace them — leaving no cluster role access at all:

```
baton-kubernetes --use-role-assignments \
  --sync-resource-types namespace,service_account,role,cluster_role,kube_user,kube_group,cluster,role_assignment
```

With no explicit selection the connector's own default already includes both, so the flag alone is enough.

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

# Connector configuration

These flags configure the cluster connection. Every flag also accepts an environment variable, formed by uppercasing the flag name, replacing dashes with underscores and prefixing `BATON_` — `--kubeconfig` becomes `BATON_KUBECONFIG`. The generic Baton flags (`--client-id`, `--client-secret`, `-f/--file`, `--log-level`, and the rest) are listed in the full usage output below.

## Choosing a cluster

| Flag | Description | Default |
| --- | --- | --- |
| `--kubeconfig` | Path to the kubeconfig file. The file must exist; the connector exits with `specified kubeconfig file does not exist: <path>` if it does not. | |
| `--server` | Address and port of the Kubernetes API server, for example `https://api.example.com:6443`. | |
| `--context` | Name of the kubeconfig context to use. | the kubeconfig's current context |
| `--cluster` | Name of the kubeconfig cluster to use. | |
| `--user` | Name of the kubeconfig user to use. | |

When you pass neither `--kubeconfig` nor `--server`, the connector resolves the cluster from the environment: the `KUBECONFIG` variable (a `:`-separated list of paths, first existing file wins), then `$HOME/.kube/config`, then an in-cluster service account. If none of the three is present it exits with `no kubeconfig available: <path> does not exist and no in-cluster service account found`. Name the target explicitly with `--kubeconfig` or `--server` when you run the connector outside a cluster — otherwise it follows whatever cluster your current context points at.

## Authenticating

Pick one method. `--token`, `--client-certificate`/`--client-key` and `--as` are mutually exclusive: combining them exits with `if any flags in the group [token client-certificate] are set none of the others can be`. `--client-certificate` and `--client-key` are required together.

| Flag | Description |
| --- | --- |
| `--token` | Bearer token for authentication to the API server. Marked secret. |
| `--client-certificate` | Path to a client certificate file for TLS. Requires `--client-key`. |
| `--client-key` | Path to a client key file for TLS. Requires `--client-certificate`. |
| `--as` | Username to impersonate. May be a user or a service account. |
| `--as-uid` | UID to impersonate. |
| `--as-group` | Group to impersonate. Repeat the flag for multiple groups. Kubernetes rejects a group without `--as`. |

## TLS and transport

| Flag | Description | Default |
| --- | --- | --- |
| `--certificate-authority` | Path to a CA certificate file used to verify the API server. Without it, a self-signed cluster certificate fails with `x509: certificate signed by unknown authority`. | |
| `--tls-server-name` | Server name for certificate validation. Falls back to the hostname in the server URL. | |
| `--insecure-skip-tls-verify` | Skip verification of the server's certificate. | `false` |
| `--request-timeout` | Time to wait for a single server request, for example `30s` or `2m`. `0` means no timeout. | `0` |
| `--disable-compression` | Opt out of response compression for all requests. | `false` |

## Selecting resource types

The connector syncs the six core RBAC types by default. Use the standard `--sync-resource-types` flag (or `BATON_SYNC_RESOURCE_TYPES`) to select a different set, as described in [Data Model](#data-model). An explicit selection replaces the default set rather than adding to it.

# `baton-kubernetes` Command Line Usage

```
baton-kubernetes

Usage:
  baton-kubernetes [flags]
  baton-kubernetes [command]

Available Commands:
  capabilities       Get connector capabilities
  completion         Generate the autocompletion script for the specified shell
  config             Get the connector config schema
  health-check       Check the health of a running connector
  help               Help about any command

Flags:
      --as string                                        Username to impersonate for the operation. User could be a regular user or a service account in a namespace. ($BATON_AS)
      --as-group strings                                 Group to impersonate for the operation, this flag can be repeated to specify multiple groups. ($BATON_AS_GROUP)
      --as-uid string                                    UID to impersonate for the operation. ($BATON_AS_UID)
      --auth-method string                               ($BATON_AUTH_METHOD)
      --certificate-authority string                     Path to a cert file for the certificate authority ($BATON_CERTIFICATE_AUTHORITY)
      --client-certificate string                        Path to a client certificate file for TLS ($BATON_CLIENT_CERTIFICATE)
      --client-id string                                 The client ID used to authenticate with ConductorOne ($BATON_CLIENT_ID)
      --client-key string                                Path to a client key file for TLS ($BATON_CLIENT_KEY)
      --client-secret string                             The client secret used to authenticate with ConductorOne ($BATON_CLIENT_SECRET)
      --cluster string                                   The name of the kubeconfig cluster to use ($BATON_CLUSTER)
      --context string                                   The name of the kubeconfig context to use ($BATON_CONTEXT)
      --disable-compression                              If true, opt-out of response compression for all requests to the server ($BATON_DISABLE_COMPRESSION)
      --external-resource-c1z string                     The path to the c1z file to sync external baton resources with ($BATON_EXTERNAL_RESOURCE_C1Z)
      --external-resource-entitlement-id-filter string   The entitlement that external users, groups must have access to sync external baton resources ($BATON_EXTERNAL_RESOURCE_ENTITLEMENT_ID_FILTER)
      --external-resource-traits strings                 Resource type traits (e.g. "user", "group", "app") to sync and match from the external resource c1z. When unset the matcher falls back to user and group; passing this flag replaces the full set rather than adding to it. ($BATON_EXTERNAL_RESOURCE_TRAITS)
  -f, --file string                                      The path to the c1z file to sync with ($BATON_FILE) (default "sync.c1z")
      --health-check                                     Enable the HTTP health check endpoint ($BATON_HEALTH_CHECK)
      --health-check-port int                            Port for the HTTP health check endpoint ($BATON_HEALTH_CHECK_PORT) (default 8081)
  -h, --help                                             help for baton-kubernetes
      --http-timeout-seconds int                         HTTP client timeout in seconds (max 1800) ($BATON_HTTP_TIMEOUT_SECONDS) (default 300)
      --insecure-skip-tls-verify                         If true, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure ($BATON_INSECURE_SKIP_TLS_VERIFY)
      --keep-previous-sync-c1z                           Keep the previously synced c1z on disk to enable ETag replay across service-mode syncs (requires a connector that supports ETag replay; costs one c1z of local disk) ($BATON_KEEP_PREVIOUS_SYNC_C1Z)
      --kubeconfig string                                Path to the kubeconfig file to use for CLI requests. ($BATON_KUBECONFIG)
      --log-format string                                The output format for logs: json, console ($BATON_LOG_FORMAT) (default "json")
      --log-level string                                 The log level: debug, info, warn, error ($BATON_LOG_LEVEL) (default "info")
      --log-level-debug-expires-at string                The timestamp indicating when debug-level logging should expire ($BATON_LOG_LEVEL_DEBUG_EXPIRES_AT)
      --log-path strings                                 The file path to write logs to ($BATON_LOG_PATH)
      --otel-collector-endpoint string                   The endpoint of the OpenTelemetry collector to send observability data to (used for both tracing and logging if specific endpoints are not provided) ($BATON_OTEL_COLLECTOR_ENDPOINT)
      --parallel-sync                                    Deprecated: use --workers instead. ($BATON_PARALLEL_SYNC)
  -p, --provisioning                                     This must be set in order for provisioning actions to be enabled ($BATON_PROVISIONING)
      --request-timeout string                           The length of time to wait before giving up on a single server request. Non-zero values should contain a corresponding time unit (e.g. 1s, 2m, 3h). A value of zero means don't timeout requests. ($BATON_REQUEST_TIMEOUT) (default "0")
      --server string                                    The address and port of the Kubernetes API server ($BATON_SERVER)
      --skip-entitlements-and-grants                     This must be set to skip syncing of entitlements and grants ($BATON_SKIP_ENTITLEMENTS_AND_GRANTS)
      --skip-full-sync                                   This must be set to skip a full sync ($BATON_SKIP_FULL_SYNC)
      --storage-engine string                            The storage engine to use when opening the sync c1z file: sqlite or pebble. Leave unset to use the baton-sdk default. ($BATON_STORAGE_ENGINE)
      --sync-resource-types strings                      The resource type IDs to sync ($BATON_SYNC_RESOURCE_TYPES)
      --sync-resources strings                           The resource IDs to sync ($BATON_SYNC_RESOURCES)
      --task-concurrency int                             The number of Baton tasks to run concurrently in service mode. Tasks may include sync, grant, revoke, and more. Minimum value is 1, maximum value is 100. ($BATON_TASK_CONCURRENCY) (default 3)
      --ticketing                                        This must be set to enable ticketing support ($BATON_TICKETING)
      --tls-server-name string                           Server name to use for server certificate validation. If it is not provided, the hostname used to contact the server is used ($BATON_TLS_SERVER_NAME)
      --token string                                     Bearer token for authentication to the API server ($BATON_TOKEN)
      --use-role-assignments                             If true, sync each (cluster role, scope) pair that has a binding as a role assignment resource, instead of declaring one entitlement per cluster role per namespace. Namespaced roles are unaffected. ($BATON_USE_ROLE_ASSIGNMENTS)
      --user string                                      The name of the kubeconfig user to use ($BATON_USER)
  -v, --version                                          version for baton-kubernetes
      --workers int                                      The number of sync workers to use. -1 for auto-detect, 0 for sequential, >0 for parallel ($BATON_WORKERS)

Use "baton-kubernetes [command] --help" for more information about a command.
```
