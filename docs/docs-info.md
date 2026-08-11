While developing the connector, please fill out this form. This information is needed to write docs and to help other users set up the connector.

## Connector capabilities

1. What resources does the connector sync?

    Six resource types sync by default:

    - Namespaces
    - Service accounts
    - Kubernetes users (`kube_user`)
    - Kubernetes groups (`kube_group`)
    - Roles
    - Cluster roles

    Seven more are declared but excluded from the default sync, and are selectable with the standard `--sync-resource-types` flag: Nodes, Pods, Deployments, StatefulSets, DaemonSets, Secrets, ConfigMaps. They carry `OptInRequired` annotations in `baton_capabilities.json`. They expose verb entitlements (`get`, `list`, `watch`, `create`, `update`, `patch`, `delete`, and for pods also `exec` and `portforward`) that never receive grants, which is why they are opt-in rather than default.

    Two more — Cluster (`cluster`) and Role assignments (`role_assignment`) — belong to the optional sparse model described below. They are always registered, but emit nothing unless `--use-role-assignments` is set, and they also carry `OptInRequired`. Fifteen resource types are declared in total.

    Three behaviours worth documenting, because none is obvious from the resource list:

    - **Users and groups are derived, not enumerated.** Kubernetes has no user store. The connector materialises a principal only when an RBAC binding references it, or when it appears as the `CN` of an x509 client certificate inside a kubeconfig Secret. A user with no binding is invisible by design.
    - **Bindings whose subject name contains `system:` produce no grants.** Roles and cluster roles named `system:*` are still synced; the exclusion applies to the subject side of a binding. If a cluster binds a `system:` group to real users, that binding does not appear as access in C1.
    - **Cluster role access has two mutually exclusive shapes.** By default a cluster role declares `all:member` plus one `<namespace>:member` per namespace, which is cluster roles × namespaces entitlements and nearly all of them permanently empty. With `--use-role-assignments` the connector instead emits one `role_assignment` per (cluster role, scope) pair that has a binding, each with a single `assigned` entitlement, and cluster roles stop reporting their own entitlements and grants so the access is not counted twice. Measured on a 71-cluster-role, 9-namespace test cluster: 710 declared cluster role entitlements down to 54. Namespaced roles are untouched by the setting — a role can only be bound in its own namespace, so the sparse form would not reduce anything. Note that `cluster` and `role_assignment` must also be selected if the resource type selection is narrowed, or the setting produces no cluster role access at all.

2. Can the connector provision any resources? If so, which ones?

    No. `baton_capabilities.json` declares `CAPABILITY_SYNC` only, and there is no `Provisioner()` implementation, no `Grant`/`Revoke`, and no account create or delete anywhere in `pkg/connector`. The connector is read-only.

## Connector credentials

1. What credentials or information are needed to set up the connector? (For example, API key, client ID and secret, domain, etc.)

    One of three ways to reach the cluster:

    - **A kubeconfig file** (`--kubeconfig`) — the usual choice when running the connector outside the cluster.
    - **A bearer token plus the API server URL** (`--token`, `--server`, and `--certificate-authority` for the cluster CA) — the choice when the API server is reachable directly.
    - **A client certificate and key plus the API server URL** (`--client-certificate`, `--client-key`, `--server`, `--certificate-authority`).

    Deployed inside the cluster, the connector uses the mounted service account token and needs no credential flags at all.

    Impersonation (`--as`, `--as-uid`, `--as-group`) is available as an alternative to a direct credential. All three methods are mutually exclusive with each other; the certificate and key are required together.

2. For each item in the list above:

   * How does a user create or look up that credential or info? Please include links to (non-gated) documentation, screenshots (of the UI or of gated docs), or a video of the process.

     * **Service account and RBAC permissions**: apply the manifest in `docs/connector.mdx` ("Set up RBAC permissions in your cluster"), which creates the namespace, the service account, and a read-only ClusterRole and ClusterRoleBinding. See [Using RBAC Authorization](https://kubernetes.io/docs/reference/access-authn-authz/rbac/).
     * **Bearer token**: create a long-lived token by applying a `kubernetes.io/service-account-token` Secret that references the service account, then read the token from that Secret. See [Manually create a long-lived API token for a ServiceAccount](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#manually-create-an-api-token-for-a-serviceaccount).
     * **API server URL**: `kubectl cluster-info`, or the `server` field of the current context in the kubeconfig.
     * **Cluster CA certificate**: the `certificate-authority-data` field of the cluster entry in the kubeconfig, base64-decoded to a file.
     * **Client certificate**: issue one through the CertificateSigningRequest API with the `kubernetes.io/kube-apiserver-client` signer. See [Certificate Signing Requests](https://kubernetes.io/docs/reference/access-authn-authz/certificate-signing-requests/).

   * Does the credential need any specific scopes or permissions? If so, list them here.

     Cluster-wide `get`, `list` and `watch` on:

     - `namespaces`, `serviceaccounts` (core API group)
     - `roles`, `clusterroles`, `rolebindings`, `clusterrolebindings` (`rbac.authorization.k8s.io`)
     - `secrets` (core API group) — **optional**, see below
     - `pods`, `nodes`, `configmaps` (core) and `deployments`, `statefulsets`, `daemonsets` (`apps`) — only when those opt-in types are selected

     `secrets` read is genuinely optional and its absence degrades cleanly rather than failing the sync. Without it, the connector logs `skipping cert-based user discovery: not permitted to list secrets` and completes: every RBAC-derived principal still syncs, and only the x509 group-membership layer is lost. Verified on v0.1.0 against a cluster where the connector's service account was denied `secrets` — the sync finished with zero errors and produced no group membership grants, while the user and group counts were otherwise unchanged.

    * If applicable: Is the list of scopes or permissions different to sync (read) versus provision (read-write)? If so, list the difference here.

      Not applicable. The connector is read-only, so read permissions are the whole surface.

     * What level of access or permissions does the user need in order to create the credentials? (For example, must be a super administrator, must have access to the admin console, etc.)

     Permission to create namespaces, service accounts, ClusterRoles and ClusterRoleBindings in the target cluster — in practice `cluster-admin` or an equivalent role. Issuing a client certificate additionally requires permission to create and approve CertificateSigningRequests.

## Limitations to document

- **Group membership is only discoverable for x509 client certificates stored in kubeconfig Secrets.** Kubernetes never persists group claims: they exist only inside the credential presented at authentication time. The connector parses the `O=` fields of a client certificate embedded in a kubeconfig Secret and emits membership from them. Membership for users authenticating via OIDC, webhook authenticators, bootstrap tokens, or in-cluster service account tokens cannot be resolved. Those users still appear as grant targets on roles and cluster roles when they hold a direct binding.
- **Grants to group subjects are not expanded.** Vanilla Kubernetes has no membership source to expand through, so a role granted to a group is recorded against the group and not propagated to its members. The cloud variants of this connector add their own expansion.
- **An explicit `--sync-resource-types` selection replaces the default set** rather than adding to it, so a selection must list every type the deployment wants.

This form was compiled from an end-to-end validation of v0.1.0 rather than by the connector author, so the sections above describe measured behaviour. Anything a docs writer needs that is not here is missing rather than intentionally omitted.
