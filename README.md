![Baton Logo](./baton-logo.png)

# `baton-kubernetes` [![Go Reference](https://pkg.go.dev/badge/github.com/conductorone/baton-kubernetes.svg)](https://pkg.go.dev/github.com/conductorone/baton-kubernetes) ![main ci](https://github.com/conductorone/baton-kubernetes/actions/workflows/main.yaml/badge.svg)

`baton-kubernetes` is a connector built using the [Baton SDK](https://github.com/conductorone/baton-sdk).

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
docker run --rm -v $(pwd):/out -v ~/.kube:/root/.kube -e BATON_CLIENT_ID=client_id -e BATON_CLIENT_SECRET=client_secret ghcr.io/conductorone/baton-kubernetes:latest -f "/out/sync.c1z"
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

`baton-kubernetes` will pull down information about the following resources:

| Resource Type | Description |
|---|---|
| Namespace | Kubernetes namespaces (parent of service accounts) |
| Service Account | Kubernetes service accounts (synced as users) |
| Kubernetes User | Users referenced in RBAC bindings |
| Kubernetes Group | Groups referenced in RBAC bindings |
| Role | Namespace-scoped RBAC roles |
| Cluster Role | Cluster-scoped RBAC roles |
| Node | Cluster nodes |
| Pod | Running pods |
| Deployment | Deployment workloads |
| Stateful Set | StatefulSet workloads |
| Daemon Set | DaemonSet workloads |
| Secret | Kubernetes secrets |
| Config Map | Kubernetes config maps |

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
  config             Get the connector config schema
  health-check       Check the health of a running connector
  help               Help about any command

Flags:
      --as string                                        Username to impersonate for the operation. User could be a regular user or a service account in a namespace. ($BATON_AS)
      --as-group strings                                 Group to impersonate for the operation, this flag can be repeated to specify multiple groups. ($BATON_AS_GROUP)
      --as-uid string                                    UID to impersonate for the operation. ($BATON_AS_UID)
      --cache-dir string                                 Default cache directory ($BATON_CACHE_DIR)
      --certificate-authority string                     Path to a cert file for the certificate authority ($BATON_CERTIFICATE_AUTHORITY)
      --client-certificate string                        Path to a client certificate file for TLS ($BATON_CLIENT_CERTIFICATE)
      --client-id string                                 The client ID used to authenticate with ConductorOne ($BATON_CLIENT_ID)
      --client-key string                                Path to a client key file for TLS ($BATON_CLIENT_KEY)
      --client-secret string                             The client secret used to authenticate with ConductorOne ($BATON_CLIENT_SECRET)
      --cluster string                                   The name of the kubeconfig cluster to use ($BATON_CLUSTER)
      --context string                                   The name of the kubeconfig context to use ($BATON_CONTEXT)
      --disable-compression                              If true, opt-out of response compression for all requests to the server ($BATON_DISABLE_COMPRESSION)
  -f, --file string                                      The path to the c1z file to sync with ($BATON_FILE) (default "sync.c1z")
  -h, --help                                             help for baton-kubernetes
      --insecure-skip-tls-verify                         If true, the server's certificate will not be checked for validity. This will make your HTTPS connections insecure ($BATON_INSECURE_SKIP_TLS_VERIFY)
      --kubeconfig string                                Path to the kubeconfig file to use for CLI requests. ($BATON_KUBECONFIG)
      --log-format string                                The output format for logs: json, console ($BATON_LOG_FORMAT) (default "json")
      --log-level string                                 The log level: debug, info, warn, error ($BATON_LOG_LEVEL) (default "info")
      --namespace string                                 If present, the namespace scope for this CLI request ($BATON_NAMESPACE)
      --password string                                  Password for basic authentication to the API server ($BATON_PASSWORD)
  -p, --provisioning                                     This must be set in order for provisioning actions to be enabled ($BATON_PROVISIONING)
      --request-timeout string                           The length of time to wait before giving up on a single server request. Non-zero values should contain a corresponding time unit (e.g. 1s, 2m, 3h). A value of zero means don't timeout requests. ($BATON_REQUEST_TIMEOUT) (default "0")
      --server string                                    The address and port of the Kubernetes API server ($BATON_SERVER)
      --ticketing                                        This must be set to enable ticketing support ($BATON_TICKETING)
      --tls-server-name string                           Server name to use for server certificate validation. If it is not provided, the hostname used to contact the server is used ($BATON_TLS_SERVER_NAME)
      --token string                                     Bearer token for authentication to the API server ($BATON_TOKEN)
      --user string                                      The name of the kubeconfig user to use ($BATON_USER)
      --username string                                  Username for basic authentication to the API server ($BATON_USERNAME)
  -v, --version                                          version for baton-kubernetes
      --workers int                                      The number of sync workers to use. -1 for auto-detect, 0 for sequential, >0 for parallel ($BATON_WORKERS)

Use "baton-kubernetes [command] --help" for more information about a command.
```
