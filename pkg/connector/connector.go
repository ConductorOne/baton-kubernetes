package connector

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	pkgconfig "github.com/conductorone/baton-kubernetes/pkg/config"
	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/cli"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	rbacv1 "k8s.io/api/rbac/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clioptions "k8s.io/cli-runtime/pkg/genericclioptions"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	pointer "k8s.io/utils/ptr"
)

const (
	ResourceTypeClusterRoleBindings = "clusterrolebindings"
	ResourceTypeClusterRoleBinding  = "clusterrolebinding"
	ResourceTypeRoleBindings        = "rolebindings"
	ResourceTypeRoleBinding         = "rolebinding"
	SubjectTypeGroup                = "Group"
	SubjectTypeUser                 = "User"
	// RBACKindRole is the Kubernetes RBAC Kind value for Role objects; it also
	// matches the connector's Role resource type DisplayName.
	RBACKindRole = "Role"

	connectorDisplayName = "Kubernetes"
	connectorDescription = "Connector for Kubernetes resources and RBAC permissions"
)

// Configuration options.
type ConnectorOpts struct {
	SyncResources []string
	CustomSyncer  map[string]ResourceSyncerBuilder
	// UseRoleAssignments switches cluster role access to the sparse model.
	UseRoleAssignments bool
	// IncludeSystemObjectPermissions keeps the control plane's own permissions
	// in the object layer.
	IncludeSystemObjectPermissions bool
	// ClusterName labels the cluster resource. Empty falls back to the API
	// server host.
	ClusterName string
}

// ConnectorOption is a function that configures the connector options.
type ConnectorOption func(*ConnectorOpts) error
type ResourceSyncerBuilder func(*kubernetes.Interface, *Kubernetes) connectorbuilder.ResourceSyncerV2

// WithSyncResources configures the connector to sync the specified resources in the list only.
func WithSyncResources(resources []string) ConnectorOption {
	return func(opts *ConnectorOpts) error {
		opts.SyncResources = resources
		return nil
	}
}

// WithCustomSyncers configures the connector to use custom syncer for known resources replacing defaults.
func WithCustomSyncers(syncers map[string]ResourceSyncerBuilder) ConnectorOption {
	return func(opts *ConnectorOpts) error {
		opts.CustomSyncer = syncers
		return nil
	}
}

// WithRoleAssignments switches cluster role access from the flat model to the
// sparse one: instead of declaring an entitlement per cluster role per
// namespace, the connector emits one role_assignment resource per
// (cluster role, scope) pair that actually has a binding.
//
// The two are mutually exclusive. With this on, cluster_role stops emitting
// entitlements and grants, so the same access is never counted twice.
// Namespaced roles are untouched: a Role can only be bound in its own
// namespace, so (role, scope) is 1:1 with the Role and the sparse form would
// produce slightly more objects, not fewer.
func WithRoleAssignments(enabled bool) ConnectorOption {
	return func(opts *ConnectorOpts) error {
		opts.UseRoleAssignments = enabled
		return nil
	}
}

// WithSystemObjectPermissions keeps the permissions Kubernetes' own control-plane
// roles hold on individual objects.
//
// They are dropped by default. Every system: cluster role is bound cluster-wide
// and most of them hold broad rules, so each one lands on every object of every
// synced type — 78% of the object layer on a stock cluster, none of it access
// anyone reviews. What those roles permit stays visible on the api_resource
// targets, where it costs one edge per API resource rather than one per object,
// and a rule naming a specific object is kept either way.
func WithSystemObjectPermissions(enabled bool) ConnectorOption {
	return func(opts *ConnectorOpts) error {
		opts.IncludeSystemObjectPermissions = enabled
		return nil
	}
}

// WithClusterName sets the display name of the singleton cluster resource.
//
// Without it the name falls back to the API server host, which is a poor label
// and sometimes a misleading one: an in-cluster deployment reads its host from
// KUBERNETES_SERVICE_HOST, the ClusterIP of the kubernetes service, so every
// such connector would call its cluster something like "10.96.0.1:443" — the
// same string on every cluster it is meant to distinguish.
//
// The standalone CLI derives this from the kubeconfig. Downstream connectors
// (baton-eks, baton-aks, baton-gke) know the real cloud cluster name and should
// pass it.
func WithClusterName(name string) ConnectorOption {
	return func(opts *ConnectorOpts) error {
		opts.ClusterName = name
		return nil
	}
}

// Kubernetes connector struct.
type Kubernetes struct {
	client kubernetes.Interface
	config *rest.Config
	opts   ConnectorOpts

	// Shared binding caches, valid only for the sync identified by bindingsSyncID.
	roleBindingsCache        []rbacv1.RoleBinding
	clusterRoleBindingsCache []rbacv1.ClusterRoleBinding
	bindingsMutex            sync.RWMutex
	bindingsLoaded           bool
	bindingsSyncID           string

	// Permission index, valid only for the sync identified by permissionsSyncID.
	permissionsMutex  sync.Mutex
	permissionsCache  *PermissionIndex
	permissionsSyncID string
}

// NewFromConfig creates a Kubernetes connector from the typed configuration struct.
// It validates kubeconfig paths, builds a REST config, and registers the
// resource syncers. This is the constructor used by the standalone
// baton-kubernetes CLI, and its signature matches cli.NewConnector so it can be
// handed straight to config.RunConnector.
//
// It deliberately does not narrow the registered resource types by the runtime's
// --sync-resource-types selection: that selection is not authoritative here, and
// registering a subset breaks service mode. See the comment on syncResources
// below. Narrowing is the sync filter's job; cmd/baton-kubernetes supplies the
// default one.
func NewFromConfig(
	ctx context.Context,
	cfg *pkgconfig.Kubernetes,
	_ *cli.ConnectorOpts,
) (connectorbuilder.ConnectorBuilderV2, []connectorbuilder.Opt, error) {
	opt := clioptions.NewConfigFlags(true)

	// --- Kubeconfig source resolution ---
	if cfg.Kubeconfig != "" {
		if _, err := os.Stat(cfg.Kubeconfig); err != nil {
			if os.IsNotExist(err) {
				return nil, nil, fmt.Errorf("specified kubeconfig file does not exist: %s", cfg.Kubeconfig)
			}
			return nil, nil, fmt.Errorf("error accessing kubeconfig file: %w", err)
		}
		opt.KubeConfig = pointer.To(cfg.Kubeconfig)
	} else if cfg.Server == "" {
		// No kubeconfig and no explicit API server. Verify that at least one
		// implicit source is available: the KUBECONFIG env var (a path list
		// honored by client-go's default loading rules), the default kubeconfig
		// file, or an in-cluster service account. client-go silently falls back
		// to localhost:8080 when none exists, which produces a confusing
		// "connection refused" error instead of a missing-auth message.
		//
		// With --server set there is no silent fallback: the connection target is
		// explicit and credentials come from --token, --client-certificate/--client-key
		// or the in-cluster service account, so this check must not run — it would
		// reject the documented bearer-token setup on hosts without a kubeconfig.
		envHasKubeconfig := false
		for _, p := range filepath.SplitList(os.Getenv("KUBECONFIG")) {
			if p == "" {
				continue
			}
			if _, err := os.Stat(filepath.Clean(p)); err == nil {
				envHasKubeconfig = true
				break
			}
		}
		defaultKubeconfig := filepath.Clean(filepath.Join(os.Getenv("HOME"), ".kube", "config"))
		// inClusterTokenPath is the well-known, fixed mount path for the in-cluster
		// service account token; it is not a credential value.
		inClusterTokenPath := "/var/run/secrets/kubernetes.io/serviceaccount/token" //nolint:gosec // well-known in-cluster service account token mount path, not a credential
		_, defaultErr := os.Stat(defaultKubeconfig)
		_, inClusterErr := os.Stat(inClusterTokenPath)
		if !envHasKubeconfig && os.IsNotExist(defaultErr) && os.IsNotExist(inClusterErr) {
			return nil, nil, fmt.Errorf("no kubeconfig available: %s does not exist and no in-cluster service account found; "+
				"provide a kubeconfig via --kubeconfig or the KUBECONFIG environment variable", defaultKubeconfig)
		}
	}

	// --- Populate ConfigFlags from typed struct (zero-value guards replace v.IsSet) ---
	if cfg.ClientCertificate != "" {
		opt.CertFile = pointer.To(cfg.ClientCertificate)
	}
	if cfg.ClientKey != "" {
		opt.KeyFile = pointer.To(cfg.ClientKey)
	}
	if cfg.Token != "" {
		opt.BearerToken = pointer.To(cfg.Token)
	}
	if cfg.As != "" {
		opt.Impersonate = pointer.To(cfg.As)
	}
	if cfg.AsUid != "" {
		opt.ImpersonateUID = pointer.To(cfg.AsUid)
	}
	if len(cfg.AsGroup) > 0 {
		opt.ImpersonateGroup = &cfg.AsGroup
	}
	if cfg.Cluster != "" {
		opt.ClusterName = pointer.To(cfg.Cluster)
	}
	if cfg.User != "" {
		opt.AuthInfoName = pointer.To(cfg.User)
	}
	if cfg.Context != "" {
		opt.Context = pointer.To(cfg.Context)
	}
	if cfg.Server != "" {
		opt.APIServer = pointer.To(cfg.Server)
	}
	if cfg.TlsServerName != "" {
		opt.TLSServerName = pointer.To(cfg.TlsServerName)
	}
	// Bools: always assign (struct zero value matches ConfigFlags default, so harmless)
	opt.Insecure = pointer.To(cfg.InsecureSkipTlsVerify)
	if cfg.CertificateAuthority != "" {
		opt.CAFile = pointer.To(cfg.CertificateAuthority)
	}
	// RequestTimeout: WithDefaultValue("0") means cfg.RequestTimeout is always "0" when unset;
	// ConfigFlags default is also "0", so unconditional assignment is safe.
	opt.Timeout = pointer.To(cfg.RequestTimeout)
	opt.DisableCompression = pointer.To(cfg.DisableCompression)

	// --- Build REST config ---
	l := ctxzap.Extract(ctx)
	restConfig, err := opt.ToRESTConfig()
	if err != nil {
		l.Error("error creating rest config", zap.Error(err))
		return nil, nil, fmt.Errorf("failed to create Kubernetes REST config: %w. Ensure you have a valid kubeconfig file or in-cluster configuration", err)
	}
	if restConfig == nil {
		l.Error("unexpectedly got nil REST config")
		return nil, nil, fmt.Errorf("failed to create Kubernetes REST config: unexpectedly got nil config")
	}

	// --- Assemble syncResources list ---
	// Register every resource type this connector supports, unconditionally.
	//
	// Choosing which types actually sync is the caller's job, not the
	// connector's. In service mode the selection arrives with each sync task
	// ("prefer the task's resource type IDs (from the server/UI) over local
	// config" -- baton-sdk pkg/tasks/c1api/full_sync.go), long after the
	// connector was built from local config alone. A connector that registers
	// only a subset therefore fails as soon as a tenant opts into anything it
	// did not pre-register, because the SDK validates the task's filter against
	// the types the connector advertised:
	//
	//	invalid resource type 'configmap' in filter
	//
	// The core-RBAC-only default instead lives where the selection is visible:
	// the runner's default filter in cmd/baton-kubernetes for local runs, and
	// the OptInRequired annotations on the workload types, which are what stop
	// the platform offering them unless a tenant asks. OptInRequired is a
	// platform-side signal only -- the SDK syncer never reads it -- so it
	// cannot substitute for that filter locally.
	//
	// That includes the sparse types. They are declared in the capabilities
	// manifest with OptInRequired, so a tenant can select them from the UI, and
	// registering them conditionally would reproduce the same failure for
	// 'role_assignment'. Their builders emit nothing while the flag is off, so
	// registering them unconditionally leaves the flat model's output untouched.
	syncResources := DeclaredResourceTypeIDs()

	k, err := New(ctx, restConfig,
		WithSyncResources(syncResources),
		WithRoleAssignments(cfg.UseRoleAssignments),
		WithSystemObjectPermissions(cfg.IncludeSystemObjectPermissions),
		WithClusterName(clusterNameFromConfig(opt, cfg)),
	)
	if err != nil {
		return nil, nil, err
	}
	return k, nil, nil
}

// clusterNameFromConfig picks a human-meaningful name for the cluster resource
// from whatever the operator supplied, preferring what they named explicitly.
//
// It returns "" when there is no name to be had, which is the normal case for an
// in-cluster deployment; the caller then falls back to the API server host, and
// past that to a plain label.
func clusterNameFromConfig(opt *clioptions.ConfigFlags, cfg *pkgconfig.Kubernetes) string {
	if cfg.Cluster != "" {
		return cfg.Cluster
	}
	if cfg.Context != "" {
		return cfg.Context
	}
	// With --server the kubeconfig is not what is being talked to, and reading a
	// name from it would be worse than reading none: RawConfig returns the merged
	// config without overrides applied (clientcmd.DirectClientConfig.RawConfig —
	// MergedRawConfig is the one that applies them), so a machine pointed at prod
	// by --server while holding a stale ~/.kube/config would label the cluster
	// after whatever that file's current context happens to be. Fall through to
	// the host, which is at least the address in use.
	if cfg.Server != "" {
		return ""
	}
	raw, err := opt.ToRawKubeConfigLoader().RawConfig()
	if err != nil {
		return ""
	}
	// The current context's cluster is the specific thing being talked to; the
	// context name is a reasonable second best when it names no cluster.
	if kubeCtx, ok := raw.Contexts[raw.CurrentContext]; ok && kubeCtx.Cluster != "" {
		return kubeCtx.Cluster
	}
	return raw.CurrentContext
}

// New creates a Kubernetes connector from a pre-built REST config.
// This is the library entry point consumed by downstream connectors
// (baton-eks, baton-aks, baton-gke), which build their own REST configs
// with cloud-specific authentication — its signature must remain stable.
// The standalone CLI goes through NewFromConfig instead.
func New(ctx context.Context, cfg *rest.Config, opts ...ConnectorOption) (*Kubernetes, error) {
	// Validate that config is not nil
	if cfg == nil {
		return nil, fmt.Errorf("kubernetes REST config cannot be nil")
	}

	options := ConnectorOpts{}

	// Apply option functions
	for _, opt := range opts {
		err := opt(&options)
		if err != nil {
			return nil, fmt.Errorf("applying option: %w", err)
		}
	}

	// Extract TLS config from Kubernetes config to apply to custom HTTP client
	tlsConfig, err := rest.TLSConfigFor(cfg)
	if err != nil {
		return nil, fmt.Errorf("getting TLS config from kubernetes config: %w", err)
	}

	// Build uhttp options
	uhttpOpts := []uhttp.Option{
		uhttp.WithLogger(true, ctxzap.Extract(ctx)),
	}

	// Apply TLS config if present
	if tlsConfig != nil {
		uhttpOpts = append(uhttpOpts, uhttp.WithTLSClientConfig(tlsConfig))
	}

	// Create kubernetes client
	httpClient, err := uhttp.NewClient(ctx, uhttpOpts...)
	if err != nil {
		return nil, fmt.Errorf("creating HTTP client: %w", err)
	}

	// Apply authentication and transport wrappers from config (bearer token, basic auth, client certs, impersonation, etc.)
	// This wraps the uhttp.Transport with authentication layers while preserving uhttp features
	// (logging, user-agent, etc.) since the underlying uhttp.Transport remains in the chain
	if httpClient.Transport != nil {
		wrappedTransport, err := rest.HTTPWrappersForConfig(cfg, httpClient.Transport)
		if err != nil {
			return nil, fmt.Errorf("wrapping HTTP transport: %w", err)
		}
		httpClient.Transport = wrappedTransport
	}

	client, err := kubernetes.NewForConfigAndClient(cfg, httpClient)
	if err != nil {
		return nil, fmt.Errorf("creating kubernetes client: %w", err)
	}

	return &Kubernetes{
		client:                   client,
		config:                   cfg,
		opts:                     options,
		roleBindingsCache:        make([]rbacv1.RoleBinding, 0),
		clusterRoleBindingsCache: make([]rbacv1.ClusterRoleBinding, 0),
	}, nil
}

// ResourceSyncers returns the resource syncers for the Kubernetes connector.
func (k *Kubernetes) ResourceSyncers(ctx context.Context) []connectorbuilder.ResourceSyncerV2 {
	// Map resource type IDs to their builder functions
	builders := map[string]ResourceSyncerBuilder{
		ResourceTypeNamespace.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncerV2 {
			return newNamespaceBuilder(k.client, k.permissions())
		},
		ResourceTypeServiceAccount.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncerV2 {
			return newServiceAccountBuilder(k.client, k.permissions())
		},
		ResourceTypeRole.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncerV2 {
			return newRoleBuilder(k.client, k)
		},
		ResourceTypeClusterRole.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncerV2 {
			return newClusterRoleBuilder(k.client, k, k.opts.UseRoleAssignments)
		},
		ResourceTypeCluster.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncerV2 {
			return newClusterBuilder(k.opts.ClusterName, k.config.Host)
		},
		ResourceTypeRoleAssignment.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncerV2 {
			return newRoleAssignmentBuilder(k.client, k, k.opts.UseRoleAssignments)
		},
		ResourceTypeAPIResource.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncerV2 {
			return newAPIResourceBuilder(k)
		},
		ResourceTypeSecret.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncerV2 {
			return newSecretBuilder(k.client, k.permissions())
		},
		ResourceTypeConfigMap.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncerV2 {
			return newConfigMapBuilder(k.client, k.permissions())
		},
		ResourceTypeNode.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncerV2 {
			return newNodeBuilder(k.client, k.permissions())
		},
		ResourceTypeDeployment.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncerV2 {
			return newDeploymentBuilder(k.client, k.permissions())
		},
		ResourceTypeStatefulSet.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncerV2 {
			return newStatefulSetBuilder(k.client, k.permissions())
		},
		ResourceTypeDaemonSet.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncerV2 {
			return newDaemonSetBuilder(k.client, k.permissions())
		},
		ResourceTypePod.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncerV2 {
			return newPodBuilder(k.client, k.permissions())
		},
		ResourceTypeKubeUser.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncerV2 {
			return newKubeUserBuilder(k.client)
		},
		ResourceTypeKubeGroup.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncerV2 {
			return newKubeGroupBuilder(k.client)
		},
	}

	var syncers []connectorbuilder.ResourceSyncerV2

	// Override dafault syncers with custom from opts if exists.
	if k.opts.CustomSyncer != nil {
		for key, builder := range k.opts.CustomSyncer {
			if _, ok := builders[key]; ok {
				builders[key] = builder
			}
		}
	}

	// If SyncResources is empty, sync everything
	if len(k.opts.SyncResources) == 0 {
		for _, builder := range builders {
			syncers = append(syncers, builder(&k.client, k))
		}
		return syncers
	}

	// Otherwise, only sync the requested resources
	for _, id := range k.opts.SyncResources {
		if builder, ok := builders[id]; ok {
			syncers = append(syncers, builder(&k.client, k))
		}
	}

	return syncers
}

// permissions returns the resolver object builders use to find which roles confer
// their objects' permissions.
//
// Not gated on anything: selecting a resource type is what asks for its access
// data. A type that syncs its objects but not the access to them would be
// inventory, which is not what anyone selects a resource type for.
func (k *Kubernetes) permissions() *permissionResolver {
	return &permissionResolver{provider: k}
}

// PermissionIndex returns this sync's permission index, building it once and
// caching it for the sync that asked.
//
// Built whole rather than incrementally: a class is only complete once every
// binding has been walked, so assembling it page by page would emit the same
// class repeatedly with a partial verb list, and because resources upsert on
// (id, sync) the last partial write would win. The cache is keyed on the sync ID
// for the same reason the binding caches are — a long-lived connector in service
// mode must never serve one sync's derived state to the next.
func (k *Kubernetes) PermissionIndex(ctx context.Context, syncID string) (*PermissionIndex, error) {
	k.permissionsMutex.Lock()
	defer k.permissionsMutex.Unlock()

	if k.permissionsCache != nil && k.permissionsSyncID == syncID {
		return k.permissionsCache, nil
	}

	index, err := buildPermissionIndex(ctx, k.client, k, syncID, k.opts.UseRoleAssignments, k.opts.IncludeSystemObjectPermissions)
	if err != nil {
		return nil, err
	}

	k.permissionsCache = index
	k.permissionsSyncID = syncID
	return index, nil
}

// Metadata returns the connector metadata.
func (k *Kubernetes) Metadata(ctx context.Context) (*v2.ConnectorMetadata, error) {
	return &v2.ConnectorMetadata{
		DisplayName: connectorDisplayName,
		Description: connectorDescription,
	}, nil
}

// DefaultCapabilitiesBuilder returns every resource type unconditionally so the
// generated capabilities manifest is always complete, regardless of how a given
// deployment narrows the sync with --sync-resource-types. The opt-in workload
// types are declared here too; their OptInRequired annotations mark them as
// excluded from the default sync.
//
// It needs no Kubernetes client: capabilities generation only reads each
// syncer's ResourceType and checks which optional interfaces it implements.
func DefaultCapabilitiesBuilder() connectorbuilder.ConnectorBuilderV2 {
	return &defaultCapabilitiesBuilder{}
}

type defaultCapabilitiesBuilder struct{}

func (d *defaultCapabilitiesBuilder) Metadata(_ context.Context) (*v2.ConnectorMetadata, error) {
	return &v2.ConnectorMetadata{
		DisplayName: connectorDisplayName,
		Description: connectorDescription,
	}, nil
}

func (d *defaultCapabilitiesBuilder) Validate(_ context.Context) (annotations.Annotations, error) {
	return nil, nil
}

func (d *defaultCapabilitiesBuilder) ResourceSyncers(_ context.Context) []connectorbuilder.ResourceSyncerV2 {
	return []connectorbuilder.ResourceSyncerV2{
		newNamespaceBuilder(nil, nil),
		newServiceAccountBuilder(nil, nil),
		newRoleBuilder(nil, nil),
		newClusterRoleBuilder(nil, nil, false),
		newClusterBuilder("", ""),
		newRoleAssignmentBuilder(nil, nil, true),
		newAPIResourceBuilder(nil),
		newKubeUserBuilder(nil),
		newKubeGroupBuilder(nil),
		newConfigMapBuilder(nil, nil),
		newSecretBuilder(nil, nil),
		newPodBuilder(nil, nil),
		newNodeBuilder(nil, nil),
		newDeploymentBuilder(nil, nil),
		newStatefulSetBuilder(nil, nil),
		newDaemonSetBuilder(nil, nil),
	}
}

// Validate validates the connector configuration.
func (k *Kubernetes) Validate(ctx context.Context) (annotations.Annotations, error) {
	// Try to list namespaces as a simple connectivity test
	_, err := k.client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil {
		// Check for different types of errors to provide better messages
		switch {
		case k8serrors.IsUnauthorized(err):
			return nil, fmt.Errorf("unauthorized access to Kubernetes API: %w", err)
		case k8serrors.IsForbidden(err):
			return nil, fmt.Errorf("forbidden access to Kubernetes API (check RBAC permissions): %w", err)
		default:
			return nil, fmt.Errorf("validating kubernetes connection: %w", err)
		}
	}

	return nil, nil
}

// loadBindingsCaches ensures that both binding caches hold data for the given
// sync, reloading them from the API when they were populated by an earlier one.
//
// The caches are scoped to a single sync, but the Kubernetes struct lives for
// the whole process. In service mode a cache loaded during the first sync would
// otherwise be reused forever, freezing every role and cluster role grant at the
// state of that first sync — add a RoleBinding and no later sync notices.
//
// Keying on the sync ID makes that invalidation a property of this shared code
// path. An earlier fix hooked it into roleBuilder.List and clusterRoleBuilder.List
// instead, which cannot work for the downstream connectors (baton-eks, baton-aks,
// baton-gke): they replace both builders through WithCustomSyncers while still
// resolving grants through these caches, so the hook never ran for them.
//
// An empty sync ID (no active sync, e.g. a direct library call) caches under ""
// and behaves as before — there is no identifier to distinguish callers by.
func (k *Kubernetes) loadBindingsCaches(ctx context.Context, syncID string) error {
	k.bindingsMutex.RLock()
	if k.bindingsLoaded && k.bindingsSyncID == syncID {
		k.bindingsMutex.RUnlock()
		return nil
	}
	k.bindingsMutex.RUnlock()

	// Need to load the caches
	k.bindingsMutex.Lock()
	defer k.bindingsMutex.Unlock()

	// Double-check pattern
	if k.bindingsLoaded && k.bindingsSyncID == syncID {
		return nil
	}

	l := ctxzap.Extract(ctx)
	l.Debug("loading role bindings and cluster role bindings caches")

	// Fetch all RoleBindings across all namespaces
	var allRoleBindings []rbacv1.RoleBinding
	continueToken := ""

	for {
		opts := metav1.ListOptions{
			Limit:    ResourcesPageSize,
			Continue: continueToken,
		}

		bindings, err := k.client.RbacV1().RoleBindings("").List(ctx, opts)
		if err != nil {
			return fmt.Errorf("listing role bindings: %w", err)
		}

		allRoleBindings = append(allRoleBindings, bindings.Items...)

		// If no continue token, we're done
		if bindings.Continue == "" {
			break
		}

		// Update token for next page
		continueToken = bindings.Continue
	}

	// Fetch all ClusterRoleBindings
	var allClusterRoleBindings []rbacv1.ClusterRoleBinding
	continueToken = ""

	for {
		opts := metav1.ListOptions{
			Limit:    ResourcesPageSize,
			Continue: continueToken,
		}

		bindings, err := k.client.RbacV1().ClusterRoleBindings().List(ctx, opts)
		if err != nil {
			return fmt.Errorf("listing cluster role bindings: %w", err)
		}

		allClusterRoleBindings = append(allClusterRoleBindings, bindings.Items...)

		// If no continue token, we're done
		if bindings.Continue == "" {
			break
		}

		// Update token for next page
		continueToken = bindings.Continue
	}

	k.roleBindingsCache = allRoleBindings
	k.clusterRoleBindingsCache = allClusterRoleBindings
	k.bindingsLoaded = true
	k.bindingsSyncID = syncID
	l.Debug("bindings caches loaded",
		zap.Int("roleBindings", len(allRoleBindings)),
		zap.Int("clusterRoleBindings", len(allClusterRoleBindings)))

	return nil
}

// AllBindings returns every RoleBinding and ClusterRoleBinding in the cluster,
// loading the shared cache for this sync if needed.
//
// The role assignment builder needs the whole set at once because it groups
// bindings by (cluster role, scope): a pair is only complete once every binding
// contributing to it has been seen, so it cannot be assembled from the
// per-role lookups the other builders use.
func (k *Kubernetes) AllBindings(ctx context.Context, syncID string) ([]rbacv1.RoleBinding, []rbacv1.ClusterRoleBinding, error) {
	if err := k.loadBindingsCaches(ctx, syncID); err != nil {
		return nil, nil, fmt.Errorf("failed to load bindings cache: %w", err)
	}

	k.bindingsMutex.RLock()
	defer k.bindingsMutex.RUnlock()

	// Copy: callers must not observe later mutation of the cache, and the caller
	// here outlives the read lock.
	roleBindings := make([]rbacv1.RoleBinding, len(k.roleBindingsCache))
	copy(roleBindings, k.roleBindingsCache)
	clusterRoleBindings := make([]rbacv1.ClusterRoleBinding, len(k.clusterRoleBindingsCache))
	copy(clusterRoleBindings, k.clusterRoleBindingsCache)

	return roleBindings, clusterRoleBindings, nil
}

// GetMatchingRoleBindings returns all RoleBindings that reference the specified Role.
//
// syncID scopes the shared binding cache; pass resource.SyncOpAttrs.SyncID from
// the calling sync operation so a long-lived connector does not serve one sync's
// bindings to the next.
func (k *Kubernetes) GetMatchingRoleBindings(ctx context.Context, syncID, namespace, roleName string) ([]rbacv1.RoleBinding, error) {
	// Ensure bindings cache is loaded
	if err := k.loadBindingsCaches(ctx, syncID); err != nil {
		return nil, fmt.Errorf("failed to load bindings cache: %w", err)
	}

	// Get matching role bindings
	k.bindingsMutex.RLock()
	defer k.bindingsMutex.RUnlock()

	var result []rbacv1.RoleBinding
	for _, binding := range k.roleBindingsCache {
		if binding.Namespace == namespace && binding.RoleRef.Kind == RBACKindRole && binding.RoleRef.Name == roleName {
			result = append(result, binding)
		}
	}

	return result, nil
}

// GetMatchingBindingsForClusterRole returns all RoleBindings and ClusterRoleBindings that reference the specified ClusterRole.
//
// syncID scopes the shared binding cache; see GetMatchingRoleBindings.
func (k *Kubernetes) GetMatchingBindingsForClusterRole(ctx context.Context, syncID, clusterRoleName string) ([]rbacv1.RoleBinding, []rbacv1.ClusterRoleBinding, error) {
	// Ensure bindings cache is loaded
	if err := k.loadBindingsCaches(ctx, syncID); err != nil {
		return nil, nil, fmt.Errorf("failed to load bindings cache: %w", err)
	}

	// Get matching role bindings and cluster role bindings
	k.bindingsMutex.RLock()
	defer k.bindingsMutex.RUnlock()

	var roleBindings []rbacv1.RoleBinding
	for _, binding := range k.roleBindingsCache {
		if binding.RoleRef.Kind == "ClusterRole" && binding.RoleRef.Name == clusterRoleName {
			roleBindings = append(roleBindings, binding)
		}
	}

	var clusterRoleBindings []rbacv1.ClusterRoleBinding
	for _, binding := range k.clusterRoleBindingsCache {
		if binding.RoleRef.Kind == "ClusterRole" && binding.RoleRef.Name == clusterRoleName {
			clusterRoleBindings = append(clusterRoleBindings, binding)
		}
	}

	return roleBindings, clusterRoleBindings, nil
}
