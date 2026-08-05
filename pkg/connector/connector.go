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
}

// NewFromConfig creates a Kubernetes connector from the typed configuration struct.
// It validates kubeconfig paths, builds a REST config, and assembles the
// list of resource types to sync. This is the constructor used by the
// standalone baton-kubernetes CLI, and its signature matches cli.NewConnector so
// it can be handed straight to config.RunConnector.
//
// connectorOpts carries the runtime's --sync-resource-types selection (the SDK's
// built-in flag, also populated by the C1 resource type selector). When the user
// has not narrowed the selection, the default core RBAC set is synced; when they
// have, exactly the requested types are registered.
func NewFromConfig(
	ctx context.Context,
	cfg *pkgconfig.Kubernetes,
	connectorOpts *cli.ConnectorOpts,
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
	// By default only the core RBAC resource types are synced: the workload and
	// configuration types expose verb entitlements that never produce grants,
	// resulting in noisy partial resources in ConductorOne. An explicit
	// --sync-resource-types selection overrides the default entirely and
	// registers exactly the requested types.
	syncResources := []string{
		ResourceTypeNamespace.Id,
		ResourceTypeServiceAccount.Id,
		ResourceTypeRole.Id,
		ResourceTypeClusterRole.Id,
		ResourceTypeKubeUser.Id,
		ResourceTypeKubeGroup.Id,
	}
	if connectorOpts != nil && connectorOpts.SyncFilterIsExplicit() {
		// Walk the connector's own type list rather than the user's slice: it
		// filters out ids this connector does not implement and deduplicates in
		// one step. Both matter — the SDK's env-var binding
		// (BATON_SYNC_RESOURCE_TYPES) can deliver a value twice, and registering
		// a duplicate resource type is a hard error in the SDK builder.
		syncResources = syncResources[:0]
		for _, id := range AllResourceTypeIDs {
			if connectorOpts.WillSyncResourceType(id) {
				syncResources = append(syncResources, id)
			}
		}
		if len(syncResources) == 0 {
			return nil, nil, fmt.Errorf("sync-resource-types matched no known resource types: %v", connectorOpts.SyncResourceTypeIDs)
		}
	}

	k, err := New(ctx, restConfig, WithSyncResources(syncResources))
	if err != nil {
		return nil, nil, err
	}
	return k, nil, nil
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
			return newNamespaceBuilder(k.client)
		},
		ResourceTypeServiceAccount.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncerV2 {
			return newServiceAccountBuilder(k.client)
		},
		ResourceTypeRole.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncerV2 {
			return newRoleBuilder(k.client, k)
		},
		ResourceTypeClusterRole.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncerV2 {
			return newClusterRoleBuilder(k.client, k)
		},
		ResourceTypeSecret.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncerV2 {
			return newSecretBuilder(k.client)
		},
		ResourceTypeConfigMap.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncerV2 {
			return newConfigMapBuilder(k.client)
		},
		ResourceTypeNode.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncerV2 {
			return newNodeBuilder(k.client)
		},
		ResourceTypeDeployment.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncerV2 {
			return newDeploymentBuilder(k.client)
		},
		ResourceTypeStatefulSet.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncerV2 {
			return newStatefulSetBuilder(k.client)
		},
		ResourceTypeDaemonSet.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncerV2 {
			return newDaemonSetBuilder(k.client)
		},
		ResourceTypePod.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncerV2 {
			return newPodBuilder(k.client)
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
		newNamespaceBuilder(nil),
		newServiceAccountBuilder(nil),
		newRoleBuilder(nil, nil),
		newClusterRoleBuilder(nil, nil),
		newKubeUserBuilder(nil),
		newKubeGroupBuilder(nil),
		newConfigMapBuilder(nil),
		newSecretBuilder(nil),
		newPodBuilder(nil),
		newNodeBuilder(nil),
		newDeploymentBuilder(nil),
		newStatefulSetBuilder(nil),
		newDaemonSetBuilder(nil),
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
