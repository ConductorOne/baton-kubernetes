package connector

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	pkgconfig "github.com/conductorone/baton-kubernetes/pkg/config"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	rbacv1 "k8s.io/api/rbac/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	clioptions "k8s.io/cli-runtime/pkg/genericclioptions"
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
type ResourceSyncerBuilder func(*kubernetes.Interface, *Kubernetes) connectorbuilder.ResourceSyncer

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

// secretsScanResult is the sealed result produced by kubeUserBuilder.List() Phase 3.
// It is built page-by-page into secretsAccumulator and sealed on the last secrets page.
// kubeGroupBuilder.Grants() reads secretsResult directly — no independent scanning.
type secretsScanResult struct {
	// Usernames holds deduplicated x509 CommonNames.
	// Only non-empty CNs are included (matching original kubeUserBuilder Phase 3 behavior).
	Usernames []string
	// GroupMembers maps Kubernetes group name (x509 Organization field) to principal names.
	// Falls back to the kubeconfig username key when CN is empty (preserving original Grants behavior).
	GroupMembers map[string][]string
}

// Kubernetes connector struct.
type Kubernetes struct {
	client kubernetes.Interface
	config *rest.Config
	opts   ConnectorOpts

	// Shared binding caches
	roleBindingsCache        []rbacv1.RoleBinding
	clusterRoleBindingsCache []rbacv1.ClusterRoleBinding
	bindingsMutex            sync.RWMutex
	bindingsLoaded           bool

	// Secrets scan cache: written by kubeUserBuilder Phase 3, read by kubeGroupBuilder Grants.
	secretsAccumulator *secretsScanResult // live during Phase 3 pagination
	secretsResult      *secretsScanResult // sealed after Phase 3 last page; read-only thereafter
	secretsMu          sync.RWMutex
}

// NewFromConfig creates a Kubernetes connector from the typed configuration struct.
// It validates kubeconfig paths, builds a REST config, and assembles the
// list of resource types to sync. This is the constructor used by the
// standalone baton-kubernetes CLI.
//
// syncResourceTypes is the user's --sync-resource-types selection (the SDK's
// built-in flag, also populated by the C1 resource type selector). When empty,
// the default core RBAC set is synced; when set, exactly the requested types
// are registered.
func NewFromConfig(ctx context.Context, cfg *pkgconfig.Kubernetes, syncResourceTypes []string) (*Kubernetes, error) {
	opt := clioptions.NewConfigFlags(true)

	// --- Kubeconfig source resolution ---
	if cfg.Kubeconfig != "" {
		if _, err := os.Stat(cfg.Kubeconfig); err != nil {
			if os.IsNotExist(err) {
				return nil, fmt.Errorf("specified kubeconfig file does not exist: %s", cfg.Kubeconfig)
			}
			return nil, fmt.Errorf("error accessing kubeconfig file: %w", err)
		}
		opt.KubeConfig = pointer.To(cfg.Kubeconfig)
	} else {
		// No explicit kubeconfig source. Verify that at least one implicit source
		// is available: the KUBECONFIG env var (a path list honored by client-go's
		// default loading rules), the default kubeconfig file, or an in-cluster
		// service account. client-go silently falls back to localhost:8080 when
		// none exists, which produces a confusing "connection refused" error
		// instead of a missing-auth message.
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
			return nil, fmt.Errorf("no kubeconfig available: %s does not exist and no in-cluster service account found; "+
				"provide a kubeconfig via --kubeconfig or the KUBECONFIG environment variable", defaultKubeconfig)
		}
	}

	// --- Populate ConfigFlags from typed struct (zero-value guards replace v.IsSet) ---
	if cfg.CacheDir != "" {
		opt.CacheDir = pointer.To(cfg.CacheDir)
	}
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
	if cfg.Username != "" {
		opt.Username = pointer.To(cfg.Username)
	}
	if cfg.Password != "" {
		opt.Password = pointer.To(cfg.Password)
	}
	if cfg.Cluster != "" {
		opt.ClusterName = pointer.To(cfg.Cluster)
	}
	if cfg.User != "" {
		opt.AuthInfoName = pointer.To(cfg.User)
	}
	if cfg.Namespace != "" {
		opt.Namespace = pointer.To(cfg.Namespace)
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
		return nil, fmt.Errorf("failed to create Kubernetes REST config: %w. Ensure you have a valid kubeconfig file or in-cluster configuration", err)
	}
	if restConfig == nil {
		l.Error("unexpectedly got nil REST config")
		return nil, fmt.Errorf("failed to create Kubernetes REST config: unexpectedly got nil config")
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
	if len(syncResourceTypes) > 0 {
		knownTypes := make(map[string]bool, len(AllResourceTypeIDs))
		for _, id := range AllResourceTypeIDs {
			knownTypes[id] = true
		}
		// Deduplicate: users may repeat entries, and the SDK's env-var binding
		// (BATON_SYNC_RESOURCE_TYPES) can deliver the same value twice.
		seen := make(map[string]bool, len(syncResourceTypes))
		syncResources = syncResources[:0]
		for _, id := range syncResourceTypes {
			if !knownTypes[id] {
				ctxzap.Extract(ctx).Warn("ignoring unknown resource type in sync-resource-types", zap.String("resource_type", id))
				continue
			}
			if seen[id] {
				continue
			}
			seen[id] = true
			syncResources = append(syncResources, id)
		}
		if len(syncResources) == 0 {
			return nil, fmt.Errorf("sync-resource-types matched no known resource types: %v", syncResourceTypes)
		}
	}

	return New(ctx, restConfig, WithSyncResources(syncResources))
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
func (k *Kubernetes) ResourceSyncers(ctx context.Context) []connectorbuilder.ResourceSyncer {
	// Map resource type IDs to their builder functions
	builders := map[string]ResourceSyncerBuilder{
		ResourceTypeNamespace.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncer {
			return newNamespaceBuilder(k.client)
		},
		ResourceTypeServiceAccount.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncer {
			return newServiceAccountBuilder(k.client)
		},
		ResourceTypeRole.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncer {
			return newRoleBuilder(k.client, k)
		},
		ResourceTypeClusterRole.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncer {
			return newClusterRoleBuilder(k.client, k)
		},
		ResourceTypeSecret.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncer {
			return newSecretBuilder(k.client)
		},
		ResourceTypeConfigMap.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncer {
			return newConfigMapBuilder(k.client)
		},
		ResourceTypeNode.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncer {
			return newNodeBuilder(k.client)
		},
		ResourceTypeDeployment.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncer {
			return newDeploymentBuilder(k.client)
		},
		ResourceTypeStatefulSet.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncer {
			return newStatefulSetBuilder(k.client)
		},
		ResourceTypeDaemonSet.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncer {
			return newDaemonSetBuilder(k.client)
		},
		ResourceTypePod.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncer {
			return newPodBuilder(k.client)
		},
		ResourceTypeKubeUser.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncer {
			return newKubeUserBuilder(k.client, k)
		},
		ResourceTypeKubeGroup.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncer {
			return newKubeGroupBuilder(k.client, k)
		},
	}

	var syncers []connectorbuilder.ResourceSyncer

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
func DefaultCapabilitiesBuilder() connectorbuilder.ConnectorBuilder {
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

func (d *defaultCapabilitiesBuilder) ResourceSyncers(_ context.Context) []connectorbuilder.ResourceSyncer {
	return []connectorbuilder.ResourceSyncer{
		newNamespaceBuilder(nil),
		newServiceAccountBuilder(nil),
		newRoleBuilder(nil, nil),
		newClusterRoleBuilder(nil, nil),
		newKubeUserBuilder(nil, nil),
		newKubeGroupBuilder(nil, nil),
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

// loadBindingsCaches ensures that both binding caches are loaded
// It uses a mutex to ensure thread safety.
func (k *Kubernetes) loadBindingsCaches(ctx context.Context) error {
	k.bindingsMutex.RLock()
	if k.bindingsLoaded {
		k.bindingsMutex.RUnlock()
		return nil
	}
	k.bindingsMutex.RUnlock()

	// Need to load the caches
	k.bindingsMutex.Lock()
	defer k.bindingsMutex.Unlock()

	// Double-check pattern
	if k.bindingsLoaded {
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
	l.Debug("bindings caches loaded",
		zap.Int("roleBindings", len(allRoleBindings)),
		zap.Int("clusterRoleBindings", len(allClusterRoleBindings)))

	return nil
}

// GetMatchingRoleBindings returns all RoleBindings that reference the specified Role.
func (k *Kubernetes) GetMatchingRoleBindings(ctx context.Context, namespace, roleName string) ([]rbacv1.RoleBinding, error) {
	// Ensure bindings cache is loaded
	if err := k.loadBindingsCaches(ctx); err != nil {
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
func (k *Kubernetes) GetMatchingBindingsForClusterRole(ctx context.Context, clusterRoleName string) ([]rbacv1.RoleBinding, []rbacv1.ClusterRoleBinding, error) {
	// Ensure bindings cache is loaded
	if err := k.loadBindingsCaches(ctx); err != nil {
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
