package connector

import (
	"context"
	"fmt"
	"sync"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/conductorone/baton-sdk/pkg/uhttp"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	rbacv1 "k8s.io/api/rbac/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	ResourceTypeClusterRoleBindings = "clusterrolebindings"
	ResourceTypeClusterRoleBinding  = "clusterrolebinding"
	ResourceTypeRoleBindings        = "rolebindings"
	ResourceTypeRoleBinding         = "rolebinding"
	SubjectTypeGroup                = "Group"
	SubjectTypeUser                 = "User"
)

// Resource type definitions.
var (
	ResourceTypeNamespace      = &v2.ResourceType{Id: "namespace", DisplayName: "Namespace"}
	ResourceTypeServiceAccount = &v2.ResourceType{Id: "service_account", DisplayName: "Service Account", Traits: []v2.ResourceType_Trait{v2.ResourceType_TRAIT_USER}}
	ResourceTypeRole           = &v2.ResourceType{Id: "role", DisplayName: "Role", Traits: []v2.ResourceType_Trait{v2.ResourceType_TRAIT_ROLE}}
	ResourceTypeClusterRole    = &v2.ResourceType{Id: "cluster_role", DisplayName: "Cluster Role", Traits: []v2.ResourceType_Trait{v2.ResourceType_TRAIT_ROLE}}
	ResourceTypeSecret         = &v2.ResourceType{Id: "secret", DisplayName: "Secret", Traits: []v2.ResourceType_Trait{v2.ResourceType_TRAIT_SECRET}}
	ResourceTypeConfigMap      = &v2.ResourceType{Id: "configmap", DisplayName: "Config Map"}
	ResourceTypeNode           = &v2.ResourceType{Id: "node", DisplayName: "Node"}
	ResourceTypePod            = &v2.ResourceType{Id: "pod", DisplayName: "Pod"}
	ResourceTypeDeployment     = &v2.ResourceType{Id: "deployment", DisplayName: "Deployment"}
	ResourceTypeStatefulSet    = &v2.ResourceType{Id: "statefulset", DisplayName: "Stateful Set"}
	ResourceTypeDaemonSet      = &v2.ResourceType{Id: "daemonset", DisplayName: "Daemon Set"}
	ResourceTypeKubeUser       = &v2.ResourceType{Id: "kube_user", DisplayName: "Kubernetes User", Traits: []v2.ResourceType_Trait{v2.ResourceType_TRAIT_USER}}
	ResourceTypeKubeGroup      = &v2.ResourceType{Id: "kube_group", DisplayName: "Kubernetes Group", Traits: []v2.ResourceType_Trait{v2.ResourceType_TRAIT_GROUP}}
	ResourceTypeBinding        = &v2.ResourceType{Id: "binding", DisplayName: "Binding", Description: "Internal type for processing RBAC bindings"}
	ResourceTypeUser           = &v2.ResourceType{Id: "user", DisplayName: "User", Traits: []v2.ResourceType_Trait{v2.ResourceType_TRAIT_USER}}
	ResourceTypeGroup          = &v2.ResourceType{Id: "group", DisplayName: "Group", Traits: []v2.ResourceType_Trait{v2.ResourceType_TRAIT_GROUP}}
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
}

// New creates a new Kubernetes connector.
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
			return newKubeUserBuilder(k.client)
		},
		ResourceTypeKubeGroup.Id: func(i *kubernetes.Interface, k *Kubernetes) connectorbuilder.ResourceSyncer {
			return newKubeGroupBuilder(k.client)
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
		DisplayName: "Kubernetes",
		Description: "Connector for Kubernetes resources and RBAC permissions",
	}, nil
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
		if binding.Namespace == namespace && binding.RoleRef.Kind == "Role" && binding.RoleRef.Name == roleName {
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
