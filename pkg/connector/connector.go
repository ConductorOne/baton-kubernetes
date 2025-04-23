package connector

import (
	"context"
	"fmt"
	"sync"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/connectorbuilder"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
	rbacv1 "k8s.io/api/rbac/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

// Resource type definitions
var (
	resourceTypeNamespace      = &v2.ResourceType{Id: "namespace", DisplayName: "Namespace"}
	resourceTypeServiceAccount = &v2.ResourceType{Id: "service_account", DisplayName: "Service Account", Traits: []v2.ResourceType_Trait{v2.ResourceType_TRAIT_USER}}
	resourceTypeRole           = &v2.ResourceType{Id: "role", DisplayName: "Role", Traits: []v2.ResourceType_Trait{v2.ResourceType_TRAIT_ROLE}}
	resourceTypeClusterRole    = &v2.ResourceType{Id: "cluster_role", DisplayName: "Cluster Role", Traits: []v2.ResourceType_Trait{v2.ResourceType_TRAIT_ROLE}}
	resourceTypeSecret         = &v2.ResourceType{Id: "secret", DisplayName: "Secret", Traits: []v2.ResourceType_Trait{v2.ResourceType_TRAIT_SECRET}}
	resourceTypeConfigMap      = &v2.ResourceType{Id: "configmap", DisplayName: "Config Map"}
	resourceTypeNode           = &v2.ResourceType{Id: "node", DisplayName: "Node"}
	resourceTypePod            = &v2.ResourceType{Id: "pod", DisplayName: "Pod"}
	resourceTypeDeployment     = &v2.ResourceType{Id: "deployment", DisplayName: "Deployment"}
	resourceTypeStatefulSet    = &v2.ResourceType{Id: "statefulset", DisplayName: "Stateful Set"}
	resourceTypeDaemonSet      = &v2.ResourceType{Id: "daemonset", DisplayName: "Daemon Set"}
	resourceTypeKubeUser       = &v2.ResourceType{Id: "kube_user", DisplayName: "Kubernetes User", Traits: []v2.ResourceType_Trait{v2.ResourceType_TRAIT_USER}}
	resourceTypeKubeGroup      = &v2.ResourceType{Id: "kube_group", DisplayName: "Kubernetes Group", Traits: []v2.ResourceType_Trait{v2.ResourceType_TRAIT_GROUP}}
	resourceTypeBinding        = &v2.ResourceType{Id: "binding", DisplayName: "Binding", Description: "Internal type for processing RBAC bindings"}
)

// Configuration options
type connectorOpts struct {
	SyncPods bool
}

// ConnectorOption is a function that configures the connector options
type ConnectorOption func(*connectorOpts) error

// WithSyncPods configures the connector to sync pods
func WithSyncPods(syncPods bool) ConnectorOption {
	return func(opts *connectorOpts) error {
		opts.SyncPods = syncPods
		return nil
	}
}

// Kubernetes connector struct
type Kubernetes struct {
	client kubernetes.Interface
	config *rest.Config
	opts   connectorOpts

	// Shared binding caches
	roleBindingsCache        []rbacv1.RoleBinding
	clusterRoleBindingsCache []rbacv1.ClusterRoleBinding
	bindingsMutex            sync.RWMutex
	bindingsLoaded           bool
}

// New creates a new Kubernetes connector
func New(ctx context.Context, cfg *rest.Config, opts ...ConnectorOption) (*Kubernetes, error) {
	// Validate that config is not nil
	if cfg == nil {
		return nil, fmt.Errorf("kubernetes REST config cannot be nil")
	}

	options := connectorOpts{}

	// Apply option functions
	for _, opt := range opts {
		err := opt(&options)
		if err != nil {
			return nil, fmt.Errorf("applying option: %w", err)
		}
	}

	// Create kubernetes client
	client, err := kubernetes.NewForConfig(cfg)
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

// ResourceSyncers returns the resource syncers for the Kubernetes connector
func (k *Kubernetes) ResourceSyncers(ctx context.Context) []connectorbuilder.ResourceSyncer {
	syncers := []connectorbuilder.ResourceSyncer{
		newNamespaceBuilder(k.client),
		newServiceAccountBuilder(k.client),
		newRoleBuilder(k.client, k),
		newClusterRoleBuilder(k.client, k),
		newSecretBuilder(k.client),
		newConfigMapBuilder(k.client),
		newNodeBuilder(k.client),
		newDeploymentBuilder(k.client),
		newStatefulSetBuilder(k.client),
		newDaemonSetBuilder(k.client),
		newPodBuilder(k.client),
		newKubeUserBuilder(k.client),
		newKubeGroupBuilder(k.client),
	}

	return syncers
}

// Metadata returns the connector metadata
func (k *Kubernetes) Metadata(ctx context.Context) (*v2.ConnectorMetadata, error) {
	return &v2.ConnectorMetadata{
		DisplayName: "Kubernetes",
		Description: "Connector for Kubernetes resources and RBAC permissions",
	}, nil
}

// Validate validates the connector configuration
func (k *Kubernetes) Validate(ctx context.Context) (annotations.Annotations, error) {
	// Try to list namespaces as a simple connectivity test
	_, err := k.client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil {
		// Check for different types of errors to provide better messages
		if k8serrors.IsUnauthorized(err) {
			return nil, fmt.Errorf("unauthorized access to Kubernetes API: %w", err)
		} else if k8serrors.IsForbidden(err) {
			return nil, fmt.Errorf("forbidden access to Kubernetes API (check RBAC permissions): %w", err)
		} else {
			return nil, fmt.Errorf("validating kubernetes connection: %w", err)
		}
	}

	return nil, nil
}

// loadBindingsCaches ensures that both binding caches are loaded
// It uses a mutex to ensure thread safety
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

// GetMatchingRoleBindings returns all RoleBindings that reference the specified Role
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

// GetMatchingBindingsForClusterRole returns all RoleBindings and ClusterRoleBindings that reference the specified ClusterRole
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
