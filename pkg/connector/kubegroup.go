package connector

import (
	"context"
	"fmt"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/types/entitlement"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

// kubeGroupBuilder syncs Kubernetes groups referenced in RBAC bindings as Baton groups.
type kubeGroupBuilder struct {
	client kubernetes.Interface
	// Cache to avoid duplicate work when extracting groups from bindings
	groupCache     map[string]bool
	groupCacheLock sync.RWMutex
}

// ResourceType returns the resource type for KubeGroup.
func (k *kubeGroupBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return ResourceTypeKubeGroup
}

// List extracts unique groups from RBAC bindings and creates Baton group resources.
func (k *kubeGroupBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	var rv []*v2.Resource

	// Initialize empty group cache if needed
	k.groupCacheLock.Lock()
	if k.groupCache == nil {
		k.groupCache = make(map[string]bool)
	}
	k.groupCacheLock.Unlock()

	// Always create built-in system groups
	builtInGroups := []string{
		"system:masters",
		"system:authenticated",
		"system:unauthenticated",
	}
	for _, groupName := range builtInGroups {
		k.processGroup(ctx, groupName, &rv)
	}

	// Parse pagination token
	bag, err := ParsePageToken(pToken.Token)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to parse page token: %w", err)
	}

	pageState := bag.PageToken()

	// Phase 1: Process RoleBindings
	if pageState == "" || pageState == ResourceTypeRoleBindings {
		// Set up list options with pagination
		opts := metav1.ListOptions{
			Limit: ResourcesPageSize,
		}
		if pageState == ResourceTypeRoleBindings {
			opts.Continue = bag.PageToken()
		}

		// Fetch role bindings from all namespaces
		l.Debug("fetching role bindings for groups", zap.String("continue_token", opts.Continue))
		resp, err := k.client.RbacV1().RoleBindings("").List(ctx, opts)
		if err != nil {
			return nil, "", nil, fmt.Errorf("failed to list role bindings: %w", err)
		}

		// Extract group subjects from bindings
		for _, binding := range resp.Items {
			for _, subject := range binding.Subjects {
				if subject.Kind == "Group" {
					// Process group
					k.processGroup(ctx, subject.Name, &rv)
				}
			}
		}

		if resp.Continue != "" {
			// Still more rolebindings to process
			bag.Push(pagination.PageState{Token: resp.Continue})
			token, err := bag.Marshal()
			if err != nil {
				return nil, "", nil, fmt.Errorf("failed to marshal pagination bag: %w", err)
			}
			return rv, token, nil, nil
		}

		// Prepare for phase 2
		bag = &pagination.Bag{}
		bag.Push(pagination.PageState{Token: "clusterrolebindings"})
	}

	// Phase 2: Process ClusterRoleBindings
	if pageState == "clusterrolebindings" {
		// Set up list options with pagination
		opts := metav1.ListOptions{
			Limit:    ResourcesPageSize,
			Continue: bag.PageToken(),
		}

		// Fetch cluster role bindings
		l.Debug("fetching cluster role bindings for groups", zap.String("continue_token", opts.Continue))
		resp, err := k.client.RbacV1().ClusterRoleBindings().List(ctx, opts)
		if err != nil {
			return nil, "", nil, fmt.Errorf("failed to list cluster role bindings: %w", err)
		}

		// Extract group subjects from bindings
		for _, binding := range resp.Items {
			for _, subject := range binding.Subjects {
				if subject.Kind == "Group" {
					// Process group
					k.processGroup(ctx, subject.Name, &rv)
				}
			}
		}

		if resp.Continue != "" {
			// Still more clusterrolebindings to process
			bag.Push(pagination.PageState{Token: resp.Continue})
			token, err := bag.Marshal()
			if err != nil {
				return nil, "", nil, fmt.Errorf("failed to marshal pagination bag: %w", err)
			}
			return rv, token, nil, nil
		}
	}

	// All done, return resources without pagination token
	return rv, "", nil, nil
}

// processGroup adds a group to the list of resources if not already processed.
func (k *kubeGroupBuilder) processGroup(ctx context.Context, groupName string, resources *[]*v2.Resource) {
	l := ctxzap.Extract(ctx)

	// Check if we've already processed this group
	k.groupCacheLock.RLock()
	processed := k.groupCache[groupName]
	k.groupCacheLock.RUnlock()

	if processed {
		return
	}

	// Mark as processed
	k.groupCacheLock.Lock()
	k.groupCache[groupName] = true
	k.groupCacheLock.Unlock()

	// Create group resource
	resource, err := k.kubeGroupResource(groupName)
	if err != nil {
		l.Error("failed to create group resource", zap.String("name", groupName), zap.Error(err))
		return
	}

	*resources = append(*resources, resource)
}

// kubeGroupResource creates a Baton group resource for a Kubernetes group.
func (k *kubeGroupBuilder) kubeGroupResource(groupName string) (*v2.Resource, error) {
	// Create profile
	profile := map[string]interface{}{
		"name": groupName,
	}

	// Create resource with group trait options
	groupOptions := []rs.GroupTraitOption{
		rs.WithGroupProfile(profile),
	}

	// Create group resource
	resource, err := rs.NewGroupResource(
		groupName,
		ResourceTypeKubeGroup,
		groupName,
		groupOptions,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create group resource: %w", err)
	}

	return resource, nil
}

// Entitlements returns entitlements for Group resources.
func (k *kubeGroupBuilder) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	// Add 'impersonate' entitlement
	impersonateEnt := entitlement.NewPermissionEntitlement(
		resource,
		"impersonate",
		entitlement.WithDisplayName(fmt.Sprintf("Impersonate %s", resource.DisplayName)),
		entitlement.WithDescription(fmt.Sprintf("Grants the ability to impersonate the %s group", resource.DisplayName)),
		entitlement.WithGrantableTo(
			ResourceTypeRole,
			ResourceTypeClusterRole,
		),
	)

	return []*v2.Entitlement{impersonateEnt}, "", nil, nil
}

// Grants returns no grants for Group resources.
func (k *kubeGroupBuilder) Grants(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

// newKubeGroupBuilder creates a new kube group builder.
func newKubeGroupBuilder(client kubernetes.Interface) *kubeGroupBuilder {
	return &kubeGroupBuilder{
		client:     client,
		groupCache: make(map[string]bool),
	}
}
