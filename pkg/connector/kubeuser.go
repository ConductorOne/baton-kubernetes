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

// kubeUserBuilder syncs Kubernetes users referenced in RBAC bindings as Baton users.
type kubeUserBuilder struct {
	client kubernetes.Interface
	// Cache to avoid duplicate work when extracting users from bindings
	userCache     map[string]bool
	userCacheLock sync.RWMutex
}

// ResourceType returns the resource type for KubeUser.
func (k *kubeUserBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return ResourceTypeKubeUser
}

// List extracts unique users from RBAC bindings and creates Baton user resources.
func (k *kubeUserBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	var rv []*v2.Resource

	// Initialize empty user cache if needed
	k.userCacheLock.Lock()
	if k.userCache == nil {
		k.userCache = make(map[string]bool)
	}
	k.userCacheLock.Unlock()

	// Parse pagination token
	bag, err := ParsePageToken(pToken.Token)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to parse page token: %w", err)
	}

	pageState := bag.PageToken()

	// Phase 1: Process RoleBindings
	if pageState == "" || pageState == "rolebindings" {
		// Set up list options with pagination
		opts := metav1.ListOptions{
			Limit: ResourcesPageSize,
		}
		if pageState == "rolebindings" {
			opts.Continue = bag.PageToken()
		}

		// Fetch role bindings from all namespaces
		l.Debug("fetching role bindings for users", zap.String("continue_token", opts.Continue))
		resp, err := k.client.RbacV1().RoleBindings("").List(ctx, opts)
		if err != nil {
			return nil, "", nil, fmt.Errorf("failed to list role bindings: %w", err)
		}

		// Extract user subjects from bindings
		for _, binding := range resp.Items {
			for _, subject := range binding.Subjects {
				if subject.Kind == "User" {
					// Process user
					k.processUser(ctx, subject.Name, &rv)
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
		l.Debug("fetching cluster role bindings for users", zap.String("continue_token", opts.Continue))
		resp, err := k.client.RbacV1().ClusterRoleBindings().List(ctx, opts)
		if err != nil {
			return nil, "", nil, fmt.Errorf("failed to list cluster role bindings: %w", err)
		}

		// Extract user subjects from bindings
		for _, binding := range resp.Items {
			for _, subject := range binding.Subjects {
				if subject.Kind == "User" {
					// Process user
					k.processUser(ctx, subject.Name, &rv)
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

// processUser adds a user to the list of resources if not already processed.
func (k *kubeUserBuilder) processUser(ctx context.Context, username string, resources *[]*v2.Resource) {
	l := ctxzap.Extract(ctx)

	// Check if we've already processed this user
	k.userCacheLock.RLock()
	processed := k.userCache[username]
	k.userCacheLock.RUnlock()

	if processed {
		return
	}

	// Mark as processed
	k.userCacheLock.Lock()
	k.userCache[username] = true
	k.userCacheLock.Unlock()

	// Create user resource
	resource, err := k.kubeUserResource(username)
	if err != nil {
		l.Error("failed to create user resource", zap.String("name", username), zap.Error(err))
		return
	}

	*resources = append(*resources, resource)
}

// kubeUserResource creates a Baton user resource for a Kubernetes user.
func (k *kubeUserBuilder) kubeUserResource(username string) (*v2.Resource, error) {
	// Create profile
	profile := map[string]interface{}{
		"name": username,
	}

	// Create resource with user trait options
	userOptions := []rs.UserTraitOption{
		rs.WithStatus(v2.UserTrait_Status_STATUS_ENABLED),
		rs.WithUserProfile(profile),
		rs.WithUserLogin(username),
	}

	// Create user resource
	resource, err := rs.NewUserResource(
		username,
		ResourceTypeKubeUser,
		username,
		userOptions,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create user resource: %w", err)
	}

	return resource, nil
}

// Entitlements returns entitlements for User resources.
func (k *kubeUserBuilder) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	// Add 'impersonate' entitlement
	impersonateEnt := entitlement.NewPermissionEntitlement(
		resource,
		"impersonate",
		entitlement.WithDisplayName(fmt.Sprintf("Impersonate %s", resource.DisplayName)),
		entitlement.WithDescription(fmt.Sprintf("Grants the ability to impersonate the %s user", resource.DisplayName)),
		entitlement.WithGrantableTo(
			ResourceTypeRole,
			ResourceTypeClusterRole,
		),
	)

	return []*v2.Entitlement{impersonateEnt}, "", nil, nil
}

// Grants returns no grants for User resources.
func (k *kubeUserBuilder) Grants(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

// newKubeUserBuilder creates a new kube user builder.
func newKubeUserBuilder(client kubernetes.Interface) *kubeUserBuilder {
	return &kubeUserBuilder{
		client:    client,
		userCache: make(map[string]bool),
	}
}
