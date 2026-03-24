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
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

// kubeGroupBuilder syncs Kubernetes groups referenced in RBAC bindings as Baton groups.
type kubeGroupBuilder struct {
	client kubernetes.Interface
	k8s    *Kubernetes
	// Cache to avoid duplicate work when extracting groups from bindings
	groupCache     map[string]bool
	groupCacheLock sync.RWMutex
}

// ResourceType returns the resource type for KubeGroup.
func (k *kubeGroupBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return ResourceTypeKubeGroup
}

// List extracts unique groups from RBAC bindings and creates Baton group resources.
// It runs in two phases tracked via PageState.ResourceTypeID:
//
//	Phase "rolebindings"        – scan RoleBindings (default/first phase)
//	Phase "clusterrolebindings" – scan ClusterRoleBindings
//
// PageState.Token holds the Kubernetes API continue token within each phase.
func (k *kubeGroupBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	var rv []*v2.Resource

	// Initialize empty group cache if needed
	k.groupCacheLock.Lock()
	if k.groupCache == nil {
		k.groupCache = make(map[string]bool)
	}
	k.groupCacheLock.Unlock()

	// Parse pagination token
	bag, err := ParsePageToken(pToken.Token)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to parse page token: %w", err)
	}

	// Determine current phase; default to rolebindings on first call (empty bag).
	phase := bag.ResourceTypeID()
	if phase == "" {
		phase = phaseRoleBindings
	}

	// Emit built-in system groups only on the very first page to avoid redundant cache lookups.
	if phase == phaseRoleBindings && bag.PageToken() == "" {
		for _, groupName := range []string{
			"system:masters",
			"system:authenticated",
			"system:unauthenticated",
		} {
			k.processGroup(ctx, groupName, &rv)
		}
	}

	// Phase 1: Process RoleBindings
	if phase == phaseRoleBindings {
		opts := metav1.ListOptions{
			Limit:    ResourcesPageSize,
			Continue: bag.PageToken(),
		}

		l.Debug("fetching role bindings for groups", zap.String("continue_token", opts.Continue))
		resp, err := k.client.RbacV1().RoleBindings("").List(ctx, opts)
		if err != nil {
			return nil, "", nil, fmt.Errorf("failed to list role bindings: %w", err)
		}

		for _, binding := range resp.Items {
			for _, subject := range binding.Subjects {
				if subject.Kind == "Group" {
					k.processGroup(ctx, subject.Name, &rv)
				}
			}
		}

		if resp.Continue != "" {
			// More RoleBinding pages remain.
			nextToken, err := marshalPhaseToken(phaseRoleBindings, resp.Continue)
			if err != nil {
				return nil, "", nil, err
			}
			return rv, nextToken, nil, nil
		}

		// Phase 1 complete — advance to Phase 2.
		nextToken, err := marshalPhaseToken(phaseClusterRoleBindings, "")
		if err != nil {
			return nil, "", nil, err
		}
		return rv, nextToken, nil, nil
	}

	// Phase 2: Process ClusterRoleBindings
	if phase == phaseClusterRoleBindings {
		opts := metav1.ListOptions{
			Limit:    ResourcesPageSize,
			Continue: bag.PageToken(),
		}

		l.Debug("fetching cluster role bindings for groups", zap.String("continue_token", opts.Continue))
		resp, err := k.client.RbacV1().ClusterRoleBindings().List(ctx, opts)
		if err != nil {
			return nil, "", nil, fmt.Errorf("failed to list cluster role bindings: %w", err)
		}

		for _, binding := range resp.Items {
			for _, subject := range binding.Subjects {
				if subject.Kind == "Group" {
					k.processGroup(ctx, subject.Name, &rv)
				}
			}
		}

		if resp.Continue != "" {
			// More ClusterRoleBinding pages remain.
			nextToken, err := marshalPhaseToken(phaseClusterRoleBindings, resp.Continue)
			if err != nil {
				return nil, "", nil, err
			}
			return rv, nextToken, nil, nil
		}
	}

	// All phases complete.
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
	// 'member' assignment entitlement: links users to the group they belong to.
	// Grants are derived from x509 client certificate O= fields in kubeconfig Secrets.
	memberEnt := entitlement.NewAssignmentEntitlement(
		resource,
		"member",
		entitlement.WithDisplayName(fmt.Sprintf("Member of %s", resource.DisplayName)),
		entitlement.WithDescription(fmt.Sprintf("Membership in the %s Kubernetes group", resource.DisplayName)),
		entitlement.WithGrantableTo(
			ResourceTypeKubeUser,
			ResourceTypeServiceAccount,
		),
	)

	return []*v2.Entitlement{memberEnt}, "", nil, nil
}

// Grants returns group membership grants from the sealed secrets cache.
// The cache is populated by kubeUserBuilder.List() Phase 3.
// The SDK guarantees all List() calls complete before Grants() is invoked.
func (k *kubeGroupBuilder) Grants(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	k.k8s.secretsMu.RLock()
	result := k.k8s.secretsResult
	k.k8s.secretsMu.RUnlock()

	if result == nil {
		return nil, "", nil, fmt.Errorf("baton-kubernetes: secrets cache not sealed; kubeUserBuilder must complete before kubeGroupBuilder.Grants")
	}

	principals := result.GroupMembers[resource.Id.Resource]
	grants := make([]*v2.Grant, 0, len(principals))
	for _, principalName := range principals {
		principalResource := GenerateResourceForGrant(principalName, ResourceTypeKubeUser.Id)
		grants = append(grants, grant.NewGrant(resource, "member", principalResource))
	}
	return grants, "", nil, nil
}

// newKubeGroupBuilder creates a new kube group builder.
func newKubeGroupBuilder(client kubernetes.Interface, k8s *Kubernetes) *kubeGroupBuilder {
	return &kubeGroupBuilder{
		client:     client,
		k8s:        k8s,
		groupCache: make(map[string]bool),
	}
}
