package connector

import (
	"context"
	"fmt"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

// kubeGroupBuilder syncs Kubernetes groups referenced in RBAC bindings as Baton groups.
type kubeGroupBuilder struct {
	client kubernetes.Interface
	// groupCache deduplicates groups across the pages of one sync, keyed by sync
	// ID for the same reason as kubeUserBuilder.userCache.
	groupCache      map[string]bool
	groupCacheSync  string
	groupCacheMutex sync.Mutex
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
func (k *kubeGroupBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, opts rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
	l := ctxzap.Extract(ctx)
	var rv []*v2.Resource

	k.resetGroupCacheForSync(opts.SyncID)

	// Parse pagination token
	bag, err := ParsePageToken(opts.PageToken.Token)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse page token: %w", err)
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
		listOpts := metav1.ListOptions{
			Limit:    ResourcesPageSize,
			Continue: bag.PageToken(),
		}

		l.Debug("fetching role bindings for groups", zap.String("continue_token", listOpts.Continue))
		resp, err := k.client.RbacV1().RoleBindings("").List(ctx, listOpts)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to list role bindings: %w", err)
		}

		for _, binding := range resp.Items {
			for _, subject := range binding.Subjects {
				if subject.Kind == SubjectKindGroup {
					k.processGroup(ctx, subject.Name, &rv)
				}
			}
		}

		if resp.Continue != "" {
			// More RoleBinding pages remain.
			nextToken, err := marshalPhaseToken(phaseRoleBindings, resp.Continue)
			if err != nil {
				return nil, nil, err
			}
			return rv, &rs.SyncOpResults{NextPageToken: nextToken}, nil
		}

		// Phase 1 complete — advance to Phase 2.
		nextToken, err := marshalPhaseToken(phaseClusterRoleBindings, "")
		if err != nil {
			return nil, nil, err
		}
		return rv, &rs.SyncOpResults{NextPageToken: nextToken}, nil
	}

	// Phase 2: Process ClusterRoleBindings
	if phase == phaseClusterRoleBindings {
		listOpts := metav1.ListOptions{
			Limit:    ResourcesPageSize,
			Continue: bag.PageToken(),
		}

		l.Debug("fetching cluster role bindings for groups", zap.String("continue_token", listOpts.Continue))
		resp, err := k.client.RbacV1().ClusterRoleBindings().List(ctx, listOpts)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to list cluster role bindings: %w", err)
		}

		for _, binding := range resp.Items {
			for _, subject := range binding.Subjects {
				if subject.Kind == SubjectKindGroup {
					k.processGroup(ctx, subject.Name, &rv)
				}
			}
		}

		if resp.Continue != "" {
			// More ClusterRoleBinding pages remain.
			nextToken, err := marshalPhaseToken(phaseClusterRoleBindings, resp.Continue)
			if err != nil {
				return nil, nil, err
			}
			return rv, &rs.SyncOpResults{NextPageToken: nextToken}, nil
		}
	}

	// All phases complete.
	return rv, nil, nil
}

// resetGroupCacheForSync discards the dedup cache when it belongs to an earlier
// sync; see kubeUserBuilder.resetUserCacheForSync.
func (k *kubeGroupBuilder) resetGroupCacheForSync(syncID string) {
	k.groupCacheMutex.Lock()
	defer k.groupCacheMutex.Unlock()
	if k.groupCache == nil || k.groupCacheSync != syncID {
		k.groupCache = make(map[string]bool)
		k.groupCacheSync = syncID
	}
}

// markGroupProcessed records the group and reports whether this call was the
// first to see it; see kubeUserBuilder.markUserProcessed.
func (k *kubeGroupBuilder) markGroupProcessed(groupName string) bool {
	k.groupCacheMutex.Lock()
	defer k.groupCacheMutex.Unlock()
	if k.groupCache == nil {
		k.groupCache = make(map[string]bool)
	}
	if k.groupCache[groupName] {
		return false
	}
	k.groupCache[groupName] = true
	return true
}

// processGroup adds a group to the list of resources if not already processed.
func (k *kubeGroupBuilder) processGroup(ctx context.Context, groupName string, resources *[]*v2.Resource) {
	l := ctxzap.Extract(ctx)

	if !k.markGroupProcessed(groupName) {
		return
	}

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
		profileKeyName: groupName,
	}

	// Create group resource
	resource, err := rs.NewGroupResource(
		groupName,
		ResourceTypeKubeGroup,
		groupName,
		nil,
		rs.WithResourceProfile(profile),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create group resource: %w", err)
	}

	return resource, nil
}

// Entitlements returns entitlements for Group resources.
func (k *kubeGroupBuilder) Entitlements(_ context.Context, resource *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
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

	return []*v2.Entitlement{memberEnt}, nil, nil
}

// Grants returns group membership grants from the sealed x509 scan that
// kubeUserBuilder.List() Phase 3 writes to this sync's session store.
// The SDK guarantees all List() calls complete before Grants() is invoked.
func (k *kubeGroupBuilder) Grants(ctx context.Context, resource *v2.Resource, opts rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	result, ok := loadSecretsScan(ctx, opts.Session)
	if !ok || !result.Sealed {
		// Either the x509 discovery pass never ran — kube_group synced without
		// kube_user (custom sync selection), or no session store is configured —
		// or it did not finish. Membership is best-effort data, and a partial
		// scan would under-report it as fact, so emit nothing either way.
		ctxzap.Extract(ctx).Debug("no sealed secrets scan; emitting no group membership grants",
			zap.String("group", resource.Id.Resource))
		return nil, nil, nil
	}

	principals := result.GroupMembers[resource.Id.Resource]
	grants := make([]*v2.Grant, 0, len(principals))
	for _, principalName := range principals {
		principalResource := GenerateResourceForGrant(principalName, ResourceTypeKubeUser.Id)
		grants = append(grants, grant.NewGrant(resource, "member", principalResource))
	}
	return grants, nil, nil
}

// newKubeGroupBuilder creates a new kube group builder.
func newKubeGroupBuilder(client kubernetes.Interface) *kubeGroupBuilder {
	return &kubeGroupBuilder{
		client:     client,
		groupCache: make(map[string]bool),
	}
}
