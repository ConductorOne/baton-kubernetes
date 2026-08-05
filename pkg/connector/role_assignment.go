package connector

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"sync"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/types/entitlement"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

// assignedEntitlement is the single entitlement shared by every role assignment.
// Declaring it once through StaticEntitlements instead of once per resource is
// what makes this model sparse.
const assignedEntitlement = "assigned"

// RBACKindClusterRole is the Kubernetes RBAC Kind value for ClusterRole objects.
const RBACKindClusterRole = "ClusterRole"

// Profile keys specific to role assignments.
const (
	profileKeyScope                = "scope"
	profileKeyScopeType            = "scopeType"
	profileKeyClusterRole          = "clusterRole"
	profileKeyContributingBindings = "contributingBindings"
	profileKeyBindingCount         = "bindingCount"
)

// contributingBinding records one Kubernetes binding behind a (role, scope)
// pair.
//
// A pair is deduplicated because C1 keys a role-scope-binding relationship on
// (scope, role) alone and keeps only the last resource reporting it, so
// modelling one resource per binding object would silently drop bindings
// whenever two of them grant the same cluster role in the same scope — which
// happens in practice. Deduplicating erases per-binding provenance from the
// resource identity, so it is carried here instead, where a reviewer can still
// see which objects produce the access and Revoke can find them all.
type contributingBinding struct {
	Name              string `json:"name"`
	Kind              string `json:"kind"`
	Namespace         string `json:"namespace,omitempty"`
	CreationTimestamp string `json:"creationTimestamp,omitempty"`
}

// assignmentKey identifies one (cluster role, scope) pair. Cluster-wide and
// namespace-scoped access to the same cluster role are different facts and are
// never merged, so the scope type is part of the key.
type assignmentKey struct {
	scopeType string
	scopeID   string
	role      string
}

// roleAssignmentBuilder syncs (cluster role, scope) pairs that actually have a
// binding, replacing the O(cluster roles x namespaces) entitlement surface the
// flat model declares.
type roleAssignmentBuilder struct {
	client          kubernetes.Interface
	bindings        BindingLister
	bindingProvider ClusterRoleBindingProvider

	// clusterRoles caches the names of existing cluster roles for one sync, so
	// paging through assignments does not re-list them per page.
	clusterRolesMutex sync.Mutex
	clusterRoles      map[string]bool
	clusterRolesSync  string
}

func (b *roleAssignmentBuilder) ResourceType(_ context.Context) *v2.ResourceType {
	return ResourceTypeRoleAssignment
}

// List emits one resource per (cluster role, scope) pair that has at least one
// binding.
//
// Every pair is built in a single pass: the pairs come from the sync-scoped
// binding cache, which already holds every binding, and a pair is only complete
// once all its contributing bindings have been seen. Assembling them page by
// page would emit the same pair repeatedly with a partial contributor list, and
// because resources upsert on (id, sync) the last partial write would win.
// Pagination therefore happens over the finished, sorted pairs.
func (b *roleAssignmentBuilder) List(ctx context.Context, _ *v2.ResourceId, opts rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
	l := ctxzap.Extract(ctx)

	roleBindings, clusterRoleBindings, err := b.bindings.AllBindings(ctx, opts.SyncID)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list bindings: %w", err)
	}

	known, err := b.knownClusterRoles(ctx, opts.SyncID)
	if err != nil {
		return nil, nil, err
	}

	pairs := make(map[assignmentKey][]contributingBinding)
	add := func(key assignmentKey, cb contributingBinding) {
		if !known[key.role] {
			// A binding may reference a cluster role that does not exist; such
			// bindings are legal and inert. Emitting one would mint a scope binding
			// whose role_id points at a resource this sync never wrote, which C1
			// drops when it maps the relationship.
			l.Debug("skipping binding with unresolvable roleRef",
				zap.String("binding", cb.Name),
				zap.String("cluster_role", key.role))
			return
		}
		pairs[key] = append(pairs[key], cb)
	}

	for _, crb := range clusterRoleBindings {
		if crb.RoleRef.Kind != RBACKindClusterRole {
			continue
		}
		add(assignmentKey{
			scopeType: ResourceTypeCluster.Id,
			scopeID:   clusterResourceID,
			role:      crb.RoleRef.Name,
		}, contributingBinding{
			Name:              crb.Name,
			Kind:              ResourceTypeClusterRoleBinding,
			CreationTimestamp: FormatTimestamp(crb.CreationTimestamp),
		})
	}

	for _, rb := range roleBindings {
		// A RoleBinding referencing a Role is namespaced access to a namespaced
		// role, which the flat role member entitlement already models 1:1. Only
		// cluster roles gain anything from the sparse form.
		if rb.RoleRef.Kind != RBACKindClusterRole {
			continue
		}
		add(assignmentKey{
			scopeType: ResourceTypeNamespace.Id,
			scopeID:   rb.Namespace,
			role:      rb.RoleRef.Name,
		}, contributingBinding{
			Name:              rb.Name,
			Kind:              ResourceTypeRoleBinding,
			Namespace:         rb.Namespace,
			CreationTimestamp: FormatTimestamp(rb.CreationTimestamp),
		})
	}

	keys := make([]assignmentKey, 0, len(pairs))
	for key := range pairs {
		keys = append(keys, key)
	}
	// Sorted so paging is stable across calls; map order is not.
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].scopeType != keys[j].scopeType {
			return keys[i].scopeType < keys[j].scopeType
		}
		if keys[i].scopeID != keys[j].scopeID {
			return keys[i].scopeID < keys[j].scopeID
		}
		return keys[i].role < keys[j].role
	})

	offset, err := parseOffsetToken(opts.PageToken.Token)
	if err != nil {
		return nil, nil, err
	}
	if offset > len(keys) {
		offset = len(keys)
	}
	end := len(keys)
	if limit := pageLimit(opts.PageToken.Size); offset+limit < end {
		end = offset + limit
	}

	var rv []*v2.Resource
	for _, key := range keys[offset:end] {
		contributors := pairs[key]
		sort.Slice(contributors, func(i, j int) bool { return contributors[i].Name < contributors[j].Name })

		resource, err := roleAssignmentResource(key, contributors)
		if err != nil {
			l.Error("failed to create role assignment resource",
				zap.String("cluster_role", key.role),
				zap.String("scope", key.scopeID),
				zap.Error(err))
			continue
		}
		rv = append(rv, resource)
	}

	if end < len(keys) {
		return rv, &rs.SyncOpResults{NextPageToken: strconv.Itoa(end)}, nil
	}
	return rv, nil, nil
}

// roleAssignmentObjectID builds the resource's object ID.
//
// The ID is opaque: nothing parses it back, because Grants reads the scope and
// role off the ScopeBindingTrait. It is prefixed by scope type anyway so a
// namespace that happens to be called "cluster" cannot collide with the
// cluster-wide pair for the same role.
func roleAssignmentObjectID(key assignmentKey) string {
	if key.scopeType == ResourceTypeCluster.Id {
		return fmt.Sprintf("cluster:%s", key.role)
	}
	return fmt.Sprintf("ns:%s:%s", key.scopeID, key.role)
}

func roleAssignmentResource(key assignmentKey, contributors []contributingBinding) (*v2.Resource, error) {
	scopeResourceID := clusterScopeResourceID()
	displayName := fmt.Sprintf("%s on cluster", key.role)
	if key.scopeType != ResourceTypeCluster.Id {
		var err error
		scopeResourceID, err = NamespaceResourceID(key.scopeID)
		if err != nil {
			return nil, fmt.Errorf("failed to create scope resource ID: %w", err)
		}
		displayName = fmt.Sprintf("%s in %s", key.role, key.scopeID)
	}

	bindings := make([]interface{}, 0, len(contributors))
	for _, cb := range contributors {
		bindings = append(bindings, map[string]interface{}{
			"name":              cb.Name,
			"kind":              cb.Kind,
			"namespace":         cb.Namespace,
			"creationTimestamp": cb.CreationTimestamp,
		})
	}

	profile := map[string]interface{}{
		profileKeyName:                 displayName,
		profileKeyClusterRole:          key.role,
		profileKeyScope:                key.scopeID,
		profileKeyScopeType:            key.scopeType,
		profileKeyBindingCount:         len(contributors),
		profileKeyContributingBindings: bindings,
	}

	return rs.NewScopeBindingResource(
		displayName,
		ResourceTypeRoleAssignment,
		roleAssignmentObjectID(key),
		[]rs.ScopeBindingTraitOption{
			rs.WithRoleScopeRoleId(&v2.ResourceId{
				ResourceType: ResourceTypeClusterRole.Id,
				Resource:     key.role,
			}),
			rs.WithRoleScopeResourceId(scopeResourceID),
		},
		rs.WithParentResourceID(scopeResourceID),
		rs.WithResourceProfile(profile),
	)
}

// StaticEntitlements declares the single entitlement shared by every role
// assignment resource.
func (b *roleAssignmentBuilder) StaticEntitlements(_ context.Context, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	return []*v2.Entitlement{
		entitlement.NewAssignmentEntitlement(
			nil,
			assignedEntitlement,
			entitlement.WithDisplayName("Assigned"),
			entitlement.WithDescription("Holds this cluster role in this scope"),
			entitlement.WithGrantableTo(
				ResourceTypeKubeUser,
				ResourceTypeKubeGroup,
				ResourceTypeServiceAccount,
			),
		),
	}, nil, nil
}

// Entitlements returns none: the type carries SkipEntitlements and declares its
// entitlement through StaticEntitlements instead.
func (b *roleAssignmentBuilder) Entitlements(_ context.Context, _ *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

// Grants returns the subjects holding this (cluster role, scope) pair.
func (b *roleAssignmentBuilder) Grants(ctx context.Context, resource *v2.Resource, opts rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	l := ctxzap.Extract(ctx)

	scopeTrait, err := rs.GetScopeBindingTrait(resource)
	if err != nil || scopeTrait == nil {
		return nil, nil, fmt.Errorf("role assignment %s has no scope binding trait", resource.GetId().GetResource())
	}
	roleName := scopeTrait.GetRoleId().GetResource()
	scope := scopeTrait.GetScopeResourceId()
	if roleName == "" || scope == nil {
		return nil, nil, fmt.Errorf("role assignment %s has an incomplete scope binding trait", resource.GetId().GetResource())
	}

	roleBindings, clusterRoleBindings, err := b.bindingProvider.GetMatchingBindingsForClusterRole(ctx, opts.SyncID, roleName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get matching bindings: %w", err)
	}

	subjects := make([]rbacv1.Subject, 0)
	if scope.GetResourceType() == ResourceTypeCluster.Id {
		for _, crb := range clusterRoleBindings {
			subjects = append(subjects, crb.Subjects...)
		}
	} else {
		for _, rb := range roleBindings {
			if rb.Namespace != scope.GetResource() {
				continue
			}
			for _, subject := range rb.Subjects {
				// A ServiceAccount subject may omit its namespace, in which case
				// Kubernetes resolves it to the binding's namespace.
				if subject.Kind == SubjectKindServiceAccount && subject.Namespace == "" {
					subject.Namespace = rb.Namespace
				}
				subjects = append(subjects, subject)
			}
		}
	}

	var rv []*v2.Grant
	// Two bindings sharing a subject would otherwise produce the same grant twice.
	seen := make(map[rbacv1.Subject]bool, len(subjects))
	for _, subject := range subjects {
		if seen[subject] {
			continue
		}
		seen[subject] = true

		subjectGrant, err := GrantRoleToSubject(subject, resource, assignedEntitlement)
		if err != nil {
			l.Debug("subject kind not supported", zap.String("subject kind", subject.Kind))
			continue
		}
		rv = append(rv, subjectGrant)
	}

	return rv, nil, nil
}

// knownClusterRoles returns the set of existing cluster role names for this
// sync, so a binding pointing at a missing one can be skipped.
func (b *roleAssignmentBuilder) knownClusterRoles(ctx context.Context, syncID string) (map[string]bool, error) {
	b.clusterRolesMutex.Lock()
	defer b.clusterRolesMutex.Unlock()

	if b.clusterRoles != nil && b.clusterRolesSync == syncID {
		return b.clusterRoles, nil
	}

	names := make(map[string]bool)
	continueToken := ""
	for {
		resp, err := b.client.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{
			Limit:    ResourcesPageSize,
			Continue: continueToken,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to list cluster roles: %w", err)
		}
		for _, cr := range resp.Items {
			names[cr.Name] = true
		}
		if resp.Continue == "" {
			break
		}
		continueToken = resp.Continue
	}

	b.clusterRoles = names
	b.clusterRolesSync = syncID
	return names, nil
}

// parseOffsetToken reads the index this page starts at. The token is a plain
// offset into the sorted pair list rather than a pagination bag, because the
// list is rebuilt identically on every call from the sync-scoped caches.
func parseOffsetToken(token string) (int, error) {
	if token == "" {
		return 0, nil
	}
	offset, err := strconv.Atoi(token)
	if err != nil || offset < 0 {
		return 0, fmt.Errorf("invalid role assignment page token: %q", token)
	}
	return offset, nil
}

func pageLimit(size int) int {
	if size <= 0 || size > ResourcesPageSize {
		return ResourcesPageSize
	}
	return size
}

func newRoleAssignmentBuilder(client kubernetes.Interface, k8s *Kubernetes) *roleAssignmentBuilder {
	return &roleAssignmentBuilder{
		client:          client,
		bindings:        k8s,
		bindingProvider: k8s,
	}
}
