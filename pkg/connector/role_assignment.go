package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
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

// less orders pairs for paging. Shared by the sort and the resume search so the
// two can never disagree about what "the next pair" means.
func (k assignmentKey) less(other assignmentKey) bool {
	if k.scopeType != other.scopeType {
		return k.scopeType < other.scopeType
	}
	if k.scopeID != other.scopeID {
		return k.scopeID < other.scopeID
	}
	return k.role < other.role
}

// roleAssignmentBuilder syncs (cluster role, scope) pairs that actually have a
// binding, replacing the O(cluster roles x namespaces) entitlement surface the
// flat model declares.
type roleAssignmentBuilder struct {
	client          kubernetes.Interface
	bindings        BindingLister
	bindingProvider ClusterRoleBindingProvider
	// enabled reports whether the sparse model is on. The type is registered
	// either way so a tenant selecting it can never fail the sync's resource
	// type validation, but with the model off cluster_role still emits the flat
	// entitlements and grants, so emitting assignments too would count the same
	// access twice.
	enabled bool
	// matchCfg tunes external-match carriers. See external_match.go.
	matchCfg ExternalMatchConfig

	// clusterRoles caches the names of existing cluster roles for one sync, so
	// paging through assignments does not re-list them per page.
	clusterRolesMutex sync.Mutex
	clusterRoles      map[string]bool
	clusterRolesSync  string

	// pairs caches the sorted (cluster role, scope) list for one sync. Every page
	// searches it, so without this each one would re-copy the whole binding cache
	// and regroup and re-sort it, making List quadratic in the number of pages on
	// a cluster large enough to need them.
	pairsMutex sync.Mutex
	pairs      []assignmentPair
	pairsSync  string
}

// assignmentPair is one (cluster role, scope) pair with the bindings behind it.
type assignmentPair struct {
	key          assignmentKey
	contributors []contributingBinding
}

func (b *roleAssignmentBuilder) ResourceType(_ context.Context) *v2.ResourceType {
	return ResourceTypeRoleAssignment
}

// List emits one resource per (cluster role, scope) pair that has at least one
// binding, paging over that list by cursor.
func (b *roleAssignmentBuilder) List(ctx context.Context, _ *v2.ResourceId, opts rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
	l := ctxzap.Extract(ctx)

	if !b.enabled {
		return nil, nil, nil
	}

	pairs, err := b.assignmentPairs(ctx, opts.SyncID)
	if err != nil {
		return nil, nil, err
	}

	cursor, err := parseAssignmentCursor(opts.PageToken.Token)
	if err != nil {
		return nil, nil, err
	}
	offset, end := pageBounds(pairs, cursor, opts.PageToken.Size,
		func(key assignmentKey, pair assignmentPair) bool { return key.less(pair.key) })

	var rv []*v2.Resource
	for _, pair := range pairs[offset:end] {
		key, contributors := pair.key, pair.contributors

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

	if end < len(pairs) {
		next, err := encodeAssignmentCursor(pairs[end-1].key)
		if err != nil {
			return nil, nil, err
		}
		return rv, &rs.SyncOpResults{NextPageToken: next}, nil
	}
	return rv, nil, nil
}

// assignmentPairs returns this sync's (cluster role, scope) pairs, sorted.
//
// Built once per sync and cached: a pair is only complete once every binding
// contributing to it has been seen, so it cannot be assembled page by page —
// doing so would emit the same pair repeatedly with a partial contributor list,
// and because resources upsert on (id, sync) the last partial write would win.
// Paging therefore searches this finished list, and caching keeps that from
// re-copying and re-sorting every binding on each page.
func (b *roleAssignmentBuilder) assignmentPairs(ctx context.Context, syncID string) ([]assignmentPair, error) {
	b.pairsMutex.Lock()
	defer b.pairsMutex.Unlock()

	if b.pairs != nil && b.pairsSync == syncID {
		return b.pairs, nil
	}

	l := ctxzap.Extract(ctx)

	roleBindings, clusterRoleBindings, err := b.bindings.AllBindings(ctx, syncID)
	if err != nil {
		return nil, fmt.Errorf("failed to list bindings: %w", err)
	}
	known, err := b.knownClusterRoles(ctx, syncID)
	if err != nil {
		return nil, err
	}

	grouped := make(map[assignmentKey][]contributingBinding)
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
		grouped[key] = append(grouped[key], cb)
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

	pairs := make([]assignmentPair, 0, len(grouped))
	for key, contributors := range grouped {
		sort.Slice(contributors, func(i, j int) bool { return contributors[i].Name < contributors[j].Name })
		pairs = append(pairs, assignmentPair{key: key, contributors: contributors})
	}
	// Sorted so paging is stable across calls; map order is not.
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].key.less(pairs[j].key) })

	b.pairs = pairs
	b.pairsSync = syncID
	return pairs, nil
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
	if err != nil {
		// Kept separate from the missing-trait case below: %w on a nil error
		// prints %!w(<nil>), so folding the two loses the decode failure that is
		// the only clue why the trait could not be read.
		return nil, nil, fmt.Errorf("role assignment %s: failed to read scope binding trait: %w",
			resource.GetId().GetResource(), err)
	}
	if scopeTrait == nil {
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

		subjectGrants, err := GrantRoleToSubject(ctx, subject, resource, assignedEntitlement, b.matchCfg)
		if err != nil {
			l.Debug("subject kind not supported", zap.String("subject kind", subject.Kind))
			continue
		}
		rv = append(rv, subjectGrants...)
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

// assignmentCursor is the wire form of the page token: the last (cluster role,
// scope) pair emitted, rather than an index into the list. See pageBounds for why
// the key rather than the index.
type assignmentCursor struct {
	ScopeType string `json:"scopeType"`
	ScopeID   string `json:"scopeID"`
	Role      string `json:"role"`
}

// parseAssignmentCursor decodes the page token, returning nil for the first page.
func parseAssignmentCursor(token string) (*assignmentKey, error) {
	if token == "" {
		return nil, nil
	}
	var c assignmentCursor
	if err := json.Unmarshal([]byte(token), &c); err != nil {
		return nil, fmt.Errorf("invalid role assignment page token %q: %w", token, err)
	}
	return &assignmentKey{scopeType: c.ScopeType, scopeID: c.ScopeID, role: c.Role}, nil
}

func encodeAssignmentCursor(key assignmentKey) (string, error) {
	token, err := json.Marshal(assignmentCursor{
		ScopeType: key.scopeType,
		ScopeID:   key.scopeID,
		Role:      key.role,
	})
	if err != nil {
		return "", fmt.Errorf("failed to encode role assignment page token: %w", err)
	}
	return string(token), nil
}

func pageLimit(size int) int {
	if size <= 0 || size > ResourcesPageSize {
		return ResourcesPageSize
	}
	return size
}

func newRoleAssignmentBuilder(
	client kubernetes.Interface,
	k8s *Kubernetes,
	enabled bool,
	matchCfg ExternalMatchConfig,
) *roleAssignmentBuilder {
	return &roleAssignmentBuilder{
		client:          client,
		bindings:        k8s,
		bindingProvider: k8s,
		enabled:         enabled,
		matchCfg:        matchCfg,
	}
}
