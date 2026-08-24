package connector

import (
	"context"
	"encoding/json"
	"fmt"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/types/entitlement"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

// apiResourceBuilder syncs the authorization targets a cluster's RBAC rules
// actually name — one resource per (API resource, scope) pair — and the verb
// entitlements each one carries.
//
// This is the half of the access chain the connector was missing. Membership
// (subject holds a role, in a scope) was already modelled; what a role permits
// was only profile text on the role. These resources make it an edge, so
// "who can create pods in team-a" is a query rather than a reading exercise.
type apiResourceBuilder struct {
	provider PermissionIndexProvider
}

func (b *apiResourceBuilder) ResourceType(_ context.Context) *v2.ResourceType {
	return ResourceTypeAPIResource
}

// List emits one resource per authorization target some bound rule names, paging
// over that derived list by cursor.
func (b *apiResourceBuilder) List(ctx context.Context, _ *v2.ResourceId, opts rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
	l := ctxzap.Extract(ctx)

	index, err := b.provider.PermissionIndex(ctx, opts.SyncID)
	if err != nil {
		return nil, nil, err
	}
	classes := index.Classes()

	cursor, err := parsePermissionClassCursor(opts.PageToken.Token)
	if err != nil {
		return nil, nil, err
	}
	offset, end := pageBounds(classes, cursor, opts.PageToken.Size,
		func(key, class permissionClass) bool { return key.less(class) })

	var rv []*v2.Resource
	for _, class := range classes[offset:end] {
		resource, err := apiResourceResource(class, index.Verbs(class))
		if err != nil {
			l.Error("failed to create api resource",
				zap.String("api_resource", class.resource),
				zap.String("resource_name", class.name),
				zap.String("api_group", class.group),
				zap.String("scope", class.scopeID),
				zap.Error(err))
			continue
		}
		rv = append(rv, resource)
	}

	if end < len(classes) {
		next, err := encodePermissionClassCursor(classes[end-1])
		if err != nil {
			return nil, nil, err
		}
		return rv, &rs.SyncOpResults{NextPageToken: next}, nil
	}
	return rv, nil, nil
}

// apiResourceResource builds the Baton resource for one authorization target.
//
// The parent is the target's scope, which is what fixes the old wildcard
// resources' worst property: they were the only unparented resources in the
// connector, floating outside the cluster and namespace tree they belonged to.
func apiResourceResource(class permissionClass, verbs []string) (*v2.Resource, error) {
	scopeResourceID := clusterScopeResourceID()
	if class.scopeType != ResourceTypeCluster.Id {
		var err error
		scopeResourceID, err = NamespaceResourceID(class.scopeID)
		if err != nil {
			return nil, fmt.Errorf("failed to create scope resource ID: %w", err)
		}
	}

	group := class.group
	if group == "" {
		group = coreAPIGroup
	}
	profile := map[string]interface{}{
		profileKeyName:        class.displayName(),
		profileKeyAPIGroup:    group,
		profileKeyAPIResource: class.resource,
		profileKeyScope:       class.scopeID,
		profileKeyScopeType:   class.scopeType,
		profileKeyVerbs:       toAnySlice(verbs),
	}
	// Present only on a target a resourceNames rule narrowed to one object, so a
	// reviewer can filter the narrowed permissions apart from the wholesale ones.
	if class.name != "" {
		profile[profileKeyResourceName] = class.name
	}

	resource, err := rs.NewResource(
		class.displayName(),
		ResourceTypeAPIResource,
		class.objectID(),
		rs.WithParentResourceID(scopeResourceID),
		rs.WithDescription(class.description()),
		rs.WithResourceProfile(profile),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create api resource: %w", err)
	}
	return resource, nil
}

// Entitlements returns one entitlement per verb some rule names for this target.
//
// Only verbs a rule actually names are declared, so every entitlement here has
// at least one grant by construction. The fixed seven-verb set the workload
// builders used to declare could not manage that: nothing in Kubernetes grants
// "delete" on the class of all pods unless a rule says so.
func (b *apiResourceBuilder) Entitlements(ctx context.Context, resource *v2.Resource, opts rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	class, verbs, err := b.classFor(ctx, resource, opts)
	if err != nil {
		return nil, nil, err
	}

	rv := make([]*v2.Entitlement, 0, len(verbs))
	for _, verb := range verbs {
		rv = append(rv, entitlement.NewPermissionEntitlement(
			resource,
			verb,
			entitlement.WithDisplayName(fmt.Sprintf("%s %s", verbLabel(verb), class.displayName())),
			entitlement.WithDescription(fmt.Sprintf("Permits %s on %s", verbLabel(verb), class.description())),
			entitlement.WithGrantableTo(
				ResourceTypeRole,
				ResourceTypeClusterRole,
				ResourceTypeRoleAssignment,
			),
		))
	}
	return rv, nil, nil
}

// Grants returns the roles conferring each verb on this target.
//
// The principal is a role-shaped resource, never an identity: Kubernetes stores
// the permission on the role, and which identities hold it is the binding's
// business. Each grant is annotated expandable through the principal's own
// membership entitlement, so the SDK's expansion phase carries the permission
// down to the subjects without this builder having to enumerate them.
func (b *apiResourceBuilder) Grants(ctx context.Context, resource *v2.Resource, opts rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	index, err := b.provider.PermissionIndex(ctx, opts.SyncID)
	if err != nil {
		return nil, nil, err
	}
	class, ok := index.Class(resource.GetId().GetResource())
	if !ok {
		return nil, nil, nil
	}

	var rv []*v2.Grant
	for _, verb := range index.Verbs(class) {
		for _, principal := range index.Principals(class, verb) {
			rv = append(rv, permissionGrant(resource, verb, principal))
		}
	}
	return rv, nil, nil
}

// classFor resolves a resource back to its class and verbs.
//
// A resource the index no longer knows yields no verbs rather than an error: a
// partial sync can hand back a resource whose rule was deleted since it was
// written, and that is a cluster change, not a fault.
func (b *apiResourceBuilder) classFor(ctx context.Context, resource *v2.Resource, opts rs.SyncOpAttrs) (permissionClass, []string, error) {
	index, err := b.provider.PermissionIndex(ctx, opts.SyncID)
	if err != nil {
		return permissionClass{}, nil, err
	}
	class, ok := index.Class(resource.GetId().GetResource())
	if !ok {
		return permissionClass{}, nil, nil
	}
	return class, index.Verbs(class), nil
}

// permissionClassCursor is the wire form of the page token: the last class
// emitted, rather than an index into the derived list. See pageBounds for why the
// key rather than the index.
type permissionClassCursor struct {
	ScopeType string `json:"scopeType"`
	ScopeID   string `json:"scopeID"`
	Group     string `json:"group"`
	Resource  string `json:"resource"`
	Name      string `json:"name,omitempty"`
}

func parsePermissionClassCursor(token string) (*permissionClass, error) {
	if token == "" {
		return nil, nil
	}
	var c permissionClassCursor
	if err := json.Unmarshal([]byte(token), &c); err != nil {
		return nil, fmt.Errorf("invalid api resource page token %q: %w", token, err)
	}
	return &permissionClass{
		group:     c.Group,
		resource:  c.Resource,
		name:      c.Name,
		scopeType: c.ScopeType,
		scopeID:   c.ScopeID,
	}, nil
}

func encodePermissionClassCursor(class permissionClass) (string, error) {
	token, err := json.Marshal(permissionClassCursor{
		ScopeType: class.scopeType,
		ScopeID:   class.scopeID,
		Group:     class.group,
		Resource:  class.resource,
		Name:      class.name,
	})
	if err != nil {
		return "", fmt.Errorf("failed to encode api resource page token: %w", err)
	}
	return string(token), nil
}

func newAPIResourceBuilder(provider PermissionIndexProvider) *apiResourceBuilder {
	return &apiResourceBuilder{provider: provider}
}
