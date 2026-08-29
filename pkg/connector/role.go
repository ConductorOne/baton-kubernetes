package connector

import (
	"context"
	"fmt"
	"strings"

	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/types/entitlement"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

// roleBuilder syncs Kubernetes Roles as Baton resources.
type roleBuilder struct {
	client          kubernetes.Interface
	bindingProvider RoleBindingProvider
	// matchCfg tunes external-match carriers. See external_match.go.
	matchCfg ExternalMatchConfig
}

// ResourceType returns the resource type for Role.
func (r *roleBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return ResourceTypeRole
}

// List fetches all Roles from the Kubernetes API.
func (r *roleBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, opts rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
	l := ctxzap.Extract(ctx)

	// Initialize empty resource slice
	var rv []*v2.Resource

	// Parse pagination token
	bag, err := ParsePageToken(opts.PageToken.Token)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse page token: %w", err)
	}

	// Set up list options with pagination
	listOpts := metav1.ListOptions{
		Limit:    ResourcesPageSize,
		Continue: bag.PageToken(),
	}

	// Fetch roles from the Kubernetes API across all namespaces
	l.Debug("fetching roles", zap.String("continue_token", listOpts.Continue))
	resp, err := r.client.RbacV1().Roles("").List(ctx, listOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list roles: %w", err)
	}

	// Process each role into a Baton resource
	for _, role := range resp.Items {
		resource, err := roleResource(&role)
		if err != nil {
			l.Error("failed to create role resource",
				zap.String("namespace", role.Namespace),
				zap.String("name", role.Name),
				zap.Error(err))
			continue
		}
		rv = append(rv, resource)
	}

	// Calculate next page token
	nextPageToken, err := HandleKubePagination(&resp.ListMeta, bag)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to handle pagination: %w", err)
	}

	return rv, &rs.SyncOpResults{NextPageToken: nextPageToken}, nil
}

// roleResource creates a Baton resource from a Kubernetes Role.
func roleResource(role *rbacv1.Role) (*v2.Resource, error) {
	// Prepare profile with standard metadata
	profile := map[string]interface{}{
		profileKeyName:              role.Name,
		profileKeyNamespace:         role.Namespace,
		profileKeyUID:               string(role.UID),
		profileKeyCreationTimestamp: FormatTimestamp(role.CreationTimestamp),
	}

	// Only add labels and annotations if they're not nil to avoid proto conversion issues
	if role.Labels != nil {
		profile[profileKeyLabels] = StringMapToAnyMap(role.Labels)
	}
	if role.Annotations != nil {
		profile[profileKeyAnnotations] = AnnotationsToAnyMap(role.Annotations)
	}

	// The rules are what the role actually permits; reviewers need them to attest access.
	for k, v := range PolicyRulesProfile(role.Rules) {
		profile[k] = v
	}

	// Get parent namespace resource ID
	parentID, err := NamespaceResourceID(role.Namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to create parent resource ID: %w", err)
	}

	// Create the raw ID as namespace/name
	rawID := role.Namespace + "/" + role.Name

	// Create resource as a role with parent namespace
	resource, err := rs.NewRoleResource(
		fmt.Sprintf("%s (%s)", role.Name, role.Namespace),
		ResourceTypeRole,
		rawID, // Pass the raw ID directly
		nil,
		rs.WithParentResourceID(parentID),
		rs.WithResourceProfile(profile),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create role resource: %w", err)
	}

	return resource, nil
}

// Entitlements returns entitlements for Role resources.
func (r *roleBuilder) Entitlements(ctx context.Context, resource *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	var entitlements []*v2.Entitlement

	// Create the 'member' entitlement for the role
	memberEnt := entitlement.NewAssignmentEntitlement(
		resource,
		"member",
		entitlement.WithDisplayName(fmt.Sprintf("%s Role Member", resource.DisplayName)),
		entitlement.WithDescription(fmt.Sprintf("Grants membership to the %s role", resource.DisplayName)),
		entitlement.WithGrantableTo(
			ResourceTypeKubeUser,
			ResourceTypeKubeGroup,
			ResourceTypeServiceAccount,
		),
	)
	entitlements = append(entitlements, memberEnt)

	return entitlements, nil, nil
}

// parseResourceID extracts namespace and name from a role resource ID.
func parseRoleResourceID(resourceID *v2.ResourceId) (string, string, error) {
	if resourceID == nil {
		return "", "", fmt.Errorf("resource ID is nil")
	}

	parts := strings.Split(resourceID.Resource, "/")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid resource ID format: %s", resourceID.Resource)
	}

	return parts[0], parts[1], nil
}

// Grants returns permission grants for Role resources.
func (r *roleBuilder) Grants(ctx context.Context, resource *v2.Resource, opts rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	l := ctxzap.Extract(ctx)
	var rv []*v2.Grant

	// Parse the resource ID to get namespace and name
	namespace, name, err := parseRoleResourceID(resource.Id)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse resource ID: %w", err)
	}

	// Get matching role bindings from the binding provider
	matchingBindings, err := r.bindingProvider.GetMatchingRoleBindings(ctx, opts.SyncID, namespace, name)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get matching role bindings: %w", err)
	}

	// If there are no bindings, there are no grants
	if len(matchingBindings) == 0 {
		l.Debug("no role bindings found for role", zap.String("namespace", namespace), zap.String("name", name))
		return nil, nil, nil
	}

	// Process each matching binding
	for _, binding := range matchingBindings {
		// Process each subject in the binding
		for _, subject := range binding.Subjects {
			// A ServiceAccount subject may omit its namespace, in which case
			// Kubernetes resolves it to the binding's namespace.
			if subject.Kind == SubjectKindServiceAccount && subject.Namespace == "" {
				subject.Namespace = binding.Namespace
			}
			subjectGrants, err := GrantRoleToSubject(ctx, subject, resource, "member", r.matchCfg)
			if err != nil {
				l.Debug("subject kind not supported", zap.String("subject kind", subject.Kind))
				continue
			}
			rv = append(rv, subjectGrants...)
		}
	}

	return rv, nil, nil
}

// newRoleBuilder creates a new role builder.
func newRoleBuilder(client kubernetes.Interface, bindingProvider RoleBindingProvider, matchCfg ExternalMatchConfig) *roleBuilder {
	return &roleBuilder{
		client:          client,
		bindingProvider: bindingProvider,
		matchCfg:        matchCfg,
	}
}
