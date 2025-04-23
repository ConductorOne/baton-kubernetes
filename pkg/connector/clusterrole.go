package connector

import (
	"context"
	"fmt"

	rbacv1 "k8s.io/api/rbac/v1"
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

// clusterRoleBuilder syncs Kubernetes ClusterRoles as Baton resources
type clusterRoleBuilder struct {
	client          kubernetes.Interface
	bindingProvider clusterRoleBindingProvider
}

// ResourceType returns the resource type for ClusterRole
func (c *clusterRoleBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return resourceTypeClusterRole
}

// List fetches all ClusterRoles from the Kubernetes API
func (c *clusterRoleBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	// Initialize empty resource slice
	var rv []*v2.Resource

	// Parse pagination token
	bag, err := parsePageToken(pToken.Token)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to parse page token: %w", err)
	}

	// Set up list options with pagination
	opts := metav1.ListOptions{
		Limit:    ResourcesPageSize,
		Continue: bag.PageToken(),
	}

	// Fetch cluster roles from the Kubernetes API
	l.Debug("fetching cluster roles", zap.String("continue_token", opts.Continue))
	resp, err := c.client.RbacV1().ClusterRoles().List(ctx, opts)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to list cluster roles: %w", err)
	}

	// Process each cluster role into a Baton resource
	for _, clusterRole := range resp.Items {
		resource, err := clusterRoleResource(&clusterRole)
		if err != nil {
			l.Error("failed to create cluster role resource",
				zap.String("name", clusterRole.Name),
				zap.Error(err))
			continue
		}
		rv = append(rv, resource)
	}

	// Calculate next page token
	nextPageToken, err := handleKubePagination(&resp.ListMeta, bag)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to handle pagination: %w", err)
	}

	return rv, nextPageToken, nil, nil
}

// clusterRoleResource creates a Baton resource from a Kubernetes ClusterRole
func clusterRoleResource(clusterRole *rbacv1.ClusterRole) (*v2.Resource, error) {
	// Prepare profile with standard metadata
	profile := map[string]interface{}{
		"name":              clusterRole.Name,
		"uid":               string(clusterRole.UID),
		"creationTimestamp": clusterRole.CreationTimestamp.String(),
		"labels":            StringMapToAnyMap(clusterRole.Labels),
		"annotations":       StringMapToAnyMap(clusterRole.Annotations),
	}

	// Add aggregation rule if present
	if clusterRole.AggregationRule != nil {
		profile["aggregationRule"] = clusterRole.AggregationRule
	}

	// Create resource as a role - pass the name directly as the raw ID
	resource, err := rs.NewRoleResource(
		clusterRole.Name,
		resourceTypeClusterRole,
		clusterRole.Name, // Pass the name directly as the object ID
		[]rs.RoleTraitOption{rs.WithRoleProfile(profile)},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create cluster role resource: %w", err)
	}

	return resource, nil
}

// Entitlements returns entitlements for ClusterRole resources
func (c *clusterRoleBuilder) Entitlements(ctx context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var entitlements []*v2.Entitlement

	// Create the 'member' entitlement for the cluster role
	memberEnt := entitlement.NewAssignmentEntitlement(
		resource,
		"member",
		entitlement.WithDisplayName(fmt.Sprintf("%s Cluster Role Member", resource.DisplayName)),
		entitlement.WithDescription(fmt.Sprintf("Grants membership to the %s cluster role", resource.DisplayName)),
		entitlement.WithGrantableTo(
			resourceTypeKubeUser,
			resourceTypeKubeGroup,
			resourceTypeServiceAccount,
		),
	)
	entitlements = append(entitlements, memberEnt)

	// Add 'bind' privilege escalation entitlement
	bindEnt := entitlement.NewPermissionEntitlement(
		resource,
		"bind",
		entitlement.WithDisplayName(fmt.Sprintf("Bind %s", resource.DisplayName)),
		entitlement.WithDescription(fmt.Sprintf("Grants the ability to bind the %s cluster role to subjects without having the permissions it grants", resource.DisplayName)),
		entitlement.WithGrantableTo(
			resourceTypeRole,
			resourceTypeClusterRole,
		),
	)
	entitlements = append(entitlements, bindEnt)

	// Add 'escalate' privilege escalation entitlement
	escalateEnt := entitlement.NewPermissionEntitlement(
		resource,
		"escalate",
		entitlement.WithDisplayName(fmt.Sprintf("Escalate %s", resource.DisplayName)),
		entitlement.WithDescription(fmt.Sprintf("Grants the ability to escalate the %s cluster role to include permissions that the user doesn't already have", resource.DisplayName)),
		entitlement.WithGrantableTo(
			resourceTypeRole,
			resourceTypeClusterRole,
		),
	)
	entitlements = append(entitlements, escalateEnt)

	return entitlements, "", nil, nil
}

// Grants returns permission grants for ClusterRole resources
func (c *clusterRoleBuilder) Grants(ctx context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	var rv []*v2.Grant

	// Extract cluster role name from resource
	if resource.Id == nil || resource.Id.Resource == "" {
		return nil, "", nil, fmt.Errorf("clusterRoleBuilder.Grants: invalid resource ID: %v", resource.Id)
	}
	name := resource.Id.Resource

	// Get the full ClusterRole object
	l.Debug("fetching cluster role for grants", zap.String("name", name))
	clusterRole, err := c.client.RbacV1().ClusterRoles().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to get cluster role %s: %w", name, err)
	}

	// Get matching role bindings and cluster role bindings from the binding provider
	matchingRoleBindings, matchingClusterBindings, err := c.bindingProvider.GetMatchingBindingsForClusterRole(ctx, name)
	if err != nil {
		// Non-fatal? Log and continue?
		l.Error("failed to get matching bindings for cluster role", zap.String("clusterRole", name), zap.Error(err))
		// Return error for now.
		return nil, "", nil, fmt.Errorf("failed to get matching bindings for cluster role %s: %w", name, err)
	}

	// Process each matching cluster binding (grants membership cluster-wide)
	for _, binding := range matchingClusterBindings {
		for _, subject := range binding.Subjects {
			// ClusterRoleBindings grant cluster-wide, so namespace is empty for subject mapping
			principalID, err := mapSubjectToPrincipalID(subject, "")
			if err != nil {
				l.Error("failed to map subject to principal ID for cluster membership grant",
					zap.String("clusterRole", name),
					zap.String("bindingName", binding.Name),
					zap.String("subjectKind", subject.Kind),
					zap.String("subjectName", subject.Name),
					zap.Error(err))
				continue // Skip this subject
			}

			memberGrant := grant.NewGrant(
				resource,                      // The ClusterRole being granted
				"member",                      // The membership entitlement
				&v2.Resource{Id: principalID}, // The subject gaining membership
			)
			rv = append(rv, memberGrant)
		}
	}

	// Process each matching role binding (grants membership within a specific namespace)
	for _, binding := range matchingRoleBindings {
		namespace := binding.Namespace // RoleBindings are namespaced
		for _, subject := range binding.Subjects {
			principalID, err := mapSubjectToPrincipalID(subject, namespace)
			if err != nil {
				l.Error("failed to map subject to principal ID for namespaced membership grant",
					zap.String("clusterRole", name),
					zap.String("bindingNamespace", namespace),
					zap.String("bindingName", binding.Name),
					zap.String("subjectKind", subject.Kind),
					zap.String("subjectName", subject.Name),
					zap.Error(err))
				continue // Skip this subject
			}

			memberGrant := grant.NewGrant(
				resource,                      // The ClusterRole being granted
				"member",                      // The membership entitlement
				&v2.Resource{Id: principalID}, // The subject gaining membership
			)
			rv = append(rv, memberGrant)
		}
	}

	// Generate Permission Grants using the helper function.
	// ClusterRoles are cluster-scoped, so pass empty string for namespace.
	permissionGrants, err := generatePermissionGrantsFromRules(ctx, l, resource, clusterRole.Rules, "")
	if err != nil {
		// Handle potential errors from the helper function, e.g., logging or returning
		return nil, "", nil, fmt.Errorf("failed to generate permission grants from rules for cluster role %s: %w", name, err)
	}
	rv = append(rv, permissionGrants...)

	return rv, "", nil, nil
}

// newClusterRoleBuilder creates a new cluster role builder
func newClusterRoleBuilder(client kubernetes.Interface, bindingProvider clusterRoleBindingProvider) *clusterRoleBuilder {
	return &clusterRoleBuilder{
		client:          client,
		bindingProvider: bindingProvider,
	}
}
