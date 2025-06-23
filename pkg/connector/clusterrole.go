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

// clusterRoleBuilder syncs Kubernetes ClusterRoles as Baton resources.
type clusterRoleBuilder struct {
	client          kubernetes.Interface
	bindingProvider clusterRoleBindingProvider
}

// ResourceType returns the resource type for ClusterRole.
func (c *clusterRoleBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return resourceTypeClusterRole
}

// List fetches all ClusterRoles from the Kubernetes API.
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

// clusterRoleResource creates a Baton resource from a Kubernetes ClusterRole.
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

// Entitlements returns entitlements for ClusterRole resources.
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

// Grants returns permission grants for ClusterRole resources.
func (c *clusterRoleBuilder) Grants(ctx context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	var rv []*v2.Grant

	// Extract cluster role name from resource
	if resource.Id == nil || resource.Id.Resource == "" {
		return nil, "", nil, fmt.Errorf("invalid resource ID")
	}
	name := resource.Id.Resource

	// Get the full ClusterRole object
	l.Debug("fetching cluster role for grants", zap.String("name", name))
	clusterRole, err := c.client.RbacV1().ClusterRoles().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to get cluster role: %w", err)
	}

	// Get matching role bindings and cluster role bindings from the binding provider
	matchingRoleBindings, matchingClusterBindings, err := c.bindingProvider.GetMatchingBindingsForClusterRole(ctx, name)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to get matching bindings: %w", err)
	}

	// If there are no bindings, there are no grants
	if len(matchingRoleBindings) == 0 && len(matchingClusterBindings) == 0 {
		l.Debug("no bindings found for cluster role", zap.String("name", name))
		return nil, "", nil, nil
	}

	// Define standard verbs for wildcard expansion
	standardVerbs := []string{"get", "list", "watch", "create", "update", "patch", "delete", "deletecollection"}

	// Process each matching cluster binding
	for _, binding := range matchingClusterBindings {
		// Process each subject in the binding
		for _, subject := range binding.Subjects {
			// Map the subject to its corresponding Baton principal resource ID
			principalID, err := mapSubjectToPrincipalID(subject, "")
			if err != nil {
				l.Error("failed to map subject to principal ID",
					zap.String("kind", subject.Kind),
					zap.String("name", subject.Name),
					zap.Error(err))
				continue
			}

			// Process each rule in the cluster role
			for _, rule := range clusterRole.Rules {
				// Skip non-resource URLs as they don't map to Baton resources
				if len(rule.NonResourceURLs) > 0 {
					l.Debug("skipping non-resource URLs in cluster role rule",
						zap.Strings("urls", rule.NonResourceURLs))
					continue
				}

				// Process each API group and resource combination
				for _, apiGroup := range rule.APIGroups {
					for _, res := range rule.Resources {
						targetResourceType := mapKubeResourceToBatonType(apiGroup, res)
						if targetResourceType == nil {
							l.Debug("unmapped resource type",
								zap.String("apiGroup", apiGroup),
								zap.String("resource", res))
							continue
						}

						// Create target resource ID
						resourceSpecifier := "*" // Wildcard by default
						if len(rule.ResourceNames) > 0 {
							// Log that we're targeting specific instances
							l.Debug("rule targets specific resource instances",
								zap.Strings("resourceNames", rule.ResourceNames))
							// For simplicity, we'll still grant on the type level
						}

						targetID, err := formatResourceID(targetResourceType, resourceSpecifier)
						if err != nil {
							l.Error("failed to create target resource ID",
								zap.String("apiGroup", apiGroup),
								zap.String("resource", res),
								zap.Error(err))
							continue
						}

						// Process each verb
						for _, verb := range rule.Verbs {
							// If the verb is "*", expand to all standard verbs
							if verb == "*" {
								// Create a grant for each standard verb
								for _, standardVerb := range standardVerbs {
									g := grant.NewGrant(
										&v2.Resource{Id: principalID},
										standardVerb,
										targetID,
									)
									rv = append(rv, g)
								}
							} else {
								// Create a grant for the specific verb
								g := grant.NewGrant(
									&v2.Resource{Id: principalID},
									verb,
									targetID,
								)
								rv = append(rv, g)
							}
						}
					}
				}
			}
		}
	}

	// Process each matching role binding
	for _, binding := range matchingRoleBindings {
		namespace := binding.Namespace

		// Process each subject in the binding
		for _, subject := range binding.Subjects {
			// Map the subject to its corresponding Baton principal resource ID
			principalID, err := mapSubjectToPrincipalID(subject, namespace)
			if err != nil {
				l.Error("failed to map subject to principal ID",
					zap.String("kind", subject.Kind),
					zap.String("name", subject.Name),
					zap.Error(err))
				continue
			}

			// Process each rule in the cluster role
			for _, rule := range clusterRole.Rules {
				// Skip non-resource URLs as they don't map to Baton resources
				if len(rule.NonResourceURLs) > 0 {
					l.Debug("skipping non-resource URLs in cluster role rule",
						zap.Strings("urls", rule.NonResourceURLs))
					continue
				}

				// Process each API group and resource combination
				for _, apiGroup := range rule.APIGroups {
					for _, res := range rule.Resources {
						targetResourceType := mapKubeResourceToBatonType(apiGroup, res)
						if targetResourceType == nil {
							l.Debug("unmapped resource type",
								zap.String("apiGroup", apiGroup),
								zap.String("resource", res))
							continue
						}

						// Create target resource ID
						resourceSpecifier := "*" // Wildcard by default
						if len(rule.ResourceNames) > 0 {
							// Log that we're targeting specific instances
							l.Debug("rule targets specific resource instances",
								zap.Strings("resourceNames", rule.ResourceNames))
							// For simplicity, we'll still grant on the type level
						}

						targetID, err := formatResourceID(targetResourceType, resourceSpecifier)
						if err != nil {
							l.Error("failed to create target resource ID",
								zap.String("apiGroup", apiGroup),
								zap.String("resource", res),
								zap.Error(err))
							continue
						}

						// Process each verb
						for _, verb := range rule.Verbs {
							// If the verb is "*", expand to all standard verbs
							if verb == "*" {
								// Create a grant for each standard verb
								for _, standardVerb := range standardVerbs {
									g := grant.NewGrant(
										&v2.Resource{Id: principalID},
										standardVerb,
										targetID,
									)
									rv = append(rv, g)
								}
							} else {
								// Create a grant for the specific verb
								g := grant.NewGrant(
									&v2.Resource{Id: principalID},
									verb,
									targetID,
								)
								rv = append(rv, g)
							}
						}
					}
				}
			}
		}
	}

	return rv, "", nil, nil
}

// newClusterRoleBuilder creates a new cluster role builder.
func newClusterRoleBuilder(client kubernetes.Interface, bindingProvider clusterRoleBindingProvider) *clusterRoleBuilder {
	return &clusterRoleBuilder{
		client:          client,
		bindingProvider: bindingProvider,
	}
}
