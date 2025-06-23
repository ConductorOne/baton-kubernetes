package connector

import (
	"context"
	"fmt"
	"strings"

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

// roleBuilder syncs Kubernetes Roles as Baton resources.
type roleBuilder struct {
	client          kubernetes.Interface
	bindingProvider roleBindingProvider
}

// ResourceType returns the resource type for Role.
func (r *roleBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return resourceTypeRole
}

// List fetches all Roles from the Kubernetes API.
func (r *roleBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
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

	// Fetch roles from the Kubernetes API across all namespaces
	l.Debug("fetching roles", zap.String("continue_token", opts.Continue))
	resp, err := r.client.RbacV1().Roles("").List(ctx, opts)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to list roles: %w", err)
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
	nextPageToken, err := handleKubePagination(&resp.ListMeta, bag)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to handle pagination: %w", err)
	}

	return rv, nextPageToken, nil, nil
}

// roleResource creates a Baton resource from a Kubernetes Role.
func roleResource(role *rbacv1.Role) (*v2.Resource, error) {
	// Prepare profile with standard metadata
	profile := map[string]interface{}{
		"name":              role.Name,
		"namespace":         role.Namespace,
		"uid":               string(role.UID),
		"creationTimestamp": role.CreationTimestamp.String(),
	}

	// Only add labels and annotations if they're not nil to avoid proto conversion issues
	if role.Labels != nil {
		profile["labels"] = StringMapToAnyMap(role.Labels)
	}
	if role.Annotations != nil {
		profile["annotations"] = StringMapToAnyMap(role.Annotations)
	}

	// Get parent namespace resource ID
	parentID, err := namespaceResourceID(role.Namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to create parent resource ID: %w", err)
	}

	// Create the raw ID as namespace/name
	rawID := role.Namespace + "/" + role.Name

	// Create resource as a role with parent namespace
	resource, err := rs.NewRoleResource(
		role.Name,
		resourceTypeRole,
		rawID, // Pass the raw ID directly
		[]rs.RoleTraitOption{rs.WithRoleProfile(profile)},
		rs.WithParentResourceID(parentID),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create role resource: %w", err)
	}

	return resource, nil
}

// Entitlements returns entitlements for Role resources.
func (r *roleBuilder) Entitlements(ctx context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var entitlements []*v2.Entitlement

	// Create the 'member' entitlement for the role
	memberEnt := entitlement.NewAssignmentEntitlement(
		resource,
		"member",
		entitlement.WithDisplayName(fmt.Sprintf("%s Role Member", resource.DisplayName)),
		entitlement.WithDescription(fmt.Sprintf("Grants membership to the %s role", resource.DisplayName)),
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
		entitlement.WithDescription(fmt.Sprintf("Grants the ability to bind the %s role to subjects without having the permissions it grants", resource.DisplayName)),
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
		entitlement.WithDescription(fmt.Sprintf("Grants the ability to escalate the %s role to include permissions that the user doesn't already have", resource.DisplayName)),
		entitlement.WithGrantableTo(
			resourceTypeRole,
			resourceTypeClusterRole,
		),
	)
	entitlements = append(entitlements, escalateEnt)

	return entitlements, "", nil, nil
}

// mapKubeResourceToBatonType maps Kubernetes API groups and resources to Baton resource types.
func mapKubeResourceToBatonType(apiGroup string, resource string) *v2.ResourceType {
	// Core API group (indicated by empty string)
	if apiGroup == "" || apiGroup == "core" {
		switch resource {
		case "pods", "pod":
			return resourceTypePod
		case "namespaces", "namespace":
			return resourceTypeNamespace
		case "services", "service":
			// There's no service resource type defined in the current scope,
			// but we could return nil or a placeholder
			return nil
		case "configmaps", "configmap":
			return resourceTypeConfigMap
		case "secrets", "secret":
			return resourceTypeSecret
		case "serviceaccounts", "serviceaccount":
			return resourceTypeServiceAccount
		case "nodes", "node":
			return resourceTypeNode
		// Added explicit mapping for users and groups for impersonate
		case "users", "user":
			return resourceTypeKubeUser
		case "groups", "group":
			return resourceTypeKubeGroup
		case "*":
			// Wildcard for all core resources
			return nil
		}
	}

	// Apps API group
	if apiGroup == "apps" || apiGroup == "apps/v1" {
		switch resource {
		case "deployments", "deployment":
			return resourceTypeDeployment
		case "statefulsets", "statefulset":
			return resourceTypeStatefulSet
		case "daemonsets", "daemonset":
			return resourceTypeDaemonSet
		case "*":
			// Wildcard for all apps resources
			return nil
		}
	}

	// RBAC API group
	if apiGroup == "rbac.authorization.k8s.io" || apiGroup == "rbac.authorization.k8s.io/v1" {
		switch resource {
		case "roles", "role":
			return resourceTypeRole
		case "clusterroles", "clusterrole":
			return resourceTypeClusterRole
		case ResourceTypeRoleBinding, ResourceTypeRoleBindings:
			return resourceTypeBinding
		case ResourceTypeClusterRoleBindings, ResourceTypeClusterRoleBinding:
			return resourceTypeBinding
		case "*":
			// Wildcard for all RBAC resources
			return nil
		}
	}

	// Authentication and authorization groups - for impersonation targets
	if apiGroup == "user.openshift.io" || apiGroup == "user.openshift.io/v1" {
		switch resource {
		case "users", "user":
			return resourceTypeKubeUser
		case "groups", "group":
			return resourceTypeKubeGroup
		}
	}

	// Wildcard API group
	if apiGroup == "*" {
		// Return nil for wildcard - handling these is complex as they
		// could apply to any resource type
		return nil
	}

	// For unknown or unsupported resource types
	return nil
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
func (r *roleBuilder) Grants(ctx context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	var rv []*v2.Grant

	// Parse the resource ID to get namespace and name
	namespace, name, err := parseRoleResourceID(resource.Id)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to parse resource ID: %w", err)
	}

	// Get the full Role object
	l.Debug("fetching role for grants", zap.String("namespace", namespace), zap.String("name", name))
	role, err := r.client.RbacV1().Roles(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to get role: %w", err)
	}

	// Get matching role bindings from the binding provider
	matchingBindings, err := r.bindingProvider.GetMatchingRoleBindings(ctx, namespace, name)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to get matching role bindings: %w", err)
	}

	// If there are no bindings, there are no grants
	if len(matchingBindings) == 0 {
		l.Debug("no role bindings found for role", zap.String("namespace", namespace), zap.String("name", name))
		return nil, "", nil, nil
	}

	// Define standard verbs for wildcard expansion
	standardVerbs := []string{"get", "list", "watch", "create", "update", "patch", "delete", "deletecollection"}

	// Process each matching binding
	for _, binding := range matchingBindings {
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

			// Process each rule in the role
			for _, rule := range role.Rules {
				// Skip non-resource URLs as they don't map to Baton resources
				if len(rule.NonResourceURLs) > 0 {
					l.Debug("skipping non-resource URLs in role rule",
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

// newRoleBuilder creates a new role builder.
func newRoleBuilder(client kubernetes.Interface, bindingProvider roleBindingProvider) *roleBuilder {
	return &roleBuilder{
		client:          client,
		bindingProvider: bindingProvider,
	}
}
