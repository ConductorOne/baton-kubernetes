package connector

import (
	"context"
	"fmt"
	"sort"
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
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

// TODO(enhancement): Move this map and helper to a more central location like types.go or helpers.go
var namespacedResourceTypes = map[string]bool{
	resourceTypePod.Id:       true,
	resourceTypeSecret.Id:    true,
	resourceTypeConfigMap.Id: true,
	// resourceTypeService.Id:     true, // Assuming service is namespaced - uncomment if defined
	resourceTypeServiceAccount.Id: true,
	resourceTypeDeployment.Id:     true,
	resourceTypeStatefulSet.Id:    true,
	resourceTypeDaemonSet.Id:      true,
	resourceTypeRole.Id:           true,
	resourceTypeBinding.Id:        true, // RoleBinding is namespaced
	resourceTypeNamespace.Id:      false,
	resourceTypeNode.Id:           false,
	resourceTypeClusterRole.Id:    false,
	// resourceTypeClusterBinding.Id: false, // Assuming ClusterRoleBinding is cluster-scoped - uncomment if defined
	// Add other resource types here
	resourceTypeKubeUser.Id:  false, // Virtual type, treated as cluster-scoped for mapping
	resourceTypeKubeGroup.Id: false, // Virtual type, treated as cluster-scoped for mapping
}

// isNamespacedType checks if a Baton resource type ID corresponds to a namespaced Kubernetes resource.
func isNamespacedType(resourceTypeId string) bool {
	return namespacedResourceTypes[resourceTypeId] // Defaults to false if not found
}

// roleBuilder syncs Kubernetes Roles as Baton resources
type roleBuilder struct {
	client          kubernetes.Interface
	bindingProvider roleBindingProvider
}

// ResourceType returns the resource type for Role
func (r *roleBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return resourceTypeRole
}

// List fetches all Roles from the Kubernetes API
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

// roleResource creates a Baton resource from a Kubernetes Role
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

// Entitlements returns entitlements for Role resources
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

// mapKubeResourceToBatonType maps Kubernetes API groups and resources to Baton resource types
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
		case "rolebindings", "rolebinding":
			return resourceTypeBinding
		case "clusterrolebindings", "clusterrolebinding":
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

// parseResourceID extracts namespace and name from a role resource ID
func parseRoleResourceID(resourceID *v2.ResourceId) (namespace string, name string, err error) {
	if resourceID == nil {
		return "", "", fmt.Errorf("resource ID is nil")
	}

	parts := strings.Split(resourceID.Resource, "/")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid resource ID format: %s", resourceID.Resource)
	}

	return parts[0], parts[1], nil
}

// Define standard verbs for wildcard expansion - ensure this list is comprehensive
var standardVerbs = []string{"get", "list", "watch", "create", "update", "patch", "delete", "deletecollection"}

// determineGrantVerbs takes the verbs from a PolicyRule and returns a deduplicated slice
// of effective verbs, expanding '*' or "" to the standard set.
func determineGrantVerbs(ruleVerbs []string) []string {
	rv := mapset.NewThreadUnsafeSet[string]()
	expandToStandard := false

	for _, verb := range ruleVerbs {
		// If a wildcard verb is present, we grant all standard verbs.
		if verb == "*" || verb == "" {
			expandToStandard = true
			break
		} else {
			rv.Add(verb)
		}
	}

	if expandToStandard {
		rv.Clear()
		rv.Append(standardVerbs...)
	}

	// Convert set back to slice for consistent return type.
	if rv.Cardinality() == 0 {
		return nil // Return nil explicitly if no verbs are granted
	}
	finalVerbs := rv.ToSlice()
	sort.Strings(finalVerbs)
	return finalVerbs
}

// generatePermissionGrantsFromRules processes RBAC rules to create Baton permission grants.
// These grants use the provided principalResource (Role or ClusterRole) as the grantor.
// It handles wildcard resources and specific resource names within rules, considering namespace context.
func generatePermissionGrantsFromRules(ctx context.Context, l *zap.Logger, principalResource *v2.Resource, rules []rbacv1.PolicyRule, currentNamespace string) ([]*v2.Grant, error) {
	var rv []*v2.Grant
	principalIdStr := principalResource.Id.String()

	for i, rule := range rules {
		// Skip non-resource URLs
		if len(rule.NonResourceURLs) > 0 {
			l.Debug("skipping non-resource URLs in rule",
				zap.String("principal_id", principalIdStr),
				zap.Int("rule_index", i),
				zap.Strings("urls", rule.NonResourceURLs))
			continue
		}

		// Determine the set of verbs to grant for this rule
		grantVerbs := determineGrantVerbs(rule.Verbs)
		if len(grantVerbs) == 0 {
			l.Debug("no effective verbs determined for rule",
				zap.String("principal_id", principalIdStr),
				zap.Int("rule_index", i))
			continue
		}

		// Process each API group and resource combination defined in the rule
		for _, apiGroup := range rule.APIGroups {
			for _, res := range rule.Resources {
				targetResourceType := mapKubeResourceToBatonType(apiGroup, res)
				if targetResourceType == nil {
					l.Debug("unmapped resource type for permission grant",
						zap.String("principal_id", principalIdStr),
						zap.Int("rule_index", i),
						zap.String("apiGroup", apiGroup),
						zap.String("resource", res))
					continue
				}

				// Check if the target resource type is namespaced
				isTargetNamespaced := isNamespacedType(targetResourceType.Id)

				// Check if rule specifies particular resource names
				if len(rule.ResourceNames) > 0 {
					// Grant permissions on specific resource instances
					for _, resourceName := range rule.ResourceNames {
						var objectId string
						// If the principal is namespaced (Role) and the target type is namespaced,
						// construct the namespaced ID (namespace/name).
						if currentNamespace != "" && isTargetNamespaced {
							objectId = currentNamespace + "/" + resourceName
						} else {
							// Otherwise (ClusterRole principal or cluster-scoped target),
							// use the resource name directly.
							objectId = resourceName
						}

						targetID, err := formatResourceID(targetResourceType, objectId)
						if err != nil {
							l.Error("failed to create specific target resource ID for permission grant",
								zap.String("principal_id", principalIdStr),
								zap.Int("rule_index", i),
								zap.String("target_type_id", targetResourceType.Id),
								zap.String("object_id", objectId),
								zap.Error(err))
							continue // Skip this specific resource name on error
						}
						targetResource := &v2.Resource{Id: targetID}

						// Create grants for all determined verbs for this specific resource
						for _, verb := range grantVerbs {
							permissionGrant := grant.NewGrant(
								targetResource,    // Specific resource instance
								verb,              // The permission/entitlement (verb)
								principalResource, // The Role/ClusterRole granting the permission (principal)
							)
							rv = append(rv, permissionGrant)
						}
					}
				} else {
					// Grant permissions on the resource type (wildcard)
					// The target ID remains wildcarded, namespace context is implicit via the principal.
					targetID, err := formatResourceID(targetResourceType, "*")
					if err != nil {
						l.Error("failed to create wildcard target resource ID for permission grant",
							zap.String("principal_id", principalIdStr),
							zap.Int("rule_index", i),
							zap.String("target_type_id", targetResourceType.Id),
							zap.Error(err))
						continue // Skip this resource type on error
					}
					targetResource := &v2.Resource{Id: targetID}

					// Create grants for all determined verbs for this resource type
					for _, verb := range grantVerbs {
						permissionGrant := grant.NewGrant(
							targetResource,    // Resource type (wildcard)
							verb,              // The permission/entitlement (verb)
							principalResource, // The Role/ClusterRole granting the permission (principal)
						)
						rv = append(rv, permissionGrant)
					}
				}
			}
		}
	}

	return rv, nil
}

// Grants returns permission grants for Role resources
func (r *roleBuilder) Grants(ctx context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	l = l.With(zap.String("resource_id", resource.Id.String()))
	var rv []*v2.Grant

	// Parse the resource ID to get namespace and name
	namespace, name, err := parseRoleResourceID(resource.Id)
	if err != nil {
		// If parsing fails here, we can't proceed reasonably.
		return nil, "", nil, fmt.Errorf("failed to parse role resource ID %v: %w", resource.Id, err)
	}

	// Get the full Role object
	l.Debug("fetching role for grants", zap.String("namespace", namespace), zap.String("name", name))
	role, err := r.client.RbacV1().Roles(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to get role %s/%s: %w", namespace, name, err)
	}

	// Get matching role bindings from the binding provider
	matchingBindings, err := r.bindingProvider.GetMatchingRoleBindings(ctx, namespace, name)
	if err != nil {
		// Non-fatal? Log and continue without membership grants?
		l.Error("failed to get matching role bindings", zap.Error(err))
		// For now, let's return error to be safe.
		return nil, "", nil, fmt.Errorf("failed to get matching role bindings for role %s/%s: %w", namespace, name, err)
	}

	// Generate Membership Grants: Grant Role membership to bound subjects
	for _, binding := range matchingBindings {
		for _, subject := range binding.Subjects {
			principalID, err := mapSubjectToPrincipalID(subject, namespace)
			if err != nil {
				l.Error("failed to map subject to principal ID for membership grant",
					zap.String("role_namespace", namespace),
					zap.String("role_name", name),
					zap.String("subjectKind", subject.Kind),
					zap.String("subjectName", subject.Name),
					zap.Error(err))
				// Decide if we should continue or return an error. Continuing might be better for partial data.
				continue
			}

			memberGrant := grant.NewGrant(
				resource,                      // The Role being granted
				"member",                      // The membership entitlement
				&v2.Resource{Id: principalID}, // The subject (User, Group, SA) gaining membership
			)
			rv = append(rv, memberGrant)
		}
	}

	// Generate Permission Grants: Define what permissions the Role itself grants
	// These grants use the Role as the principal, allowing Baton to expand them.
	// Pass the role's namespace to the helper function.
	permissionGrants, err := generatePermissionGrantsFromRules(ctx, l, resource, role.Rules, namespace)
	if err != nil {
		// If the helper function returns an error, wrap and return it.
		return nil, "", nil, fmt.Errorf("failed to generate permission grants for role %s/%s: %w", namespace, name, err)
	}
	rv = append(rv, permissionGrants...)

	return rv, "", nil, nil
}

// newRoleBuilder creates a new role builder
func newRoleBuilder(client kubernetes.Interface, bindingProvider roleBindingProvider) *roleBuilder {
	return &roleBuilder{
		client:          client,
		bindingProvider: bindingProvider,
	}
}
