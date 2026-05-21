package connector

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	rbacv1 "k8s.io/api/rbac/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/types/entitlement"
	sdkGrant "github.com/conductorone/baton-sdk/pkg/types/grant"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

const namespaceCacheTTL = 5 * time.Minute
const clusterScopedMember = "all:member"

// clusterRoleBuilder syncs Kubernetes ClusterRoles as Baton resources.
type clusterRoleBuilder struct {
	client          kubernetes.Interface
	bindingProvider ClusterRoleBindingProvider
	// Cached namespaces
	cachedNamespaces []string
	nsMutex          sync.Mutex
	nsCacheExpiry    time.Time
}

// ResourceType returns the resource type for ClusterRole.
func (c *clusterRoleBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return ResourceTypeClusterRole
}

// List fetches all ClusterRoles from the Kubernetes API.
func (c *clusterRoleBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	// Initialize empty resource slice
	var rv []*v2.Resource

	// Parse pagination token
	bag, err := ParsePageToken(pToken.Token)
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
	nextPageToken, err := HandleKubePagination(&resp.ListMeta, bag)
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
		agRule, err := ParseAggregationRule(clusterRole.AggregationRule)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal aggregation rule: %w", err)
		}
		profile["aggregationRule"] = agRule
	}

	// Create resource as a role - pass the name directly as the raw ID
	resource, err := rs.NewRoleResource(
		clusterRole.Name,
		ResourceTypeClusterRole,
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

	// Create the 'all:member' entitlement for the cluster role for cluster level (all namespaces)
	memberEnt := entitlement.NewAssignmentEntitlement(
		resource,
		clusterScopedMember,
		entitlement.WithDisplayName(fmt.Sprintf("%s Cluster Role Member", resource.DisplayName)),
		entitlement.WithDescription(fmt.Sprintf("Grants membership to the %s cluster role", resource.DisplayName)),
		entitlement.WithGrantableTo(
			ResourceTypeKubeUser,
			ResourceTypeKubeGroup,
			ResourceTypeServiceAccount,
		),
	)
	entitlements = append(entitlements, memberEnt)

	// Each ClusterRole can be granted in a RoleBinding, thus binding it to a namespace.
	// Create entitlements for each namespace.
	err := c.cacheNamespaces(ctx)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to cache namespaces: %w", err)
	}

	for _, ns := range c.cachedNamespaces {
		entitlementName := fmt.Sprintf("%s:%s", ns, "member")
		nsEnt := entitlement.NewAssignmentEntitlement(
			resource,
			entitlementName,
			entitlement.WithDisplayName(fmt.Sprintf("\"%s\" Cluster Role Member in \"%s\" namespace", resource.DisplayName, ns)),
			entitlement.WithDescription(fmt.Sprintf("Grants membership to the \"%s\" cluster role in namespace \"%s\"", resource.DisplayName, ns)),
			entitlement.WithGrantableTo(
				ResourceTypeKubeUser,
				ResourceTypeKubeGroup,
				ResourceTypeServiceAccount,
			),
		)
		entitlements = append(entitlements, nsEnt)
	}

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

	// Process each matching cluster binding
	for _, binding := range matchingClusterBindings {
		// Process each subject in the binding
		for _, subject := range binding.Subjects {
			subjectGrant, err := GrantRoleToSubject(subject, resource, clusterScopedMember)
			if err != nil {
				l.Debug("subject type not supported", zap.String("subject kind", subject.Kind))
				continue
			}
			rv = append(rv, subjectGrant)
		}
	}

	// Process each matching role binding
	for _, binding := range matchingRoleBindings {
		namespace := binding.Namespace
		// Process each subject in the binding
		for _, subject := range binding.Subjects {
			entName := fmt.Sprintf("%s:%s", namespace, "member")
			subjectGrant, err := GrantRoleToSubject(subject, resource, entName)
			if err != nil {
				l.Debug("subject kind not supported", zap.String("subject kind", subject.Kind))
				continue
			}
			rv = append(rv, subjectGrant)
		}
	}

	return rv, "", nil, nil
}

// getNamespaces returns cached namespaces or fetches them if cache is expired or empty.
func (c *clusterRoleBuilder) cacheNamespaces(ctx context.Context) error {
	c.nsMutex.Lock()
	defer c.nsMutex.Unlock()

	now := time.Now()
	if c.cachedNamespaces != nil && now.Before(c.nsCacheExpiry) {
		// Cache is valid.
		return nil
	}
	var (
		names      []string
		continueAt string
	)
	for {
		opts := metav1.ListOptions{
			Continue: continueAt,
		}
		nsList, err := c.client.CoreV1().Namespaces().List(ctx, opts)
		if err != nil {
			return fmt.Errorf("failed to cache namespaces list: %w", err)
		}
		for _, ns := range nsList.Items {
			names = append(names, ns.Name)
		}
		if nsList.Continue == "" {
			break
		}
		continueAt = nsList.Continue
	}

	c.cachedNamespaces = names
	c.nsCacheExpiry = now.Add(namespaceCacheTTL)
	return nil
}

var k8sNameRegexp = regexp.MustCompile(`[^a-z0-9-]`)

const (
	maxK8sNameLen = 253
	batonLabel    = "app.kubernetes.io/managed-by"
	batonLabelVal = "baton-kubernetes"
)

func sanitizeK8sName(s string) string {
	s = strings.ToLower(s)
	s = k8sNameRegexp.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if len(s) > maxK8sNameLen {
		s = s[:maxK8sNameLen]
	}
	return s
}

func bindingName(clusterRole, subjectKind, subjectName string) string {
	return sanitizeK8sName(fmt.Sprintf("baton-%s-%s-%s", clusterRole, subjectKind, subjectName))
}

func principalToK8sSubject(principal *v2.Resource) (rbacv1.Subject, error) {
	switch principal.GetId().GetResourceType() {
	case ResourceTypeKubeUser.Id:
		return rbacv1.Subject{
			Kind:     SubjectKindUser,
			Name:     principal.GetId().GetResource(),
			APIGroup: RBACAPIGroup,
		}, nil
	case ResourceTypeKubeGroup.Id:
		return rbacv1.Subject{
			Kind:     SubjectKindGroup,
			Name:     principal.GetId().GetResource(),
			APIGroup: RBACAPIGroup,
		}, nil
	case ResourceTypeServiceAccount.Id:
		parts := strings.SplitN(principal.GetId().GetResource(), "/", 2)
		if len(parts) != 2 {
			return rbacv1.Subject{}, fmt.Errorf("baton-kubernetes: invalid service account ID %q, expected namespace/name", principal.GetId().GetResource())
		}
		return rbacv1.Subject{
			Kind:      SubjectKindServiceAccount,
			Name:      parts[1],
			Namespace: parts[0],
		}, nil
	default:
		return rbacv1.Subject{}, fmt.Errorf("baton-kubernetes: unsupported principal type %q", principal.GetId().GetResourceType())
	}
}

// Grant creates a ClusterRoleBinding (cluster-scoped) or RoleBinding (namespace-scoped)
// to bind the principal to the ClusterRole.
func (c *clusterRoleBuilder) Grant(ctx context.Context, principal *v2.Resource, ent *v2.Entitlement) ([]*v2.Grant, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	clusterRoleName := ent.GetResource().GetId().GetResource()
	slug := ent.GetSlug()

	subject, err := principalToK8sSubject(principal)
	if err != nil {
		return nil, nil, err
	}

	l.Info("granting cluster role",
		zap.String("cluster_role", clusterRoleName),
		zap.String("slug", slug),
		zap.String("subject_kind", subject.Kind),
		zap.String("subject_name", subject.Name),
	)

	labels := map[string]string{
		batonLabel: batonLabelVal,
	}

	if slug == clusterScopedMember {
		name := bindingName(clusterRoleName, subject.Kind, subject.Name)
		binding := &rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:   name,
				Labels: labels,
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: RBACAPIGroup,
				Kind:     "ClusterRole",
				Name:     clusterRoleName,
			},
			Subjects: []rbacv1.Subject{subject},
		}

		_, err := c.client.RbacV1().ClusterRoleBindings().Create(ctx, binding, metav1.CreateOptions{})
		if err != nil {
			if k8serrors.IsAlreadyExists(err) {
				g := sdkGrant.NewGrant(ent.GetResource(), slug, principal.GetId())
				return []*v2.Grant{g}, nil, nil
			}
			return nil, nil, fmt.Errorf("baton-kubernetes: failed to create cluster role binding: %w", err)
		}
	} else {
		parts := strings.SplitN(slug, ":", 2)
		if len(parts) != 2 {
			return nil, nil, fmt.Errorf("baton-kubernetes: invalid entitlement slug %q", slug)
		}
		namespace := parts[0]

		name := bindingName(clusterRoleName, subject.Kind, subject.Name)
		binding := &rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
				Labels:    labels,
			},
			RoleRef: rbacv1.RoleRef{
				APIGroup: RBACAPIGroup,
				Kind:     "ClusterRole",
				Name:     clusterRoleName,
			},
			Subjects: []rbacv1.Subject{subject},
		}

		_, err := c.client.RbacV1().RoleBindings(namespace).Create(ctx, binding, metav1.CreateOptions{})
		if err != nil {
			if k8serrors.IsAlreadyExists(err) {
				g := sdkGrant.NewGrant(ent.GetResource(), slug, principal.GetId())
				return []*v2.Grant{g}, nil, nil
			}
			return nil, nil, fmt.Errorf("baton-kubernetes: failed to create role binding in namespace %s: %w", namespace, err)
		}
	}

	g := sdkGrant.NewGrant(ent.GetResource(), slug, principal.GetId())
	return []*v2.Grant{g}, nil, nil
}

// Revoke removes the principal's binding to the ClusterRole.
// It first tries to delete a baton-managed binding by deterministic name.
// If not found, it searches all bindings for the role and removes the subject.
func (c *clusterRoleBuilder) Revoke(ctx context.Context, grantObj *v2.Grant) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	clusterRoleName := grantObj.GetEntitlement().GetResource().GetId().GetResource()
	slug := grantObj.GetEntitlement().GetSlug()

	subject, err := principalToK8sSubject(grantObj.GetPrincipal())
	if err != nil {
		return nil, err
	}

	l.Info("revoking cluster role",
		zap.String("cluster_role", clusterRoleName),
		zap.String("slug", slug),
		zap.String("subject_kind", subject.Kind),
		zap.String("subject_name", subject.Name),
	)

	if slug == clusterScopedMember {
		return c.revokeClusterScoped(ctx, clusterRoleName, subject)
	}

	parts := strings.SplitN(slug, ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("baton-kubernetes: invalid entitlement slug %q", slug)
	}
	return c.revokeNamespaceScoped(ctx, clusterRoleName, parts[0], subject)
}

func (c *clusterRoleBuilder) revokeClusterScoped(ctx context.Context, clusterRoleName string, subject rbacv1.Subject) (annotations.Annotations, error) {
	name := bindingName(clusterRoleName, subject.Kind, subject.Name)

	err := c.client.RbacV1().ClusterRoleBindings().Delete(ctx, name, metav1.DeleteOptions{})
	if err == nil {
		return nil, nil
	}
	if !k8serrors.IsNotFound(err) {
		return nil, fmt.Errorf("baton-kubernetes: failed to delete cluster role binding %s: %w", name, err)
	}

	return c.revokeSubjectFromClusterRoleBindings(ctx, clusterRoleName, subject)
}

func (c *clusterRoleBuilder) revokeSubjectFromClusterRoleBindings(ctx context.Context, clusterRoleName string, subject rbacv1.Subject) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	var continueToken string
	for {
		bindings, err := c.client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{
			Limit:    ResourcesPageSize,
			Continue: continueToken,
		})
		if err != nil {
			return nil, fmt.Errorf("baton-kubernetes: failed to list cluster role bindings: %w", err)
		}

		for _, binding := range bindings.Items {
			if binding.RoleRef.Kind != "ClusterRole" || binding.RoleRef.Name != clusterRoleName {
				continue
			}
			if updated, found := removeSubject(binding.Subjects, subject); found {
				if len(updated) == 0 {
					if err := c.client.RbacV1().ClusterRoleBindings().Delete(ctx, binding.Name, metav1.DeleteOptions{}); err != nil && !k8serrors.IsNotFound(err) {
						return nil, fmt.Errorf("baton-kubernetes: failed to delete cluster role binding %s: %w", binding.Name, err)
					}
				} else {
					binding.Subjects = updated
					if _, err := c.client.RbacV1().ClusterRoleBindings().Update(ctx, &binding, metav1.UpdateOptions{}); err != nil {
						return nil, fmt.Errorf("baton-kubernetes: failed to update cluster role binding %s: %w", binding.Name, err)
					}
				}
				l.Info("revoked subject from cluster role binding", zap.String("binding", binding.Name))
				return nil, nil
			}
		}

		if bindings.Continue == "" {
			break
		}
		continueToken = bindings.Continue
	}

	return nil, nil
}

func (c *clusterRoleBuilder) revokeNamespaceScoped(ctx context.Context, clusterRoleName, namespace string, subject rbacv1.Subject) (annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	name := bindingName(clusterRoleName, subject.Kind, subject.Name)

	err := c.client.RbacV1().RoleBindings(namespace).Delete(ctx, name, metav1.DeleteOptions{})
	if err == nil {
		return nil, nil
	}
	if !k8serrors.IsNotFound(err) {
		return nil, fmt.Errorf("baton-kubernetes: failed to delete role binding %s in namespace %s: %w", name, namespace, err)
	}

	bindings, err := c.client.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("baton-kubernetes: failed to list role bindings in namespace %s: %w", namespace, err)
	}

	for _, binding := range bindings.Items {
		if binding.RoleRef.Kind != "ClusterRole" || binding.RoleRef.Name != clusterRoleName {
			continue
		}
		if updated, found := removeSubject(binding.Subjects, subject); found {
			if len(updated) == 0 {
				if err := c.client.RbacV1().RoleBindings(namespace).Delete(ctx, binding.Name, metav1.DeleteOptions{}); err != nil && !k8serrors.IsNotFound(err) {
					return nil, fmt.Errorf("baton-kubernetes: failed to delete role binding %s: %w", binding.Name, err)
				}
			} else {
				binding.Subjects = updated
				if _, err := c.client.RbacV1().RoleBindings(namespace).Update(ctx, &binding, metav1.UpdateOptions{}); err != nil {
					return nil, fmt.Errorf("baton-kubernetes: failed to update role binding %s: %w", binding.Name, err)
				}
			}
			l.Info("revoked subject from role binding", zap.String("binding", binding.Name), zap.String("namespace", namespace))
			return nil, nil
		}
	}

	return nil, nil
}

func removeSubject(subjects []rbacv1.Subject, target rbacv1.Subject) ([]rbacv1.Subject, bool) {
	var result []rbacv1.Subject
	found := false
	for _, s := range subjects {
		if s.Kind == target.Kind && s.Name == target.Name && s.Namespace == target.Namespace {
			found = true
			continue
		}
		result = append(result, s)
	}
	return result, found
}

// newClusterRoleBuilder creates a new cluster role builder.
func newClusterRoleBuilder(client kubernetes.Interface, bindingProvider ClusterRoleBindingProvider) *clusterRoleBuilder {
	return &clusterRoleBuilder{
		client:          client,
		bindingProvider: bindingProvider,
	}
}
