package connector

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/types/entitlement"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

// serviceAccountBuilder syncs Kubernetes ServiceAccounts as Baton users.
type serviceAccountBuilder struct {
	client kubernetes.Interface
}

// ResourceType returns the resource type for ServiceAccount.
func (s *serviceAccountBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return ResourceTypeServiceAccount
}

// List fetches all ServiceAccounts from the Kubernetes API.
func (s *serviceAccountBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	// Initialize empty resource slice
	var rv []*v2.Resource

	// Parse pagination token
	bag, err := ParsePageToken(pToken.Token)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to parse page token: %w", err)
	}

	// Add wildcard resource first, but only on the first page (when page token is empty)
	if bag.PageToken() == "" {
		wildcardResource, err := generateWildcardResource(ResourceTypeServiceAccount)
		if err != nil {
			l.Error("failed to create wildcard resource for service accounts", zap.Error(err))
		} else {
			rv = append(rv, wildcardResource)
		}
	}

	// Set up list options with pagination
	opts := metav1.ListOptions{
		Limit:    ResourcesPageSize,
		Continue: bag.PageToken(),
	}

	// Fetch service accounts from the Kubernetes API across all namespaces
	l.Debug("fetching service accounts", zap.String("continue_token", opts.Continue))
	resp, err := s.client.CoreV1().ServiceAccounts("").List(ctx, opts)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to list service accounts: %w", err)
	}

	// Process each service account into a Baton resource
	for _, sa := range resp.Items {
		resource, err := serviceAccountResource(&sa)
		if err != nil {
			l.Error("failed to create service account resource",
				zap.String("namespace", sa.Namespace),
				zap.String("name", sa.Name),
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

// serviceAccountResource creates a Baton resource from a Kubernetes ServiceAccount.
func serviceAccountResource(serviceAccount *corev1.ServiceAccount) (*v2.Resource, error) {
	// Prepare profile with standard metadata
	profile := map[string]interface{}{
		"name":              serviceAccount.Name,
		"namespace":         serviceAccount.Namespace,
		"uid":               string(serviceAccount.UID),
		"creationTimestamp": serviceAccount.CreationTimestamp.String(),
		"labels":            StringMapToAnyMap(serviceAccount.Labels),
		"annotations":       StringMapToAnyMap(serviceAccount.Annotations),
	}

	// Add secrets if present
	if len(serviceAccount.Secrets) > 0 {
		secretNames := make([]string, 0, len(serviceAccount.Secrets))
		for _, secret := range serviceAccount.Secrets {
			secretNames = append(secretNames, secret.Name)
		}
		profile["secrets"] = secretNames
	}

	// Add image pull secrets if present
	if len(serviceAccount.ImagePullSecrets) > 0 {
		secretNames := make([]string, 0, len(serviceAccount.ImagePullSecrets))
		for _, secret := range serviceAccount.ImagePullSecrets {
			secretNames = append(secretNames, secret.Name)
		}
		profile["imagePullSecrets"] = secretNames
	}

	// Get parent namespace resource ID
	parentID, err := NamespaceResourceID(serviceAccount.Namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to create parent resource ID: %w", err)
	}

	// Unique ID is namespace/name
	rawID := serviceAccount.Namespace + "/" + serviceAccount.Name

	// Create resource with parent namespace
	resource, err := rs.NewUserResource(
		serviceAccount.Name,
		ResourceTypeServiceAccount,
		rawID,
		[]rs.UserTraitOption{rs.WithUserProfile(profile)},
		rs.WithParentResourceID(parentID),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create service account resource: %w", err)
	}

	return resource, nil
}

// Entitlements returns entitlements for ServiceAccount resources.
func (s *serviceAccountBuilder) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	// Add 'impersonate' entitlement
	impersonateEnt := entitlement.NewPermissionEntitlement(
		resource,
		"impersonate",
		entitlement.WithDisplayName(fmt.Sprintf("Impersonate %s", resource.DisplayName)),
		entitlement.WithDescription(fmt.Sprintf("Grants the ability to impersonate the %s service account", resource.DisplayName)),
		entitlement.WithGrantableTo(
			ResourceTypeRole,
			ResourceTypeClusterRole,
		),
	)

	return []*v2.Entitlement{impersonateEnt}, "", nil, nil
}

// Grants returns no grants for ServiceAccount resources.
func (s *serviceAccountBuilder) Grants(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

// newServiceAccountBuilder creates a new service account builder.
func newServiceAccountBuilder(client kubernetes.Interface) *serviceAccountBuilder {
	return &serviceAccountBuilder{
		client: client,
	}
}
