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

// configMapBuilder syncs Kubernetes ConfigMaps as Baton resources.
type configMapBuilder struct {
	client kubernetes.Interface
}

// ResourceType returns the resource type for ConfigMap.
func (c *configMapBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return ResourceTypeConfigMap
}

// List fetches all ConfigMaps from the Kubernetes API.
func (c *configMapBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
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
		wildcardResource, err := generateWildcardResource(ResourceTypeConfigMap)
		if err != nil {
			l.Error("failed to create wildcard resource for configmaps", zap.Error(err))
		} else {
			rv = append(rv, wildcardResource)
		}
	}

	// Set up list options with pagination
	opts := metav1.ListOptions{
		Limit:    ResourcesPageSize,
		Continue: bag.PageToken(),
	}

	// Fetch configmaps from the Kubernetes API across all namespaces
	l.Debug("fetching configmaps", zap.String("continue_token", opts.Continue))
	resp, err := c.client.CoreV1().ConfigMaps("").List(ctx, opts)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to list configmaps: %w", err)
	}

	// Process each configmap into a Baton resource
	for _, cm := range resp.Items {
		resource, err := configMapResource(&cm)
		if err != nil {
			l.Error("failed to create configmap resource",
				zap.String("namespace", cm.Namespace),
				zap.String("name", cm.Name),
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

// configMapResource creates a Baton resource from a Kubernetes ConfigMap.
func configMapResource(cm *corev1.ConfigMap) (*v2.Resource, error) {
	// Get parent namespace resource ID
	parentID, err := NamespaceResourceID(cm.Namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to create parent resource ID: %w", err)
	}

	// Create resource options with simplified description
	options := []rs.ResourceOption{
		rs.WithParentResourceID(parentID),
		rs.WithDescription(fmt.Sprintf("ConfigMap in namespace %s", cm.Namespace)),
	}

	// Add external ID if available
	if len(cm.UID) > 0 {
		options = append(options, rs.WithExternalID(&v2.ExternalId{Id: string(cm.UID)}))
	}

	// Create the raw ID as namespace/name
	rawID := cm.Namespace + "/" + cm.Name

	// Create resource
	resource, err := rs.NewResource(
		cm.Name,
		ResourceTypeConfigMap,
		rawID, // Pass the raw ID directly
		options...,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create configmap resource: %w", err)
	}

	return resource, nil
}

// Entitlements returns standard verb entitlements for ConfigMap resources.
func (c *configMapBuilder) Entitlements(ctx context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var entitlements []*v2.Entitlement

	// Add standard verb entitlements
	for _, verb := range standardResourceVerbs {
		ent := entitlement.NewPermissionEntitlement(
			resource,
			verb,
			entitlement.WithDisplayName(fmt.Sprintf("%s %s", verb, resource.DisplayName)),
			entitlement.WithDescription(fmt.Sprintf("Grants %s permission on the %s configmap", verb, resource.DisplayName)),
			entitlement.WithGrantableTo(
				ResourceTypeRole,
				ResourceTypeClusterRole,
			),
		)
		entitlements = append(entitlements, ent)
	}

	return entitlements, "", nil, nil
}

// Grants returns no grants for ConfigMap resources.
func (c *configMapBuilder) Grants(ctx context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

// newConfigMapBuilder creates a new configmap builder.
func newConfigMapBuilder(client kubernetes.Interface) *configMapBuilder {
	return &configMapBuilder{
		client: client,
	}
}
