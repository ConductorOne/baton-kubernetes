package connector

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
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

// statefulSetBuilder syncs Kubernetes StatefulSets as Baton resources.
type statefulSetBuilder struct {
	client kubernetes.Interface
}

// ResourceType returns the resource type for StatefulSet.
func (s *statefulSetBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return ResourceTypeStatefulSet
}

// List fetches all StatefulSets from the Kubernetes API.
func (s *statefulSetBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
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
		wildcardResource, err := generateWildcardResource(ResourceTypeStatefulSet)
		if err != nil {
			l.Error("failed to create wildcard resource for statefulsets", zap.Error(err))
		} else {
			rv = append(rv, wildcardResource)
		}
	}

	// Set up list options with pagination
	opts := metav1.ListOptions{
		Limit:    ResourcesPageSize,
		Continue: bag.PageToken(),
	}

	// Fetch statefulsets from the Kubernetes API across all namespaces
	l.Debug("fetching statefulsets", zap.String("continue_token", opts.Continue))
	resp, err := s.client.AppsV1().StatefulSets("").List(ctx, opts)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to list statefulsets: %w", err)
	}

	// Process each statefulset into a Baton resource
	for _, statefulset := range resp.Items {
		resource, err := statefulSetResource(&statefulset)
		if err != nil {
			l.Error("failed to create statefulset resource",
				zap.String("namespace", statefulset.Namespace),
				zap.String("name", statefulset.Name),
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

// statefulSetResource creates a Baton resource from a Kubernetes StatefulSet.
func statefulSetResource(statefulset *appsv1.StatefulSet) (*v2.Resource, error) {
	// Get parent namespace resource ID
	parentID, err := NamespaceResourceID(statefulset.Namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to create parent resource ID: %w", err)
	}

	// Create resource options with simplified description
	options := []rs.ResourceOption{
		rs.WithParentResourceID(parentID),
		rs.WithDescription(fmt.Sprintf("StatefulSet in namespace %s", statefulset.Namespace)),
	}

	// Add external ID if available
	if len(statefulset.UID) > 0 {
		options = append(options, rs.WithExternalID(&v2.ExternalId{Id: string(statefulset.UID)}))
	}

	// Create the raw ID as namespace/name
	rawID := statefulset.Namespace + "/" + statefulset.Name

	// Create resource
	resource, err := rs.NewResource(
		statefulset.Name,
		ResourceTypeStatefulSet,
		rawID, // Pass the raw ID directly
		options...,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create statefulset resource: %w", err)
	}

	return resource, nil
}

// Entitlements returns standard verb entitlements for StatefulSet resources.
func (s *statefulSetBuilder) Entitlements(ctx context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var entitlements []*v2.Entitlement

	// Add standard verb entitlements
	for _, verb := range standardResourceVerbs {
		ent := entitlement.NewPermissionEntitlement(
			resource,
			verb,
			entitlement.WithDisplayName(fmt.Sprintf("%s %s", verb, resource.DisplayName)),
			entitlement.WithDescription(fmt.Sprintf("Grants %s permission on the %s statefulset", verb, resource.DisplayName)),
			entitlement.WithGrantableTo(
				ResourceTypeRole,
				ResourceTypeClusterRole,
			),
		)
		entitlements = append(entitlements, ent)
	}

	// Add statefulset-specific entitlements
	statefulSetSpecificVerbs := []string{
		"scale",
	}

	for _, verb := range statefulSetSpecificVerbs {
		ent := entitlement.NewPermissionEntitlement(
			resource,
			verb,
			entitlement.WithDisplayName(fmt.Sprintf("%s %s", verb, resource.DisplayName)),
			entitlement.WithDescription(fmt.Sprintf("Grants %s permission on the %s statefulset", verb, resource.DisplayName)),
			entitlement.WithGrantableTo(
				ResourceTypeRole,
				ResourceTypeClusterRole,
			),
		)
		entitlements = append(entitlements, ent)
	}

	return entitlements, "", nil, nil
}

// Grants returns no grants for StatefulSet resources.
func (s *statefulSetBuilder) Grants(ctx context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

// newStatefulSetBuilder creates a new statefulset builder.
func newStatefulSetBuilder(client kubernetes.Interface) *statefulSetBuilder {
	return &statefulSetBuilder{
		client: client,
	}
}
