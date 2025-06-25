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

// daemonSetBuilder syncs Kubernetes DaemonSets as Baton resources.
type daemonSetBuilder struct {
	client kubernetes.Interface
}

// ResourceType returns the resource type for DaemonSet.
func (d *daemonSetBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return ResourceTypeDaemonSet
}

// List fetches all DaemonSets from the Kubernetes API.
func (d *daemonSetBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
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
		wildcardResource, err := generateWildcardResource(ResourceTypeDaemonSet)
		if err != nil {
			l.Error("failed to create wildcard resource for daemonsets", zap.Error(err))
		} else {
			rv = append(rv, wildcardResource)
		}
	}

	// Set up list options with pagination
	opts := metav1.ListOptions{
		Limit:    ResourcesPageSize,
		Continue: bag.PageToken(),
	}

	// Fetch daemonsets from the Kubernetes API across all namespaces
	l.Debug("fetching daemonsets", zap.String("continue_token", opts.Continue))
	resp, err := d.client.AppsV1().DaemonSets("").List(ctx, opts)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to list daemonsets: %w", err)
	}

	// Process each daemonset into a Baton resource
	for _, daemonset := range resp.Items {
		resource, err := daemonSetResource(&daemonset)
		if err != nil {
			l.Error("failed to create daemonset resource",
				zap.String("namespace", daemonset.Namespace),
				zap.String("name", daemonset.Name),
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

// daemonSetResource creates a Baton resource from a Kubernetes DaemonSet.
func daemonSetResource(daemonset *appsv1.DaemonSet) (*v2.Resource, error) {
	// Get parent namespace resource ID
	parentID, err := NamespaceResourceID(daemonset.Namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to create parent resource ID: %w", err)
	}

	// Create resource options with simplified description
	options := []rs.ResourceOption{
		rs.WithParentResourceID(parentID),
		rs.WithDescription(fmt.Sprintf("DaemonSet in namespace %s", daemonset.Namespace)),
	}

	// Add external ID if available
	if len(daemonset.UID) > 0 {
		options = append(options, rs.WithExternalID(&v2.ExternalId{Id: string(daemonset.UID)}))
	}

	// Create the raw ID as namespace/name
	rawID := daemonset.Namespace + "/" + daemonset.Name

	// Create resource
	resource, err := rs.NewResource(
		daemonset.Name,
		ResourceTypeDaemonSet,
		rawID, // Pass the raw ID directly
		options...,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create daemonset resource: %w", err)
	}

	return resource, nil
}

// Entitlements returns standard verb entitlements for DaemonSet resources.
func (d *daemonSetBuilder) Entitlements(ctx context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var entitlements []*v2.Entitlement

	// Add standard verb entitlements
	for _, verb := range standardResourceVerbs {
		ent := entitlement.NewPermissionEntitlement(
			resource,
			verb,
			entitlement.WithDisplayName(fmt.Sprintf("%s %s", verb, resource.DisplayName)),
			entitlement.WithDescription(fmt.Sprintf("Grants %s permission on the %s daemonset", verb, resource.DisplayName)),
			entitlement.WithGrantableTo(
				ResourceTypeRole,
				ResourceTypeClusterRole,
			),
		)
		entitlements = append(entitlements, ent)
	}

	return entitlements, "", nil, nil
}

// Grants returns no grants for DaemonSet resources.
func (d *daemonSetBuilder) Grants(ctx context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

// newDaemonSetBuilder creates a new daemonset builder.
func newDaemonSetBuilder(client kubernetes.Interface) *daemonSetBuilder {
	return &daemonSetBuilder{
		client: client,
	}
}
