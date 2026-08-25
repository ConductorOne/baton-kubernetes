package connector

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

// configMapBuilder syncs Kubernetes ConfigMaps as Baton resources.
type configMapBuilder struct {
	client kubernetes.Interface
	// perms resolves which roles confer this builder's objects' permissions.
	// Only grants need it: what a type declares is fixed (object_permissions.go).
	perms *permissionResolver
}

// ResourceType returns the resource type for ConfigMap.
func (c *configMapBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return ResourceTypeConfigMap
}

// List fetches all ConfigMaps from the Kubernetes API.
func (c *configMapBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, opts rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
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

	// Fetch configmaps from the Kubernetes API across all namespaces
	l.Debug("fetching configmaps", zap.String("continue_token", listOpts.Continue))
	resp, err := c.client.CoreV1().ConfigMaps("").List(ctx, listOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list configmaps: %w", err)
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
		return nil, nil, fmt.Errorf("failed to handle pagination: %w", err)
	}

	return rv, &rs.SyncOpResults{NextPageToken: nextPageToken}, nil
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

// StaticEntitlements declares what an object of this type can carry, once for
// the whole type rather than per object. The set is fixed and needs nothing from
// the cluster — see object_permissions.go for why it is a capability list rather
// than a reading of the rules.
func (c *configMapBuilder) StaticEntitlements(_ context.Context, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	return staticObjectEntitlements(ResourceTypeConfigMap), nil, nil
}

// Entitlements returns none: the type carries SkipEntitlements and declares its
// entitlements through StaticEntitlements instead.
func (c *configMapBuilder) Entitlements(_ context.Context, _ *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

// Grants returns the roles conferring those named-object permissions, expandable
// through each one's membership entitlement so the subjects holding the role
// inherit the permission.
func (c *configMapBuilder) Grants(ctx context.Context, resource *v2.Resource, opts rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	// objectGrants returns no grants alongside an error, so this needs no branch.
	grants, err := objectGrants(ctx, c.perms, opts, ResourceTypeConfigMap, resource)
	return grants, nil, err
}

// newConfigMapBuilder creates a new configmap builder.
func newConfigMapBuilder(client kubernetes.Interface, perms *permissionResolver) *configMapBuilder {
	return &configMapBuilder{
		client: client,
		perms:  perms,
	}
}
