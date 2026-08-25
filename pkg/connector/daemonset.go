package connector

import (
	"context"
	"fmt"

	appsv1 "k8s.io/api/apps/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

// daemonSetBuilder syncs Kubernetes DaemonSets as Baton resources.
type daemonSetBuilder struct {
	client kubernetes.Interface
	// perms resolves which roles confer this builder's objects' permissions.
	// Only grants need it: what a type declares is fixed (object_permissions.go).
	perms *permissionResolver
}

// ResourceType returns the resource type for DaemonSet.
func (d *daemonSetBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return ResourceTypeDaemonSet
}

// List fetches all DaemonSets from the Kubernetes API.
func (d *daemonSetBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, opts rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
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

	// Fetch daemonsets from the Kubernetes API across all namespaces
	l.Debug("fetching daemonsets", zap.String("continue_token", listOpts.Continue))
	resp, err := d.client.AppsV1().DaemonSets("").List(ctx, listOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list daemonsets: %w", err)
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
		return nil, nil, fmt.Errorf("failed to handle pagination: %w", err)
	}

	return rv, &rs.SyncOpResults{NextPageToken: nextPageToken}, nil
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

// StaticEntitlements declares what an object of this type can carry, once for
// the whole type rather than per object. The set is fixed and needs nothing from
// the cluster — see object_permissions.go for why it is a capability list rather
// than a reading of the rules.
func (d *daemonSetBuilder) StaticEntitlements(_ context.Context, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	return staticObjectEntitlements(ResourceTypeDaemonSet), nil, nil
}

// Entitlements returns none: the type carries SkipEntitlements and declares its
// entitlements through StaticEntitlements instead.
func (d *daemonSetBuilder) Entitlements(_ context.Context, _ *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

// Grants returns the roles conferring those named-object permissions, expandable
// through each one's membership entitlement so the subjects holding the role
// inherit the permission.
func (d *daemonSetBuilder) Grants(ctx context.Context, resource *v2.Resource, opts rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	// objectGrants returns no grants alongside an error, so this needs no branch.
	grants, err := objectGrants(ctx, d.perms, opts, ResourceTypeDaemonSet, resource)
	return grants, nil, err
}

// newDaemonSetBuilder creates a new daemonset builder.
func newDaemonSetBuilder(client kubernetes.Interface, perms *permissionResolver) *daemonSetBuilder {
	return &daemonSetBuilder{
		client: client,
		perms:  perms,
	}
}
