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

// nodeBuilder syncs Kubernetes Nodes as Baton resources.
type nodeBuilder struct {
	client kubernetes.Interface
	// perms resolves which roles confer this builder's objects' permissions.
	// Only grants need it: what a type declares is fixed (object_permissions.go).
	perms *permissionResolver
}

// ResourceType returns the resource type for Node.
func (n *nodeBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return ResourceTypeNode
}

// List fetches all Nodes from the Kubernetes API.
func (n *nodeBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, opts rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
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

	// Fetch nodes from the Kubernetes API
	l.Debug("fetching nodes", zap.String("continue_token", listOpts.Continue))
	resp, err := n.client.CoreV1().Nodes().List(ctx, listOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list nodes: %w", err)
	}

	// Process each node into a Baton resource
	for _, node := range resp.Items {
		resource, err := nodeResource(&node)
		if err != nil {
			l.Error("failed to create node resource",
				zap.String("name", node.Name),
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

// nodeResource creates a Baton resource from a Kubernetes Node.
func nodeResource(node *corev1.Node) (*v2.Resource, error) {
	// Create resource options with simplified description
	options := []rs.ResourceOption{
		rs.WithDescription("Kubernetes node"),
	}

	// Add external ID if available
	if len(node.UID) > 0 {
		options = append(options, rs.WithExternalID(&v2.ExternalId{Id: string(node.UID)}))
	}

	// Create resource
	resource, err := rs.NewResource(
		node.Name,
		ResourceTypeNode,
		node.Name,
		options...,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create node resource: %w", err)
	}

	return resource, nil
}

// StaticEntitlements declares what an object of this type can carry, once for
// the whole type rather than per object. The set is fixed and needs nothing from
// the cluster — see object_permissions.go for why it is a capability list rather
// than a reading of the rules.
func (n *nodeBuilder) StaticEntitlements(_ context.Context, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	return staticObjectEntitlements(ResourceTypeNode), nil, nil
}

// Entitlements returns none: the type carries SkipEntitlements and declares its
// entitlements through StaticEntitlements instead.
func (n *nodeBuilder) Entitlements(_ context.Context, _ *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

// Grants returns the roles conferring those named-object permissions, expandable
// through each one's membership entitlement so the subjects holding the role
// inherit the permission.
func (n *nodeBuilder) Grants(ctx context.Context, resource *v2.Resource, opts rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	grants, err := objectGrants(ctx, n.perms, opts, ResourceTypeNode, resource)
	if err != nil {
		return nil, nil, err
	}
	return grants, nil, nil
}

// newNodeBuilder creates a new node builder.
func newNodeBuilder(client kubernetes.Interface, perms *permissionResolver) *nodeBuilder {
	return &nodeBuilder{
		client: client,
		perms:  perms,
	}
}
