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

// nodeBuilder syncs Kubernetes Nodes as Baton resources.
type nodeBuilder struct {
	client kubernetes.Interface
}

// ResourceType returns the resource type for Node.
func (n *nodeBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return ResourceTypeNode
}

// List fetches all Nodes from the Kubernetes API.
func (n *nodeBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
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
		wildcardResource, err := generateWildcardResource(ResourceTypeNode)
		if err != nil {
			l.Error("failed to create wildcard resource for nodes", zap.Error(err))
		} else {
			rv = append(rv, wildcardResource)
		}
	}

	// Set up list options with pagination
	opts := metav1.ListOptions{
		Limit:    ResourcesPageSize,
		Continue: bag.PageToken(),
	}

	// Fetch nodes from the Kubernetes API
	l.Debug("fetching nodes", zap.String("continue_token", opts.Continue))
	resp, err := n.client.CoreV1().Nodes().List(ctx, opts)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to list nodes: %w", err)
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
		return nil, "", nil, fmt.Errorf("failed to handle pagination: %w", err)
	}

	return rv, nextPageToken, nil, nil
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

// Entitlements returns standard verb entitlements for Node resources.
func (n *nodeBuilder) Entitlements(ctx context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var entitlements []*v2.Entitlement

	// Add standard verb entitlements
	for _, verb := range standardResourceVerbs {
		ent := entitlement.NewPermissionEntitlement(
			resource,
			verb,
			entitlement.WithDisplayName(fmt.Sprintf("%s %s", verb, resource.DisplayName)),
			entitlement.WithDescription(fmt.Sprintf("Grants %s permission on the %s node", verb, resource.DisplayName)),
			entitlement.WithGrantableTo(
				ResourceTypeRole,
				ResourceTypeClusterRole,
			),
		)
		entitlements = append(entitlements, ent)
	}

	return entitlements, "", nil, nil
}

// Grants returns no grants for Node resources.
func (n *nodeBuilder) Grants(ctx context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

// newNodeBuilder creates a new node builder.
func newNodeBuilder(client kubernetes.Interface) *nodeBuilder {
	return &nodeBuilder{
		client: client,
	}
}
