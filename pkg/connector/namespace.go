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

// namespaceBuilder syncs Kubernetes Namespaces as Baton resources.
type namespaceBuilder struct {
	client kubernetes.Interface
	// perms resolves which roles confer this builder's objects' permissions.
	// Only grants need it: what a type declares is fixed (object_permissions.go).
	perms *permissionResolver
}

// ResourceType returns the resource type for Namespace.
func (n *namespaceBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return ResourceTypeNamespace
}

// List fetches all Namespaces from the Kubernetes API.
func (n *namespaceBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, opts rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
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

	// Fetch namespaces from the Kubernetes API
	l.Debug("fetching namespaces", zap.String("continue_token", listOpts.Continue))
	resp, err := n.client.CoreV1().Namespaces().List(ctx, listOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list namespaces: %w", err)
	}

	// Process each namespace into a Baton resource
	for _, ns := range resp.Items {
		resource, err := namespaceResource(&ns)
		if err != nil {
			l.Error("failed to create namespace resource", zap.String("namespace", ns.Name), zap.Error(err))
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

// namespaceResource creates a Baton resource from a Kubernetes Namespace.
func namespaceResource(ns *corev1.Namespace) (*v2.Resource, error) {
	// Prepare profile with standard metadata
	profile := map[string]interface{}{
		profileKeyName:              ns.Name,
		profileKeyUID:               string(ns.UID),
		profileKeyCreationTimestamp: FormatTimestamp(ns.CreationTimestamp),
		profileKeyLabels:            StringMapToAnyMap(ns.Labels),
		profileKeyAnnotations:       AnnotationsToAnyMap(ns.Annotations),
	}

	// Add status phase if available
	if ns.Status.Phase != "" {
		profile["status.phase"] = string(ns.Status.Phase)
	}

	// Create resource with options
	options := []rs.ResourceOption{
		rs.WithAnnotation(&v2.ChildResourceType{ResourceTypeId: ResourceTypeServiceAccount.Id}),
	}

	// Pass the raw name as the object ID
	resource, err := rs.NewResource(
		ns.Name,
		ResourceTypeNamespace,
		ns.Name, // Just pass the raw name as the object ID
		options...,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	return resource, nil
}

// StaticEntitlements declares what an object of this type can carry, once for
// the whole type rather than per object. The set is fixed and needs nothing from
// the cluster — see object_permissions.go for why it is a capability list rather
// than a reading of the rules.
func (n *namespaceBuilder) StaticEntitlements(_ context.Context, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	return staticObjectEntitlements(ResourceTypeNamespace), nil, nil
}

// Entitlements returns none: the type carries SkipEntitlements and declares its
// entitlements through StaticEntitlements instead.
func (n *namespaceBuilder) Entitlements(_ context.Context, _ *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

// Grants returns the roles conferring those named-object permissions, expandable
// through each one's membership entitlement so the subjects holding the role
// inherit the permission.
func (n *namespaceBuilder) Grants(ctx context.Context, resource *v2.Resource, opts rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	grants, err := objectGrants(ctx, n.perms, opts, ResourceTypeNamespace, resource)
	if err != nil {
		return nil, nil, err
	}
	return grants, nil, nil
}

// newNamespaceBuilder creates a new namespace builder.
func newNamespaceBuilder(client kubernetes.Interface, perms *permissionResolver) *namespaceBuilder {
	return &namespaceBuilder{
		client: client,
		perms:  perms,
	}
}
