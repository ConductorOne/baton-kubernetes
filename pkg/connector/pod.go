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

// podBuilder syncs Kubernetes Pods as Baton resources.
type podBuilder struct {
	client kubernetes.Interface
	// perms resolves which roles confer this builder's objects' permissions.
	// Only grants need it: what a type declares is fixed (object_permissions.go).
	perms *permissionResolver
}

// ResourceType returns the resource type for Pod.
func (p *podBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return ResourceTypePod
}

// List fetches all Pods from the Kubernetes API.
func (p *podBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, opts rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
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

	// Fetch pods from the Kubernetes API across all namespaces
	l.Debug("fetching pods", zap.String("continue_token", listOpts.Continue))
	resp, err := p.client.CoreV1().Pods("").List(ctx, listOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list pods: %w", err)
	}

	// Process each pod into a Baton resource
	for _, pod := range resp.Items {
		resource, err := podResource(&pod)
		if err != nil {
			l.Error("failed to create pod resource",
				zap.String("namespace", pod.Namespace),
				zap.String("name", pod.Name),
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

// podResource creates a Baton resource from a Kubernetes Pod.
func podResource(pod *corev1.Pod) (*v2.Resource, error) {
	// Get parent namespace resource ID
	parentID, err := NamespaceResourceID(pod.Namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to create parent resource ID: %w", err)
	}

	// Create resource options with simplified description
	options := []rs.ResourceOption{
		rs.WithParentResourceID(parentID),
		rs.WithDescription(fmt.Sprintf("Pod in namespace %s", pod.Namespace)),
	}

	// Add external ID if available
	if len(pod.UID) > 0 {
		options = append(options, rs.WithExternalID(&v2.ExternalId{Id: string(pod.UID)}))
	}

	// Create the raw ID as namespace/name
	rawID := pod.Namespace + "/" + pod.Name

	// Create resource
	resource, err := rs.NewResource(
		pod.Name,
		ResourceTypePod,
		rawID, // Pass the raw ID directly
		options...,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create pod resource: %w", err)
	}

	return resource, nil
}

// StaticEntitlements declares what an object of this type can carry, once for
// the whole type rather than per object. The set is fixed and needs nothing from
// the cluster — see object_permissions.go for why it is a capability list rather
// than a reading of the rules.
func (p *podBuilder) StaticEntitlements(_ context.Context, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	return staticObjectEntitlements(ResourceTypePod), nil, nil
}

// Entitlements returns none: the type carries SkipEntitlements and declares its
// entitlements through StaticEntitlements instead.
func (p *podBuilder) Entitlements(_ context.Context, _ *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

// Grants returns the roles conferring those named-object permissions, expandable
// through each one's membership entitlement so the subjects holding the role
// inherit the permission.
func (p *podBuilder) Grants(ctx context.Context, resource *v2.Resource, opts rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	grants, err := objectGrants(ctx, p.perms, opts, ResourceTypePod, resource)
	if err != nil {
		return nil, nil, err
	}
	return grants, nil, nil
}

// newPodBuilder creates a new pod builder.
func newPodBuilder(client kubernetes.Interface, perms *permissionResolver) *podBuilder {
	return &podBuilder{
		client: client,
		perms:  perms,
	}
}
