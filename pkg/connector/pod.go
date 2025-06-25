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

// podBuilder syncs Kubernetes Pods as Baton resources.
type podBuilder struct {
	client kubernetes.Interface
}

// ResourceType returns the resource type for Pod.
func (p *podBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return ResourceTypePod
}

// List fetches all Pods from the Kubernetes API.
func (p *podBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
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
		wildcardResource, err := generateWildcardResource(ResourceTypePod)
		if err != nil {
			l.Error("failed to create wildcard resource for pods", zap.Error(err))
		} else {
			rv = append(rv, wildcardResource)
		}
	}

	// Set up list options with pagination
	opts := metav1.ListOptions{
		Limit:    ResourcesPageSize,
		Continue: bag.PageToken(),
	}

	// Fetch pods from the Kubernetes API across all namespaces
	l.Debug("fetching pods", zap.String("continue_token", opts.Continue))
	resp, err := p.client.CoreV1().Pods("").List(ctx, opts)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to list pods: %w", err)
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
		return nil, "", nil, fmt.Errorf("failed to handle pagination: %w", err)
	}

	return rv, nextPageToken, nil, nil
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

// Entitlements returns standard verb entitlements for Pod resources.
func (p *podBuilder) Entitlements(ctx context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var entitlements []*v2.Entitlement

	// Add standard verb entitlements
	for _, verb := range standardResourceVerbs {
		ent := entitlement.NewPermissionEntitlement(
			resource,
			verb,
			entitlement.WithDisplayName(fmt.Sprintf("%s %s", verb, resource.DisplayName)),
			entitlement.WithDescription(fmt.Sprintf("Grants %s permission on the %s pod", verb, resource.DisplayName)),
			entitlement.WithGrantableTo(
				ResourceTypeRole,
				ResourceTypeClusterRole,
			),
		)
		entitlements = append(entitlements, ent)
	}

	// Add pod-specific entitlements
	execEntitlement := entitlement.NewPermissionEntitlement(
		resource,
		"exec",
		entitlement.WithDisplayName(fmt.Sprintf("exec %s", resource.DisplayName)),
		entitlement.WithDescription(fmt.Sprintf("Grants execution permission on the %s pod", resource.DisplayName)),
		entitlement.WithGrantableTo(
			ResourceTypeRole,
			ResourceTypeClusterRole,
		),
	)
	entitlements = append(entitlements, execEntitlement)

	portForwardEntitlement := entitlement.NewPermissionEntitlement(
		resource,
		"portforward",
		entitlement.WithDisplayName(fmt.Sprintf("port-forward %s", resource.DisplayName)),
		entitlement.WithDescription(fmt.Sprintf("Grants port-forward permission on the %s pod", resource.DisplayName)),
		entitlement.WithGrantableTo(
			ResourceTypeRole,
			ResourceTypeClusterRole,
		),
	)
	entitlements = append(entitlements, portForwardEntitlement)

	return entitlements, "", nil, nil
}

// Grants returns no grants for Pod resources.
func (p *podBuilder) Grants(ctx context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

// newPodBuilder creates a new pod builder.
func newPodBuilder(client kubernetes.Interface) *podBuilder {
	return &podBuilder{
		client: client,
	}
}
