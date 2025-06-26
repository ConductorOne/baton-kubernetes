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

// deploymentBuilder syncs Kubernetes Deployments as Baton resources.
type deploymentBuilder struct {
	client kubernetes.Interface
}

// ResourceType returns the resource type for Deployment.
func (d *deploymentBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return ResourceTypeDeployment
}

// List fetches all Deployments from the Kubernetes API.
func (d *deploymentBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
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
		wildcardResource, err := generateWildcardResource(ResourceTypeDeployment)
		if err != nil {
			l.Error("failed to create wildcard resource for deployments", zap.Error(err))
		} else {
			rv = append(rv, wildcardResource)
		}
	}

	// Set up list options with pagination
	opts := metav1.ListOptions{
		Limit:    ResourcesPageSize,
		Continue: bag.PageToken(),
	}

	// Fetch deployments from the Kubernetes API across all namespaces
	l.Debug("fetching deployments", zap.String("continue_token", opts.Continue))
	resp, err := d.client.AppsV1().Deployments("").List(ctx, opts)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to list deployments: %w", err)
	}

	// Process each deployment into a Baton resource
	for _, deployment := range resp.Items {
		resource, err := deploymentResource(&deployment)
		if err != nil {
			l.Error("failed to create deployment resource",
				zap.String("namespace", deployment.Namespace),
				zap.String("name", deployment.Name),
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

// deploymentResource creates a Baton resource from a Kubernetes Deployment.
func deploymentResource(deployment *appsv1.Deployment) (*v2.Resource, error) {
	// Create resource ID for the deployment
	resourceID := deployment.Namespace + "/" + deployment.Name

	// Get parent namespace resource ID
	parentID, err := NamespaceResourceID(deployment.Namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to create parent resource ID: %w", err)
	}

	// Create resource options with simplified description
	options := []rs.ResourceOption{
		rs.WithParentResourceID(parentID),
		rs.WithDescription(fmt.Sprintf("Deployment in namespace %s", deployment.Namespace)),
	}

	// Add external ID if available
	if len(deployment.UID) > 0 {
		options = append(options, rs.WithExternalID(&v2.ExternalId{Id: string(deployment.UID)}))
	}

	// Create resource
	resource, err := rs.NewResource(
		deployment.Name,
		ResourceTypeDeployment,
		resourceID,
		options...,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create deployment resource: %w", err)
	}

	return resource, nil
}

// Entitlements returns standard verb entitlements for Deployment resources.
func (d *deploymentBuilder) Entitlements(ctx context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var entitlements []*v2.Entitlement

	// Add standard verb entitlements
	for _, verb := range standardResourceVerbs {
		ent := entitlement.NewPermissionEntitlement(
			resource,
			verb,
			entitlement.WithDisplayName(fmt.Sprintf("%s %s", verb, resource.DisplayName)),
			entitlement.WithDescription(fmt.Sprintf("Grants %s permission on the %s deployment", verb, resource.DisplayName)),
			entitlement.WithGrantableTo(
				ResourceTypeRole,
				ResourceTypeClusterRole,
			),
		)
		entitlements = append(entitlements, ent)
	}

	// Add deployment-specific entitlements
	deploymentSpecificVerbs := []string{
		"scale",
		"rollback",
	}

	for _, verb := range deploymentSpecificVerbs {
		ent := entitlement.NewPermissionEntitlement(
			resource,
			verb,
			entitlement.WithDisplayName(fmt.Sprintf("%s %s", verb, resource.DisplayName)),
			entitlement.WithDescription(fmt.Sprintf("Grants %s permission on the %s deployment", verb, resource.DisplayName)),
			entitlement.WithGrantableTo(
				ResourceTypeRole,
				ResourceTypeClusterRole,
			),
		)
		entitlements = append(entitlements, ent)
	}

	return entitlements, "", nil, nil
}

// Grants returns no grants for Deployment resources.
func (d *deploymentBuilder) Grants(ctx context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

// newDeploymentBuilder creates a new deployment builder.
func newDeploymentBuilder(client kubernetes.Interface) *deploymentBuilder {
	return &deploymentBuilder{
		client: client,
	}
}
