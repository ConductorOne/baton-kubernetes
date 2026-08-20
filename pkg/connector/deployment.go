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

// deploymentBuilder syncs Kubernetes Deployments as Baton resources.
type deploymentBuilder struct {
	client kubernetes.Interface
	// perms resolves which roles confer this builder's objects' permissions.
	// Only grants need it: what a type declares is fixed (object_permissions.go).
	perms *permissionResolver
}

// ResourceType returns the resource type for Deployment.
func (d *deploymentBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return ResourceTypeDeployment
}

// List fetches all Deployments from the Kubernetes API.
func (d *deploymentBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, opts rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
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

	// Fetch deployments from the Kubernetes API across all namespaces
	l.Debug("fetching deployments", zap.String("continue_token", listOpts.Continue))
	resp, err := d.client.AppsV1().Deployments("").List(ctx, listOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list deployments: %w", err)
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
		return nil, nil, fmt.Errorf("failed to handle pagination: %w", err)
	}

	return rv, &rs.SyncOpResults{NextPageToken: nextPageToken}, nil
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

// StaticEntitlements declares what an object of this type can carry, once for
// the whole type rather than per object. The set is fixed and needs nothing from
// the cluster — see object_permissions.go for why it is a capability list rather
// than a reading of the rules.
func (d *deploymentBuilder) StaticEntitlements(_ context.Context, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	return staticObjectEntitlements(ResourceTypeDeployment), nil, nil
}

// Entitlements returns none: the type carries SkipEntitlements and declares its
// entitlements through StaticEntitlements instead.
func (d *deploymentBuilder) Entitlements(_ context.Context, _ *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

// Grants returns the roles conferring those named-object permissions, expandable
// through each one's membership entitlement so the subjects holding the role
// inherit the permission.
func (d *deploymentBuilder) Grants(ctx context.Context, resource *v2.Resource, opts rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	grants, err := objectGrants(ctx, d.perms, opts, ResourceTypeDeployment, resource)
	if err != nil {
		return nil, nil, err
	}
	return grants, nil, nil
}

// newDeploymentBuilder creates a new deployment builder.
func newDeploymentBuilder(client kubernetes.Interface, perms *permissionResolver) *deploymentBuilder {
	return &deploymentBuilder{
		client: client,
		perms:  perms,
	}
}
