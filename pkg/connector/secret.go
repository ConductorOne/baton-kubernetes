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

// secretBuilder syncs Kubernetes Secrets as Baton resources.
type secretBuilder struct {
	client kubernetes.Interface
	// perms resolves which roles confer this builder's objects' permissions.
	// Only grants need it: what a type declares is fixed (object_permissions.go).
	perms *permissionResolver
}

// ResourceType returns the resource type for Secret.
func (s *secretBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return ResourceTypeSecret
}

// List fetches all Secrets from the Kubernetes API.
func (s *secretBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, opts rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
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

	// Fetch secrets from the Kubernetes API across all namespaces
	l.Debug("fetching secrets", zap.String("continue_token", listOpts.Continue))
	resp, err := s.client.CoreV1().Secrets("").List(ctx, listOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	// Process each secret into a Baton resource
	for _, secret := range resp.Items {
		resource, err := secretResource(&secret)
		if err != nil {
			l.Error("failed to create secret resource",
				zap.String("namespace", secret.Namespace),
				zap.String("name", secret.Name),
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

// secretResource creates a Baton resource from a Kubernetes Secret.
func secretResource(secret *corev1.Secret) (*v2.Resource, error) {
	// Create resource ID for the secret
	resourceID := secret.Namespace + "/" + secret.Name

	// Get parent namespace resource ID
	parentID, err := NamespaceResourceID(secret.Namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to create parent resource ID: %w", err)
	}

	// Create profile with standard metadata
	profile := map[string]interface{}{
		profileKeyName:              secret.Name,
		profileKeyNamespace:         secret.Namespace,
		profileKeyUID:               string(secret.UID),
		profileKeyCreationTimestamp: FormatTimestamp(secret.CreationTimestamp),
		profileKeyLabels:            StringMapToAnyMap(secret.Labels),
		profileKeyAnnotations:       AnnotationsToAnyMap(secret.Annotations),
		"type":                      string(secret.Type),
	}

	// Resource options
	options := []rs.ResourceOption{
		rs.WithParentResourceID(parentID),
		rs.WithDescription(fmt.Sprintf("Secret of type %s in namespace %s", secret.Type, secret.Namespace)),
		rs.WithResourceCreatedAt(secret.CreationTimestamp.Time),
		rs.WithResourceProfile(profile),
	}

	// Add external ID if available
	if len(secret.UID) > 0 {
		options = append(options, rs.WithExternalID(&v2.ExternalId{Id: string(secret.UID)}))
	}

	// Create resource with secret trait
	resource, err := rs.NewSecretResource(
		secret.Name,
		ResourceTypeSecret,
		resourceID,
		nil,
		options...,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create secret resource: %w", err)
	}

	return resource, nil
}

// StaticEntitlements declares what an object of this type can carry, once for
// the whole type rather than per object. The set is fixed and needs nothing from
// the cluster — see object_permissions.go for why it is a capability list rather
// than a reading of the rules.
func (s *secretBuilder) StaticEntitlements(_ context.Context, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	return staticObjectEntitlements(ResourceTypeSecret), nil, nil
}

// Entitlements returns none: the type carries SkipEntitlements and declares its
// entitlements through StaticEntitlements instead.
func (s *secretBuilder) Entitlements(_ context.Context, _ *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

// Grants returns the roles conferring those named-object permissions, expandable
// through each one's membership entitlement so the subjects holding the role
// inherit the permission.
func (s *secretBuilder) Grants(ctx context.Context, resource *v2.Resource, opts rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	// objectGrants returns no grants alongside an error, so this needs no branch.
	grants, err := objectGrants(ctx, s.perms, opts, ResourceTypeSecret, resource)
	return grants, nil, err
}

// newSecretBuilder creates a new secret builder.
func newSecretBuilder(client kubernetes.Interface, perms *permissionResolver) *secretBuilder {
	return &secretBuilder{
		client: client,
		perms:  perms,
	}
}
