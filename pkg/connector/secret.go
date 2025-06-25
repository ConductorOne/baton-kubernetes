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
	"google.golang.org/protobuf/types/known/structpb"
)

// Standard verb entitlements for Kubernetes resources.
var standardResourceVerbs = []string{
	"get",
	"list",
	"watch",
	"create",
	"update",
	"patch",
	"delete",
}

// secretBuilder syncs Kubernetes Secrets as Baton resources.
type secretBuilder struct {
	client kubernetes.Interface
}

// ResourceType returns the resource type for Secret.
func (s *secretBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return ResourceTypeSecret
}

// List fetches all Secrets from the Kubernetes API.
func (s *secretBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
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
		wildcardResource, err := generateWildcardResource(ResourceTypeSecret)
		if err != nil {
			l.Error("failed to create wildcard resource for secrets", zap.Error(err))
		} else {
			rv = append(rv, wildcardResource)
		}
	}

	// Set up list options with pagination
	opts := metav1.ListOptions{
		Limit:    ResourcesPageSize,
		Continue: bag.PageToken(),
	}

	// Fetch secrets from the Kubernetes API across all namespaces
	l.Debug("fetching secrets", zap.String("continue_token", opts.Continue))
	resp, err := s.client.CoreV1().Secrets("").List(ctx, opts)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to list secrets: %w", err)
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
		return nil, "", nil, fmt.Errorf("failed to handle pagination: %w", err)
	}

	return rv, nextPageToken, nil, nil
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
		"name":              secret.Name,
		"namespace":         secret.Namespace,
		"uid":               string(secret.UID),
		"creationTimestamp": secret.CreationTimestamp.String(),
		"labels":            StringMapToAnyMap(secret.Labels),
		"annotations":       StringMapToAnyMap(secret.Annotations),
		"type":              string(secret.Type),
	}

	// Secret trait options
	secretOptions := []rs.SecretTraitOption{
		// Set creation time from metadata
		rs.WithSecretCreatedAt(secret.CreationTimestamp.Time),
		// Create a custom trait option for the profile
		func(t *v2.SecretTrait) error {
			profileStruct, err := structpb.NewStruct(profile)
			if err != nil {
				return err
			}
			t.Profile = profileStruct
			return nil
		},
	}

	// Resource options
	options := []rs.ResourceOption{
		rs.WithParentResourceID(parentID),
		rs.WithDescription(fmt.Sprintf("Secret of type %s in namespace %s", secret.Type, secret.Namespace)),
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
		secretOptions,
		options...,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create secret resource: %w", err)
	}

	return resource, nil
}

// Entitlements returns standard verb entitlements for Secret resources.
func (s *secretBuilder) Entitlements(ctx context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var entitlements []*v2.Entitlement

	// Add standard verb entitlements
	for _, verb := range standardResourceVerbs {
		ent := entitlement.NewPermissionEntitlement(
			resource,
			verb,
			entitlement.WithDisplayName(fmt.Sprintf("%s %s", verb, resource.DisplayName)),
			entitlement.WithDescription(fmt.Sprintf("Grants %s permission on the %s secret", verb, resource.DisplayName)),
			entitlement.WithGrantableTo(
				ResourceTypeRole,
				ResourceTypeClusterRole,
			),
		)
		entitlements = append(entitlements, ent)
	}

	return entitlements, "", nil, nil
}

// Grants returns no grants for Secret resources.
func (s *secretBuilder) Grants(ctx context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

// newSecretBuilder creates a new secret builder.
func newSecretBuilder(client kubernetes.Interface) *secretBuilder {
	return &secretBuilder{
		client: client,
	}
}
