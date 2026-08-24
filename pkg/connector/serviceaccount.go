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

// serviceAccountBuilder syncs Kubernetes ServiceAccounts as Baton users.
type serviceAccountBuilder struct {
	client kubernetes.Interface
	// perms resolves which roles confer this builder's objects' permissions.
	// Only grants need it: what a type declares is fixed (object_permissions.go).
	perms *permissionResolver
}

// ResourceType returns the resource type for ServiceAccount.
func (s *serviceAccountBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return ResourceTypeServiceAccount
}

// List fetches all ServiceAccounts from the Kubernetes API.
func (s *serviceAccountBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, opts rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
	l := ctxzap.Extract(ctx)
	if parentResourceID == nil {
		return nil, nil, nil
	}
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

	// Fetch service accounts from the Kubernetes API for the parent namespace
	l.Debug("fetching service accounts", zap.String("continue_token", listOpts.Continue))
	parentNamespace := parentResourceID.Resource
	resp, err := s.client.CoreV1().ServiceAccounts(parentNamespace).List(ctx, listOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to list service accounts: %w", err)
	}

	// Process each service account into a Baton resource
	for _, sa := range resp.Items {
		resource, err := serviceAccountResource(&sa)
		if err != nil {
			l.Error("failed to create service account resource",
				zap.String("namespace", sa.Namespace),
				zap.String("name", sa.Name),
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

// serviceAccountResource creates a Baton resource from a Kubernetes ServiceAccount.
func serviceAccountResource(serviceAccount *corev1.ServiceAccount) (*v2.Resource, error) {
	// Prepare profile with standard metadata
	profile := map[string]interface{}{
		profileKeyName:              serviceAccount.Name,
		profileKeyNamespace:         serviceAccount.Namespace,
		profileKeyUID:               string(serviceAccount.UID),
		profileKeyCreationTimestamp: FormatTimestamp(serviceAccount.CreationTimestamp),
		profileKeyLabels:            StringMapToAnyMap(serviceAccount.Labels),
		profileKeyAnnotations:       AnnotationsToAnyMap(serviceAccount.Annotations),
	}

	// Add secrets if present
	if len(serviceAccount.Secrets) > 0 {
		secretNames := make([]string, 0, len(serviceAccount.Secrets))
		for _, secret := range serviceAccount.Secrets {
			secretNames = append(secretNames, secret.Name)
		}
		profile["secrets"] = secretNames
	}

	// Add image pull secrets if present
	if len(serviceAccount.ImagePullSecrets) > 0 {
		secretNames := make([]string, 0, len(serviceAccount.ImagePullSecrets))
		for _, secret := range serviceAccount.ImagePullSecrets {
			secretNames = append(secretNames, secret.Name)
		}
		profile["imagePullSecrets"] = secretNames
	}

	// Get parent namespace resource ID
	parentID, err := NamespaceResourceID(serviceAccount.Namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to create parent resource ID: %w", err)
	}

	// Unique ID is namespace/name
	rawID := serviceAccount.Namespace + "/" + serviceAccount.Name

	// Create resource with parent namespace
	resource, err := rs.NewUserResource(
		fmt.Sprintf("%s (%s)", serviceAccount.Name, serviceAccount.Namespace),
		ResourceTypeServiceAccount,
		rawID,
		[]rs.UserTraitOption{
			rs.WithAccountType(v2.UserTrait_ACCOUNT_TYPE_SERVICE),
		},
		rs.WithParentResourceID(parentID),
		rs.WithResourceProfile(profile),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create service account resource: %w", err)
	}

	return resource, nil
}

// StaticEntitlements declares what an object of this type can carry, once for
// the whole type rather than per object. The set is fixed and needs nothing from
// the cluster — see object_permissions.go for why it is a capability list rather
// than a reading of the rules.
func (s *serviceAccountBuilder) StaticEntitlements(_ context.Context, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	return staticObjectEntitlements(ResourceTypeServiceAccount), nil, nil
}

// Entitlements returns none: the type carries SkipEntitlements and declares its
// entitlements through StaticEntitlements instead.
func (s *serviceAccountBuilder) Entitlements(_ context.Context, _ *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

// Grants returns the roles conferring those named-object permissions, expandable
// through each one's membership entitlement so the subjects holding the role
// inherit the permission.
func (s *serviceAccountBuilder) Grants(ctx context.Context, resource *v2.Resource, opts rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	// objectGrants returns no grants alongside an error, so this needs no branch.
	grants, err := objectGrants(ctx, s.perms, opts, ResourceTypeServiceAccount, resource)
	return grants, nil, err
}

// newServiceAccountBuilder creates a new service account builder.
func newServiceAccountBuilder(client kubernetes.Interface, perms *permissionResolver) *serviceAccountBuilder {
	return &serviceAccountBuilder{
		client: client,
		perms:  perms,
	}
}
