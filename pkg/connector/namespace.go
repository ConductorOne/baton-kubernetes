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
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"

	"github.com/conductorone/baton-sdk/pkg/types/entitlement"
)

// namespaceBuilder syncs Kubernetes Namespaces as Baton resources
type namespaceBuilder struct {
	client kubernetes.Interface
}

// ResourceType returns the resource type for Namespace
func (n *namespaceBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return resourceTypeNamespace
}

// List fetches all Namespaces from the Kubernetes API
func (n *namespaceBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	// Initialize empty resource slice
	var rv []*v2.Resource

	// Parse pagination token
	bag, err := parsePageToken(pToken.Token)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to parse page token: %w", err)
	}

	// Add wildcard resource first, but only on the first page (when page token is empty)
	if bag.PageToken() == "" {
		wildcardResource, err := generateWildcardResource(resourceTypeNamespace)
		if err != nil {
			l.Error("failed to create wildcard resource for namespaces", zap.Error(err))
		} else {
			rv = append(rv, wildcardResource)
		}
	}

	// Set up list options with pagination
	opts := metav1.ListOptions{
		Limit:    ResourcesPageSize,
		Continue: bag.PageToken(),
	}

	// Fetch namespaces from the Kubernetes API
	l.Debug("fetching namespaces", zap.String("continue_token", opts.Continue))
	resp, err := n.client.CoreV1().Namespaces().List(ctx, opts)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to list namespaces: %w", err)
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
	nextPageToken, err := handleKubePagination(&resp.ListMeta, bag)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to handle pagination: %w", err)
	}

	return rv, nextPageToken, nil, nil
}

// namespaceResource creates a Baton resource from a Kubernetes Namespace
func namespaceResource(ns *corev1.Namespace) (*v2.Resource, error) {
	// Prepare profile with standard metadata
	profile := map[string]interface{}{
		"name":              ns.Name,
		"uid":               string(ns.UID),
		"creationTimestamp": ns.CreationTimestamp.String(),
		"labels":            StringMapToAnyMap(ns.Labels),
		"annotations":       StringMapToAnyMap(ns.Annotations),
	}

	// Add status phase if available
	if ns.Status.Phase != "" {
		profile["status.phase"] = string(ns.Status.Phase)
	}

	// Create resource with options
	options := []rs.ResourceOption{
		rs.WithAnnotation(&v2.ChildResourceType{ResourceTypeId: resourceTypeServiceAccount.Id}),
	}

	// Pass the raw name as the object ID
	resource, err := rs.NewResource(
		ns.Name,
		resourceTypeNamespace,
		ns.Name, // Just pass the raw name as the object ID
		options...,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	return resource, nil
}

// Entitlements defines the entitlements for namespace resources.
func (n *namespaceBuilder) Entitlements(ctx context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	var entitlements []*v2.Entitlement

	// Define entitlements for standard verbs applicable to Namespaces
	// For type-level permissions granted by Roles/ClusterRoles, we associate the entitlement
	// with the resource type, but NewPermissionEntitlement expects a *v2.Resource.
	// We use the `resource` passed in, assuming it represents a typical instance
	// or using the resource type ID if needed, though SDK functions handle this.
	// Baton core resolves these based on the target resource ID in the grant (`namespace:*`).

	getEnt := entitlement.NewPermissionEntitlement(resource, "get",
		entitlement.WithDisplayName(fmt.Sprintf("Get %s Namespace", resource.DisplayName)),
		entitlement.WithDescription(fmt.Sprintf("Allows reading the %s namespace", resource.DisplayName)),
		entitlement.WithGrantableTo(resourceTypeRole, resourceTypeClusterRole),
	)
	listEnt := entitlement.NewPermissionEntitlement(resource, "list",
		entitlement.WithDisplayName("List Namespaces"), // List is typically not per-resource
		entitlement.WithDescription("Allows listing namespaces"),
		entitlement.WithGrantableTo(resourceTypeRole, resourceTypeClusterRole),
	)
	watchEnt := entitlement.NewPermissionEntitlement(resource, "watch",
		entitlement.WithDisplayName("Watch Namespaces"), // Watch is typically not per-resource
		entitlement.WithDescription("Allows watching namespaces for changes"),
		entitlement.WithGrantableTo(resourceTypeRole, resourceTypeClusterRole),
	)
	createEnt := entitlement.NewPermissionEntitlement(resource, "create",
		entitlement.WithDisplayName("Create Namespace"),
		entitlement.WithDescription("Allows creating new namespaces"),
		entitlement.WithGrantableTo(resourceTypeRole, resourceTypeClusterRole),
	)
	updateEnt := entitlement.NewPermissionEntitlement(resource, "update",
		entitlement.WithDisplayName(fmt.Sprintf("Update %s Namespace", resource.DisplayName)),
		entitlement.WithDescription(fmt.Sprintf("Allows updating the %s namespace", resource.DisplayName)),
		entitlement.WithGrantableTo(resourceTypeRole, resourceTypeClusterRole),
	)
	patchEnt := entitlement.NewPermissionEntitlement(resource, "patch",
		entitlement.WithDisplayName(fmt.Sprintf("Patch %s Namespace", resource.DisplayName)),
		entitlement.WithDescription(fmt.Sprintf("Allows patching the %s namespace", resource.DisplayName)),
		entitlement.WithGrantableTo(resourceTypeRole, resourceTypeClusterRole),
	)
	deleteEnt := entitlement.NewPermissionEntitlement(resource, "delete",
		entitlement.WithDisplayName(fmt.Sprintf("Delete %s Namespace", resource.DisplayName)),
		entitlement.WithDescription(fmt.Sprintf("Allows deleting the %s namespace", resource.DisplayName)),
		entitlement.WithGrantableTo(resourceTypeRole, resourceTypeClusterRole),
	)

	entitlements = append(entitlements, getEnt, listEnt, watchEnt, createEnt, updateEnt, patchEnt, deleteEnt)

	// Add any other existing or specific entitlements for namespaces here...

	return entitlements, "", nil, nil
}

// Grants defines the grants for namespace resources.
func (n *namespaceBuilder) Grants(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

// newNamespaceBuilder creates a new namespace builder
func newNamespaceBuilder(client kubernetes.Interface) *namespaceBuilder {
	return &namespaceBuilder{
		client: client,
	}
}
