package connector

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	"github.com/conductorone/baton-sdk/pkg/types/entitlement"
	"github.com/conductorone/baton-sdk/pkg/types/grant"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

// kubeGroupBuilder syncs Kubernetes groups referenced in RBAC bindings as Baton groups.
type kubeGroupBuilder struct {
	client kubernetes.Interface
	// Cache to avoid duplicate work when extracting groups from bindings
	groupCache     map[string]bool
	groupCacheLock sync.RWMutex
}

// ResourceType returns the resource type for KubeGroup.
func (k *kubeGroupBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return ResourceTypeKubeGroup
}

// List extracts unique groups from RBAC bindings and creates Baton group resources.
// It runs in two phases tracked via PageState.ResourceTypeID:
//
//	Phase "rolebindings"        – scan RoleBindings (default/first phase)
//	Phase "clusterrolebindings" – scan ClusterRoleBindings
//
// PageState.Token holds the Kubernetes API continue token within each phase.
func (k *kubeGroupBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	var rv []*v2.Resource

	// Initialize empty group cache if needed
	k.groupCacheLock.Lock()
	if k.groupCache == nil {
		k.groupCache = make(map[string]bool)
	}
	k.groupCacheLock.Unlock()

	// Always create built-in system groups on the first call.
	builtInGroups := []string{
		"system:masters",
		"system:authenticated",
		"system:unauthenticated",
	}
	for _, groupName := range builtInGroups {
		k.processGroup(ctx, groupName, &rv)
	}

	// Parse pagination token
	bag, err := ParsePageToken(pToken.Token)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to parse page token: %w", err)
	}

	// Determine current phase; default to rolebindings on first call (empty bag).
	phase := bag.ResourceTypeID()
	if phase == "" {
		phase = phaseRoleBindings
	}

	// Phase 1: Process RoleBindings
	if phase == phaseRoleBindings {
		opts := metav1.ListOptions{
			Limit:    ResourcesPageSize,
			Continue: bag.PageToken(),
		}

		l.Debug("fetching role bindings for groups", zap.String("continue_token", opts.Continue))
		resp, err := k.client.RbacV1().RoleBindings("").List(ctx, opts)
		if err != nil {
			return nil, "", nil, fmt.Errorf("failed to list role bindings: %w", err)
		}

		for _, binding := range resp.Items {
			for _, subject := range binding.Subjects {
				if subject.Kind == "Group" {
					k.processGroup(ctx, subject.Name, &rv)
				}
			}
		}

		if resp.Continue != "" {
			// More RoleBinding pages remain.
			nextToken, err := marshalPhaseToken(phaseRoleBindings, resp.Continue)
			if err != nil {
				return nil, "", nil, err
			}
			return rv, nextToken, nil, nil
		}

		// Phase 1 complete — advance to Phase 2.
		nextToken, err := marshalPhaseToken(phaseClusterRoleBindings, "")
		if err != nil {
			return nil, "", nil, err
		}
		return rv, nextToken, nil, nil
	}

	// Phase 2: Process ClusterRoleBindings
	if phase == phaseClusterRoleBindings {
		opts := metav1.ListOptions{
			Limit:    ResourcesPageSize,
			Continue: bag.PageToken(),
		}

		l.Debug("fetching cluster role bindings for groups", zap.String("continue_token", opts.Continue))
		resp, err := k.client.RbacV1().ClusterRoleBindings().List(ctx, opts)
		if err != nil {
			return nil, "", nil, fmt.Errorf("failed to list cluster role bindings: %w", err)
		}

		for _, binding := range resp.Items {
			for _, subject := range binding.Subjects {
				if subject.Kind == "Group" {
					k.processGroup(ctx, subject.Name, &rv)
				}
			}
		}

		if resp.Continue != "" {
			// More ClusterRoleBinding pages remain.
			nextToken, err := marshalPhaseToken(phaseClusterRoleBindings, resp.Continue)
			if err != nil {
				return nil, "", nil, err
			}
			return rv, nextToken, nil, nil
		}
	}

	// All phases complete.
	return rv, "", nil, nil
}

// processGroup adds a group to the list of resources if not already processed.
func (k *kubeGroupBuilder) processGroup(ctx context.Context, groupName string, resources *[]*v2.Resource) {
	l := ctxzap.Extract(ctx)

	// Check if we've already processed this group
	k.groupCacheLock.RLock()
	processed := k.groupCache[groupName]
	k.groupCacheLock.RUnlock()

	if processed {
		return
	}

	// Mark as processed
	k.groupCacheLock.Lock()
	k.groupCache[groupName] = true
	k.groupCacheLock.Unlock()

	// Create group resource
	resource, err := k.kubeGroupResource(groupName)
	if err != nil {
		l.Error("failed to create group resource", zap.String("name", groupName), zap.Error(err))
		return
	}

	*resources = append(*resources, resource)
}

// kubeGroupResource creates a Baton group resource for a Kubernetes group.
func (k *kubeGroupBuilder) kubeGroupResource(groupName string) (*v2.Resource, error) {
	// Create profile
	profile := map[string]interface{}{
		"name": groupName,
	}

	// Create resource with group trait options
	groupOptions := []rs.GroupTraitOption{
		rs.WithGroupProfile(profile),
	}

	// Create group resource
	resource, err := rs.NewGroupResource(
		groupName,
		ResourceTypeKubeGroup,
		groupName,
		groupOptions,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create group resource: %w", err)
	}

	return resource, nil
}

// Entitlements returns entitlements for Group resources.
func (k *kubeGroupBuilder) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	// 'member' assignment entitlement: links users to the group they belong to.
	// Grants are derived from x509 client certificate O= fields in kubeconfig Secrets.
	memberEnt := entitlement.NewAssignmentEntitlement(
		resource,
		"member",
		entitlement.WithDisplayName(fmt.Sprintf("Member of %s", resource.DisplayName)),
		entitlement.WithDescription(fmt.Sprintf("Membership in the %s Kubernetes group", resource.DisplayName)),
		entitlement.WithGrantableTo(
			ResourceTypeKubeUser,
			ResourceTypeServiceAccount,
		),
	)

	return []*v2.Entitlement{memberEnt}, "", nil, nil
}

// Grants returns grants for Group resources by inspecting x509 client certificates in kubeconfig Secrets.
// Group membership in Kubernetes is encoded in the O= (Organization) field of x509 client certificates.
// Note: OIDC and webhook-based group membership is out of scope.
func (k *kubeGroupBuilder) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	groupName := resource.Id.Resource

	// Parse pagination token
	bag, err := ParsePageToken(pToken.Token)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to parse page token: %w", err)
	}

	// Set up list options with pagination
	opts := metav1.ListOptions{
		Limit:    ResourcesPageSize,
		Continue: bag.PageToken(),
	}

	// Fetch secrets from the Kubernetes API across all namespaces
	l.Debug("fetching secrets for group grants", zap.String("group", groupName), zap.String("continue_token", opts.Continue))
	resp, err := k.client.CoreV1().Secrets("").List(ctx, opts)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	var grants []*v2.Grant

	// Process each secret, looking for kubeconfig data containing x509 client certificates
	for _, secret := range resp.Items {
		for dataKey, data := range secret.Data {
			// Try to parse the secret value as a kubeconfig
			kubecfg, err := clientcmd.Load(data)
			if err != nil {
				// Not a kubeconfig, skip
				continue
			}

			// For each user in the kubeconfig, check if their certificate includes this group
			for username, authInfo := range kubecfg.AuthInfos {
				if len(authInfo.ClientCertificateData) == 0 {
					continue
				}

				// Parse x509 certificates from PEM data
				certs, err := parseCertsFromPEM(authInfo.ClientCertificateData)
				if err != nil || len(certs) == 0 {
					l.Warn("failed to parse client certificate",
						zap.String("secret", secret.Namespace+"/"+secret.Name),
						zap.String("key", dataKey),
						zap.String("user", username),
						zap.Error(err))
					continue
				}

				// Use the leaf certificate to check organization membership
				cert := certs[0]
				for _, org := range cert.Subject.Organization {
					if org != groupName {
						continue
					}

					// Prefer the CN from the certificate as the Kubernetes username
					principalName := cert.Subject.CommonName
					if principalName == "" {
						principalName = username
					}

					principalResource := GenerateResourceForGrant(principalName, ResourceTypeKubeUser.Id)
					g := grant.NewGrant(resource, "member", principalResource)
					grants = append(grants, g)
					break // one grant per user per group
				}
			}
		}
	}

	// Handle pagination
	nextPageToken, err := HandleKubePagination(&resp.ListMeta, bag)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to handle pagination: %w", err)
	}

	return grants, nextPageToken, nil, nil
}

// parseCertsFromPEM parses x509 certificates from PEM-encoded data.
func parseCertsFromPEM(pemData []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for {
		block, rest := pem.Decode(pemData)
		if block == nil {
			break
		}
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse certificate: %w", err)
			}
			certs = append(certs, cert)
		}
		pemData = rest
	}
	return certs, nil
}

// newKubeGroupBuilder creates a new kube group builder.
func newKubeGroupBuilder(client kubernetes.Interface) *kubeGroupBuilder {
	return &kubeGroupBuilder{
		client:     client,
		groupCache: make(map[string]bool),
	}
}
