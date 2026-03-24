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

const phasePreloadCache = "pre-load-cache"

// kubeGroupBuilder syncs Kubernetes groups referenced in RBAC bindings as Baton groups.
type kubeGroupBuilder struct {
	client kubernetes.Interface
	// Cache to avoid duplicate work when extracting groups from bindings
	groupCache     map[string]bool
	groupCacheLock sync.RWMutex
	// grantsAccumulator collects group→principals while paging through secrets.
	// grantsCache is nil until all secret pages have been scanned; once set it is never mutated.
	grantsAccumulator map[string][]string
	grantsCache       map[string][]string
	grantsCacheLock   sync.RWMutex
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

	// Emit built-in system groups only on the very first page to avoid redundant cache lookups.
	if phase == phaseRoleBindings && bag.PageToken() == "" {
		for _, groupName := range []string{
			"system:masters",
			"system:authenticated",
			"system:unauthenticated",
		} {
			k.processGroup(ctx, groupName, &rv)
		}
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
//
// Secret pages are scanned one at a time through the bag pagination mechanism using the
// phasePreloadCache phase. On the first call for any group the phase is pushed onto the bag and
// scanning begins. Each subsequent call fetches one more secrets page and accumulates a
// groupName → []principalName map for ALL groups simultaneously. Once the last page is reached
// the map is promoted to grantsCache and grants for the requested group are emitted. Every
// subsequent group skips scanning entirely and does a direct cache lookup.
func (k *kubeGroupBuilder) Grants(ctx context.Context, resource *v2.Resource, pToken *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)

	// Fast path: cache already fully built — skip scanning and emit grants directly.
	k.grantsCacheLock.RLock()
	cacheReady := k.grantsCache != nil
	k.grantsCacheLock.RUnlock()
	if cacheReady {
		return k.emitGrants(resource), "", nil, nil
	}

	bag, err := ParsePageToken(pToken.Token)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to parse page token: %w", err)
	}

	// First call for this group (empty bag): initialize the accumulator and start scanning.
	// Subsequent calls carry phasePreloadCache with the K8s continue token.
	if bag.ResourceTypeID() == "" {
		k.grantsCacheLock.Lock()
		k.grantsAccumulator = make(map[string][]string)
		k.grantsCacheLock.Unlock()
	}

	// Fetch one secrets page. On the first call the continue token is empty (first page);
	// on subsequent calls it is whatever K8s returned on the previous page.
	opts := metav1.ListOptions{
		Limit:    ResourcesPageSize,
		Continue: bag.PageToken(),
	}
	l.Debug("fetching secrets for grants cache", zap.String("continue_token", opts.Continue))
	resp, err := k.client.CoreV1().Secrets("").List(ctx, opts)
	if err != nil {
		return nil, "", nil, fmt.Errorf("failed to list secrets: %w", err)
	}

	// Parse secrets outside the lock — clientcmd.Load and certificate parsing are CPU-bound
	// and should not block other readers of the struct.
	pageResults := make(map[string][]string)
	for _, secret := range resp.Items {
		for dataKey, data := range secret.Data {
			kubecfg, err := clientcmd.Load(data)
			if err != nil {
				continue // not a kubeconfig
			}
			for username, authInfo := range kubecfg.AuthInfos {
				if len(authInfo.ClientCertificateData) == 0 {
					continue
				}
				certs, err := parseCertsFromPEM(authInfo.ClientCertificateData)
				if err != nil || len(certs) == 0 {
					l.Warn("failed to parse client certificate",
						zap.String("secret", secret.Namespace+"/"+secret.Name),
						zap.String("key", dataKey),
						zap.String("user", username),
						zap.Error(err))
					continue
				}
				cert := certs[0]
				principalName := cert.Subject.CommonName
				if principalName == "" {
					principalName = username
				}
				for _, org := range cert.Subject.Organization {
					pageResults[org] = append(pageResults[org], principalName)
				}
			}
		}
	}

	// Merge page results into the accumulator under the lock.
	k.grantsCacheLock.Lock()
	for org, principals := range pageResults {
		k.grantsAccumulator[org] = append(k.grantsAccumulator[org], principals...)
	}

	if resp.Continue != "" {
		// More secret pages remain — return next page token, no grants emitted yet.
		k.grantsCacheLock.Unlock()
		token, err := marshalPhaseToken(phasePreloadCache, resp.Continue)
		if err != nil {
			return nil, "", nil, err
		}
		return nil, token, nil, nil
	}

	// Last page: promote accumulator to cache.
	k.grantsCache = k.grantsAccumulator
	k.grantsAccumulator = nil
	k.grantsCacheLock.Unlock()

	return k.emitGrants(resource), "", nil, nil
}

// emitGrants builds the grant slice for resource from the completed grantsCache.
func (k *kubeGroupBuilder) emitGrants(resource *v2.Resource) []*v2.Grant {
	k.grantsCacheLock.RLock()
	principals := k.grantsCache[resource.Id.Resource]
	k.grantsCacheLock.RUnlock()
	grants := make([]*v2.Grant, 0, len(principals))
	for _, principalName := range principals {
		principalResource := GenerateResourceForGrant(principalName, ResourceTypeKubeUser.Id)
		grants = append(grants, grant.NewGrant(resource, "member", principalResource))
	}
	return grants
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
