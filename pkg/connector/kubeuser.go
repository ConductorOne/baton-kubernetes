package connector

import (
	"context"
	"fmt"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
	"github.com/conductorone/baton-sdk/pkg/annotations"
	"github.com/conductorone/baton-sdk/pkg/pagination"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

// Phase IDs used in PageState.ResourceTypeID to track which listing phase we're in.
const (
	phaseRoleBindings        = "rolebindings"
	phaseClusterRoleBindings = "clusterrolebindings"
	phaseSecrets             = "secrets"
)

// kubeUserBuilder syncs Kubernetes users referenced in RBAC bindings and kubeconfig Secrets.
type kubeUserBuilder struct {
	client kubernetes.Interface
	// Cache to avoid duplicate work when extracting users from bindings
	userCache     map[string]bool
	userCacheLock sync.RWMutex
}

// ResourceType returns the resource type for KubeUser.
func (k *kubeUserBuilder) ResourceType(ctx context.Context) *v2.ResourceType {
	return ResourceTypeKubeUser
}

// List extracts unique users from RBAC bindings and kubeconfig Secrets, and creates Baton user resources.
// It runs in three phases tracked via PageState.ResourceTypeID:
//
//	Phase "rolebindings"        – scan RoleBindings (default/first phase)
//	Phase "clusterrolebindings" – scan ClusterRoleBindings
//	Phase "secrets"             – discover cert-based users from kubeconfig Secrets
//
// PageState.Token holds the Kubernetes API continue token within each phase.
func (k *kubeUserBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, pToken *pagination.Token) ([]*v2.Resource, string, annotations.Annotations, error) {
	l := ctxzap.Extract(ctx)
	var rv []*v2.Resource

	// Initialize empty user cache if needed
	k.userCacheLock.Lock()
	if k.userCache == nil {
		k.userCache = make(map[string]bool)
	}
	k.userCacheLock.Unlock()

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

		l.Debug("fetching role bindings for users", zap.String("continue_token", opts.Continue))
		resp, err := k.client.RbacV1().RoleBindings("").List(ctx, opts)
		if err != nil {
			return nil, "", nil, fmt.Errorf("failed to list role bindings: %w", err)
		}

		for _, binding := range resp.Items {
			for _, subject := range binding.Subjects {
				if subject.Kind == "User" {
					k.processUser(ctx, subject.Name, &rv)
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

		l.Debug("fetching cluster role bindings for users", zap.String("continue_token", opts.Continue))
		resp, err := k.client.RbacV1().ClusterRoleBindings().List(ctx, opts)
		if err != nil {
			return nil, "", nil, fmt.Errorf("failed to list cluster role bindings: %w", err)
		}

		for _, binding := range resp.Items {
			for _, subject := range binding.Subjects {
				if subject.Kind == "User" {
					k.processUser(ctx, subject.Name, &rv)
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

		// Phase 2 complete — advance to Phase 3.
		nextToken, err := marshalPhaseToken(phaseSecrets, "")
		if err != nil {
			return nil, "", nil, err
		}
		return rv, nextToken, nil, nil
	}

	// Phase 3: Discover users from x509 client certificates in kubeconfig Secrets.
	// This ensures cert-based users who appear in group member grants are synced as resources.
	if phase == phaseSecrets {
		opts := metav1.ListOptions{
			Limit:    ResourcesPageSize,
			Continue: bag.PageToken(),
		}

		l.Debug("fetching secrets to discover cert-based users", zap.String("continue_token", opts.Continue))
		resp, err := k.client.CoreV1().Secrets("").List(ctx, opts)
		if err != nil {
			return nil, "", nil, fmt.Errorf("failed to list secrets: %w", err)
		}

		for _, secret := range resp.Items {
			for _, data := range secret.Data {
				kubecfg, err := clientcmd.Load(data)
				if err != nil {
					continue
				}
				for _, authInfo := range kubecfg.AuthInfos {
					if len(authInfo.ClientCertificateData) == 0 {
						continue
					}
					certs, err := parseCertsFromPEM(authInfo.ClientCertificateData)
					if err != nil || len(certs) == 0 {
						continue
					}
					// Use the CN from the certificate as the Kubernetes username
					cn := certs[0].Subject.CommonName
					if cn != "" {
						k.processUser(ctx, cn, &rv)
					}
				}
			}
		}

		if resp.Continue != "" {
			nextToken, err := marshalPhaseToken(phaseSecrets, resp.Continue)
			if err != nil {
				return nil, "", nil, err
			}
			return rv, nextToken, nil, nil
		}
	}

	// All phases complete.
	return rv, "", nil, nil
}

// marshalPhaseToken creates a pagination token encoding the given phase and K8s continue token.
func marshalPhaseToken(phase, k8sContinue string) (string, error) {
	b := &pagination.Bag{}
	b.Push(pagination.PageState{
		ResourceTypeID: phase,
		Token:          k8sContinue,
	})
	token, err := b.Marshal()
	if err != nil {
		return "", fmt.Errorf("failed to marshal pagination bag: %w", err)
	}
	return token, nil
}

// processUser adds a user to the list of resources if not already processed.
func (k *kubeUserBuilder) processUser(ctx context.Context, username string, resources *[]*v2.Resource) {
	l := ctxzap.Extract(ctx)

	// Check if we've already processed this user
	k.userCacheLock.RLock()
	processed := k.userCache[username]
	k.userCacheLock.RUnlock()

	if processed {
		return
	}

	// Mark as processed
	k.userCacheLock.Lock()
	k.userCache[username] = true
	k.userCacheLock.Unlock()

	// Create user resource
	resource, err := k.kubeUserResource(username)
	if err != nil {
		l.Error("failed to create user resource", zap.String("name", username), zap.Error(err))
		return
	}

	*resources = append(*resources, resource)
}

// kubeUserResource creates a Baton user resource for a Kubernetes user.
func (k *kubeUserBuilder) kubeUserResource(username string) (*v2.Resource, error) {
	// Create profile
	profile := map[string]interface{}{
		"name": username,
	}

	// Create resource with user trait options
	userOptions := []rs.UserTraitOption{
		rs.WithStatus(v2.UserTrait_Status_STATUS_ENABLED),
		rs.WithUserProfile(profile),
		rs.WithUserLogin(username),
	}

	// Create user resource
	resource, err := rs.NewUserResource(
		username,
		ResourceTypeKubeUser,
		username,
		userOptions,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create user resource: %w", err)
	}

	return resource, nil
}

// Entitlements returns no entitlements for KubeUser resources.
// KubeUser is a principal type — users appear as grant targets on Roles, ClusterRoles,
// and KubeGroups, not as resources with their own entitlements.
func (k *kubeUserBuilder) Entitlements(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Entitlement, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

// Grants returns no grants for User resources.
func (k *kubeUserBuilder) Grants(_ context.Context, resource *v2.Resource, _ *pagination.Token) ([]*v2.Grant, string, annotations.Annotations, error) {
	return nil, "", nil, nil
}

// newKubeUserBuilder creates a new kube user builder.
func newKubeUserBuilder(client kubernetes.Interface) *kubeUserBuilder {
	return &kubeUserBuilder{
		client:    client,
		userCache: make(map[string]bool),
	}
}
