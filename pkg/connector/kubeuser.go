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
	client        kubernetes.Interface
	k8s           *Kubernetes
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
				if subject.Kind == SubjectKindUser {
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
				if subject.Kind == SubjectKindUser {
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

	// Phase 3: Discover cert-based users and accumulate group membership data.
	// No internal pagination loop: the SDK calls List() once per page via the bag token.
	// The accumulator is initialized on the first page and sealed on the last page.
	if phase == phaseSecrets {
		continueToken := bag.PageToken()
		opts := metav1.ListOptions{
			Limit:    ResourcesPageSize,
			Continue: continueToken,
		}

		// Initialize the accumulator if needed. This is not gated on the continue
		// token being empty: a resumed sync can enter Phase 3 mid-pagination in a
		// fresh process, where the accumulator has not been created yet.
		k.k8s.secretsMu.Lock()
		if k.k8s.secretsAccumulator == nil {
			k.k8s.secretsAccumulator = &secretsScanResult{
				GroupMembers: make(map[string][]string),
			}
		}
		k.k8s.secretsMu.Unlock()

		l.Debug("fetching secrets page", zap.String("continue_token", continueToken))
		resp, err := k.client.CoreV1().Secrets("").List(ctx, opts)
		if err != nil {
			// Phase 3 is a best-effort x509 discovery pass. Listing secrets
			// cluster-wide is a privilege many read-only service accounts
			// deliberately lack; that must not fail the mandatory user sync.
			// Seal whatever has been accumulated so kubeGroupBuilder.Grants
			// still has a (possibly empty) result to read.
			l.Warn("skipping cert-based user discovery: cannot list secrets", zap.Error(err))
			k.k8s.secretsMu.Lock()
			k.k8s.secretsResult = k.k8s.secretsAccumulator
			k.k8s.secretsAccumulator = nil
			k.k8s.secretsMu.Unlock()
			return rv, "", nil, nil
		}

		// certEntry holds parsed data from one kubeconfig auth entry.
		type certEntry struct {
			cn   string   // x509 CN; the principal identity
			orgs []string // x509 Organization fields (group names)
		}

		// Parse certs outside the lock (CPU-bound).
		var entries []certEntry
		for _, secret := range resp.Items {
			for _, data := range secret.Data {
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
						continue
					}
					cert := certs[0]
					cn := cert.Subject.CommonName
					if cn == "" {
						// The CN is the identity Kubernetes authenticates; a kubeconfig
						// auth-info key is an arbitrary local label, and using it as a
						// fallback would emit membership grants for a principal that is
						// never synced as a resource.
						l.Debug("skipping client certificate without CommonName", zap.String("auth_info", username))
						continue
					}
					entries = append(entries, certEntry{
						cn:   cn,
						orgs: cert.Subject.Organization,
					})
				}
			}
		}

		// Merge into the accumulator under the lock; collect new CNs to emit as user resources.
		var newCNs []string
		k.k8s.secretsMu.Lock()
		acc := k.k8s.secretsAccumulator
		for _, e := range entries {
			if !containsString(acc.Usernames, e.cn) {
				acc.Usernames = append(acc.Usernames, e.cn)
				newCNs = append(newCNs, e.cn)
			}
			for _, org := range e.orgs {
				if !containsString(acc.GroupMembers[org], e.cn) {
					acc.GroupMembers[org] = append(acc.GroupMembers[org], e.cn)
				}
			}
		}
		k.k8s.secretsMu.Unlock()

		// Emit user resources outside the lock (processUser uses its own userCacheLock
		// and handles deduplication against users already seen in Phases 1 and 2).
		for _, cn := range newCNs {
			k.processUser(ctx, cn, &rv)
		}

		if resp.Continue != "" {
			nextToken, err := marshalPhaseToken(phaseSecrets, resp.Continue)
			if err != nil {
				return nil, "", nil, err
			}
			return rv, nextToken, nil, nil
		}

		// Last page: seal the accumulator into the final read-only result.
		k.k8s.secretsMu.Lock()
		k.k8s.secretsResult = k.k8s.secretsAccumulator
		k.k8s.secretsAccumulator = nil
		k.k8s.secretsMu.Unlock()
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
		profileKeyName: username,
	}

	// Create resource with user trait options
	userOptions := []rs.UserTraitOption{
		rs.WithUserLogin(username),
	}

	// Create user resource
	resource, err := rs.NewUserResource(
		username,
		ResourceTypeKubeUser,
		username,
		userOptions,
		rs.WithResourceStatus(v2.Status_RESOURCE_STATUS_ENABLED, ""),
		rs.WithResourceProfile(profile),
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
func newKubeUserBuilder(client kubernetes.Interface, k8s *Kubernetes) *kubeUserBuilder {
	return &kubeUserBuilder{
		client:    client,
		k8s:       k8s,
		userCache: make(map[string]bool),
	}
}
