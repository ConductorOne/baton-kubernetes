package connector

import (
	"context"
	"fmt"
	"sync"

	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/clientcmd"

	v2 "github.com/conductorone/baton-sdk/pb/c1/connector/v2"
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
	// userCache deduplicates principals across the pages of one sync. It is keyed
	// by sync ID: the SDK builds one syncer per connector and service mode reuses
	// that instance for every sync, so a cache that outlives its sync makes every
	// principal look already-processed and the next sync emits none of them.
	userCache      map[string]bool
	userCacheSync  string
	userCacheMutex sync.Mutex
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
func (k *kubeUserBuilder) List(ctx context.Context, parentResourceID *v2.ResourceId, opts rs.SyncOpAttrs) ([]*v2.Resource, *rs.SyncOpResults, error) {
	l := ctxzap.Extract(ctx)
	var rv []*v2.Resource

	k.resetUserCacheForSync(opts.SyncID)

	// Parse pagination token
	bag, err := ParsePageToken(opts.PageToken.Token)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse page token: %w", err)
	}

	// Determine current phase; default to rolebindings on first call (empty bag).
	phase := bag.ResourceTypeID()
	if phase == "" {
		phase = phaseRoleBindings
	}

	// Phase 1: Process RoleBindings
	if phase == phaseRoleBindings {
		listOpts := metav1.ListOptions{
			Limit:    ResourcesPageSize,
			Continue: bag.PageToken(),
		}

		l.Debug("fetching role bindings for users", zap.String("continue_token", listOpts.Continue))
		resp, err := k.client.RbacV1().RoleBindings("").List(ctx, listOpts)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to list role bindings: %w", err)
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
				return nil, nil, err
			}
			return rv, &rs.SyncOpResults{NextPageToken: nextToken}, nil
		}

		// Phase 1 complete — advance to Phase 2.
		nextToken, err := marshalPhaseToken(phaseClusterRoleBindings, "")
		if err != nil {
			return nil, nil, err
		}
		return rv, &rs.SyncOpResults{NextPageToken: nextToken}, nil
	}

	// Phase 2: Process ClusterRoleBindings
	if phase == phaseClusterRoleBindings {
		listOpts := metav1.ListOptions{
			Limit:    ResourcesPageSize,
			Continue: bag.PageToken(),
		}

		l.Debug("fetching cluster role bindings for users", zap.String("continue_token", listOpts.Continue))
		resp, err := k.client.RbacV1().ClusterRoleBindings().List(ctx, listOpts)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to list cluster role bindings: %w", err)
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
				return nil, nil, err
			}
			return rv, &rs.SyncOpResults{NextPageToken: nextToken}, nil
		}

		// Phase 2 complete — advance to Phase 3.
		nextToken, err := marshalPhaseToken(phaseSecrets, "")
		if err != nil {
			return nil, nil, err
		}
		return rv, &rs.SyncOpResults{NextPageToken: nextToken}, nil
	}

	// Phase 3: Discover cert-based users and accumulate group membership data.
	// No internal pagination loop: the SDK calls List() once per page via the bag
	// token. Each page merges into the scan held in this sync's session store, and
	// the last page seals it for kubeGroupBuilder.Grants.
	if phase == phaseSecrets {
		continueToken := bag.PageToken()
		listOpts := metav1.ListOptions{
			Limit:    ResourcesPageSize,
			Continue: continueToken,
		}

		// Load the running scan for this sync. It is absent on the first secrets
		// page, and also whenever a resumed sync re-enters Phase 3 mid-pagination
		// in a process that never ran the earlier pages.
		acc, ok := loadSecretsScan(ctx, opts.Session)
		if !ok {
			acc = newSecretsScanResult()
		}

		l.Debug("fetching secrets page", zap.String("continue_token", continueToken))
		resp, err := k.client.CoreV1().Secrets("").List(ctx, listOpts)
		if err != nil {
			// Phase 3 is a best-effort x509 discovery pass, and listing secrets
			// cluster-wide is a privilege many read-only service accounts
			// deliberately lack — that must not fail the mandatory user sync.
			// Any other failure (transient 5xx, network error) is real: returning
			// it avoids silently sealing an incomplete membership result.
			if !k8serrors.IsForbidden(err) && !k8serrors.IsUnauthorized(err) {
				return nil, nil, fmt.Errorf("failed to list secrets: %w", err)
			}
			// Seal whatever has been accumulated so kubeGroupBuilder.Grants
			// still has a (possibly empty) result to read.
			l.Debug("skipping cert-based user discovery: not permitted to list secrets", zap.Error(err))
			acc.Sealed = true
			storeSecretsScan(ctx, opts.Session, acc)
			return rv, nil, nil
		}

		// certEntry holds parsed data from one kubeconfig auth entry.
		type certEntry struct {
			cn   string   // x509 CN; the principal identity
			orgs []string // x509 Organization fields (group names)
		}

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

		// Merge this page into the running scan; collect new CNs to emit as user resources.
		var newCNs []string
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

		// processUser deduplicates against users already seen in Phases 1 and 2.
		for _, cn := range newCNs {
			k.processUser(ctx, cn, &rv)
		}

		// Seal on the last page. kubeGroupBuilder.Grants only reads a sealed scan,
		// so a partial one is never mistaken for complete membership data.
		acc.Sealed = resp.Continue == ""
		storeSecretsScan(ctx, opts.Session, acc)

		if resp.Continue != "" {
			nextToken, err := marshalPhaseToken(phaseSecrets, resp.Continue)
			if err != nil {
				return nil, nil, err
			}
			return rv, &rs.SyncOpResults{NextPageToken: nextToken}, nil
		}
	}

	// All phases complete.
	return rv, nil, nil
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

// resetUserCacheForSync discards the dedup cache when it belongs to an earlier
// sync, so a long-lived builder does not treat the previous sync's principals as
// already emitted.
func (k *kubeUserBuilder) resetUserCacheForSync(syncID string) {
	k.userCacheMutex.Lock()
	defer k.userCacheMutex.Unlock()
	if k.userCache == nil || k.userCacheSync != syncID {
		k.userCache = make(map[string]bool)
		k.userCacheSync = syncID
	}
}

// markUserProcessed records the username and reports whether this call was the
// first to see it. Test-and-set under one lock: separate read and write windows
// let two callers both observe "not processed" and emit the resource twice.
func (k *kubeUserBuilder) markUserProcessed(username string) bool {
	k.userCacheMutex.Lock()
	defer k.userCacheMutex.Unlock()
	if k.userCache == nil {
		k.userCache = make(map[string]bool)
	}
	if k.userCache[username] {
		return false
	}
	k.userCache[username] = true
	return true
}

// processUser adds a user to the list of resources if not already processed.
func (k *kubeUserBuilder) processUser(ctx context.Context, username string, resources *[]*v2.Resource) {
	l := ctxzap.Extract(ctx)

	if !k.markUserProcessed(username) {
		return
	}

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
func (k *kubeUserBuilder) Entitlements(_ context.Context, resource *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Entitlement, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

// Grants returns no grants for User resources.
func (k *kubeUserBuilder) Grants(_ context.Context, resource *v2.Resource, _ rs.SyncOpAttrs) ([]*v2.Grant, *rs.SyncOpResults, error) {
	return nil, nil, nil
}

// newKubeUserBuilder creates a new kube user builder.
func newKubeUserBuilder(client kubernetes.Interface) *kubeUserBuilder {
	return &kubeUserBuilder{
		client:    client,
		userCache: make(map[string]bool),
	}
}
