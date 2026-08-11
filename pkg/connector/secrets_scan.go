package connector

import (
	"context"

	"github.com/conductorone/baton-sdk/pkg/session"
	"github.com/conductorone/baton-sdk/pkg/types/sessions"
	"github.com/grpc-ecosystem/go-grpc-middleware/logging/zap/ctxzap"
	"go.uber.org/zap"
)

// secretsScanKey is the session-store key holding the x509 scan for one sync.
// The store handed to a resource syncer is already scoped by sync ID, so a bare
// key cannot collide across syncs.
const secretsScanKey = "x509-secrets-scan" //nolint:gosec // session-store key naming the scan, not a credential

// secretsScanPrefix namespaces the key within the sync's session store.
const secretsScanPrefix = "kubernetes"

// secretsScanResult is the x509 discovery pass produced by kubeUserBuilder.List()
// Phase 3 and consumed by kubeGroupBuilder.Grants().
//
// It lives in the session store rather than on the connector struct because the
// two builders run in different sync phases: a sync resumed in a fresh process
// would otherwise reach the grants phase with nothing accumulated and silently
// emit zero group-membership grants.
type secretsScanResult struct {
	// Usernames holds deduplicated x509 CommonNames. Only non-empty CNs are
	// included.
	Usernames []string `json:"usernames"`
	// GroupMembers maps a Kubernetes group name (the x509 Organization field) to
	// the CommonNames that carry it.
	GroupMembers map[string][]string `json:"groupMembers"`
	// Sealed marks the scan complete. kubeGroupBuilder.Grants only trusts a
	// sealed result: a partial one would under-report membership as fact.
	Sealed bool `json:"sealed"`
}

func newSecretsScanResult() *secretsScanResult {
	return &secretsScanResult{GroupMembers: make(map[string][]string)}
}

// withUsableStore runs fn against the session store, turning both errors and
// panics into a plain false.
//
// The panic recovery is load-bearing, not paranoia. A syncer is always handed a
// non-nil store: the SDK wraps whatever it has in connectorbuilder.WithSyncId,
// which returns a *SessionStoreWithSyncID even when the store inside it is nil.
// That is exactly what an embedder gets from connectorbuilder.NewConnector
// without WithSessionStore — the shape baton-eks, baton-aks and baton-gke build
// today — and calling through the wrapper then dereferences the nil inner store.
// A nil check on the wrapper cannot see that, so without recovering here the
// x509 pass would take down an otherwise healthy sync in every embedder.
//
// Errors are swallowed for the same reason: this pass is best-effort discovery,
// and losing group membership is the correct degradation.
func withUsableStore(ctx context.Context, store sessions.SessionStore, what string, fn func() error) bool {
	if store == nil {
		return false
	}

	failed := false
	func() {
		defer func() {
			if r := recover(); r != nil {
				ctxzap.Extract(ctx).Debug("x509 scan skipped: session store unusable",
					zap.String("operation", what), zap.Any("recovered", r))
				failed = true
			}
		}()
		if err := fn(); err != nil {
			ctxzap.Extract(ctx).Debug("x509 scan skipped: session store failed",
				zap.String("operation", what), zap.Error(err))
			failed = true
		}
	}()

	return !failed
}

// loadSecretsScan reads this sync's scan. A missing key, an unusable store, or a
// session store the runtime did not enable all yield (nil, false).
func loadSecretsScan(ctx context.Context, store sessions.SessionStore) (*secretsScanResult, bool) {
	var result *secretsScanResult
	var found bool

	ok := withUsableStore(ctx, store, "read", func() error {
		var err error
		result, found, err = session.GetJSON[*secretsScanResult](ctx, store, secretsScanKey, sessions.WithPrefix(secretsScanPrefix))
		return err
	})
	if !ok || !found || result == nil {
		return nil, false
	}
	if result.GroupMembers == nil {
		result.GroupMembers = make(map[string][]string)
	}
	return result, true
}

// storeSecretsScan persists this sync's scan, reporting whether it stuck.
func storeSecretsScan(ctx context.Context, store sessions.SessionStore, result *secretsScanResult) bool {
	return withUsableStore(ctx, store, "write", func() error {
		return session.SetJSON(ctx, store, secretsScanKey, result, sessions.WithPrefix(secretsScanPrefix))
	})
}
