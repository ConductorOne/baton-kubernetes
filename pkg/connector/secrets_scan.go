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

// loadSecretsScan reads this sync's scan. A missing key, a nil store, or a
// session store the runtime did not enable all yield (nil, false).
//
// Errors are logged and swallowed on purpose. The x509 pass is best-effort
// discovery — downstream connectors embedding this package may run without
// WithSessionStoreEnabled, and that must degrade group membership rather than
// fail the mandatory user sync.
func loadSecretsScan(ctx context.Context, store sessions.SessionStore) (*secretsScanResult, bool) {
	if store == nil {
		return nil, false
	}
	result, found, err := session.GetJSON[*secretsScanResult](ctx, store, secretsScanKey, sessions.WithPrefix(secretsScanPrefix))
	if err != nil {
		ctxzap.Extract(ctx).Debug("x509 scan unavailable: session store read failed", zap.Error(err))
		return nil, false
	}
	if !found || result == nil {
		return nil, false
	}
	if result.GroupMembers == nil {
		result.GroupMembers = make(map[string][]string)
	}
	return result, true
}

// storeSecretsScan persists this sync's scan, reporting whether it stuck.
// Failures are logged and swallowed for the same reason as loadSecretsScan.
func storeSecretsScan(ctx context.Context, store sessions.SessionStore, result *secretsScanResult) bool {
	if store == nil {
		return false
	}
	if err := session.SetJSON(ctx, store, secretsScanKey, result, sessions.WithPrefix(secretsScanPrefix)); err != nil {
		ctxzap.Extract(ctx).Debug("x509 scan not persisted: session store write failed", zap.Error(err))
		return false
	}
	return true
}
