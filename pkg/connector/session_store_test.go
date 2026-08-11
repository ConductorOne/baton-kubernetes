package connector

import (
	"context"
	"fmt"
	"maps"
	"sync"

	"github.com/conductorone/baton-sdk/pkg/pagination"
	rs "github.com/conductorone/baton-sdk/pkg/types/resource"
	"github.com/conductorone/baton-sdk/pkg/types/sessions"
)

// syncNextToken reads the token out of a SyncOpResults, which syncers are free
// to return as nil when a phase completes in one call.
func syncNextToken(results *rs.SyncOpResults) string {
	if results == nil {
		return ""
	}
	return results.NextPageToken
}

// memorySessionStore is an in-memory sessions.SessionStore for tests.
//
// The SDK's own session.MemorySessionCache is a read-through cache that
// requires a backing store, and session.NoOpSessionStore fails every operation
// by design, so neither can stand in for the real store here.
//
// Keys are namespaced by sync ID and prefix exactly as the production store is,
// so a test can assert that one sync cannot read another's data.
type memorySessionStore struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMemorySessionStore() *memorySessionStore {
	return &memorySessionStore{data: make(map[string][]byte)}
}

func (m *memorySessionStore) bagKey(ctx context.Context, key string, opt ...sessions.SessionStoreOption) (string, error) {
	bag := &sessions.SessionStoreBag{}
	for _, o := range opt {
		if err := o(ctx, bag); err != nil {
			return "", err
		}
	}
	return fmt.Sprintf("%s/%s/%s", bag.SyncID, bag.Prefix, key), nil
}

func (m *memorySessionStore) Get(ctx context.Context, key string, opt ...sessions.SessionStoreOption) ([]byte, bool, error) {
	k, err := m.bagKey(ctx, key, opt...)
	if err != nil {
		return nil, false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.data[k]
	return v, ok, nil
}

func (m *memorySessionStore) Set(ctx context.Context, key string, value []byte, opt ...sessions.SessionStoreOption) error {
	k, err := m.bagKey(ctx, key, opt...)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[k] = value
	return nil
}

func (m *memorySessionStore) GetMany(ctx context.Context, keys []string, opt ...sessions.SessionStoreOption) (map[string][]byte, []string, error) {
	found := make(map[string][]byte)
	var missing []string
	for _, key := range keys {
		v, ok, err := m.Get(ctx, key, opt...)
		if err != nil {
			return nil, nil, err
		}
		if ok {
			found[key] = v
			continue
		}
		missing = append(missing, key)
	}
	return found, missing, nil
}

func (m *memorySessionStore) SetMany(ctx context.Context, values map[string][]byte, opt ...sessions.SessionStoreOption) error {
	for key, value := range values {
		if err := m.Set(ctx, key, value, opt...); err != nil {
			return err
		}
	}
	return nil
}

func (m *memorySessionStore) Delete(ctx context.Context, key string, opt ...sessions.SessionStoreOption) error {
	k, err := m.bagKey(ctx, key, opt...)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, k)
	return nil
}

func (m *memorySessionStore) Clear(_ context.Context, _ ...sessions.SessionStoreOption) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data = make(map[string][]byte)
	return nil
}

func (m *memorySessionStore) GetAll(_ context.Context, _ string, _ ...sessions.SessionStoreOption) (map[string][]byte, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make(map[string][]byte, len(m.data))
	maps.Copy(out, m.data)
	return out, "", nil
}

// paginationToken builds a SyncOpAttrs page token for tests.
func paginationToken(token string) pagination.Token {
	return pagination.Token{Token: token}
}

// paginationTokenWithSize sets the page size too, for tests that page.
func paginationTokenWithSize(token string, size int) pagination.Token {
	return pagination.Token{Token: token, Size: size}
}
