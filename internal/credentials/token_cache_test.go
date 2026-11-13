package credentials

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

const (
	testClientID     = "test-client-id"
	testClientSecret = "super-secret-value-do-not-store"
	testTokenURL     = "https://auth.example.com/oauth2/token"
	testAudience     = "https://api.example.com"
)

type fakeTokenSource struct {
	mu          sync.Mutex
	calls       int
	accessToken string
	expiresIn   time.Duration
	err         error
}

func (f *fakeTokenSource) Token() (*oauth2.Token, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.calls++

	if f.err != nil {
		return nil, f.err
	}

	return &oauth2.Token{
		AccessToken: f.accessToken,
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(f.expiresIn),
	}, nil
}

func (f *fakeTokenSource) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()

	return f.calls
}

func newFakeTokenSource(accessToken string) *fakeTokenSource {
	return &fakeTokenSource{accessToken: accessToken, expiresIn: time.Hour}
}

// newPrivateTestDir returns a fresh temp dir chmod'd to exactly the 0700 this package's own write()
// creates a cache directory with - t.TempDir() isn't guaranteed to produce that under every umask,
// but a freshly-created real token-cache dir always is, so this is what the cache actually sees in
// real use.
func newPrivateTestDir(t *testing.T) string {
	t.Helper()

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("failed to set up a private test dir: %v", err)
	}

	return dir
}

func newTestCache(t *testing.T, inner oauth2.TokenSource, dir, clientSecret string) oauth2.TokenSource {
	t.Helper()

	return newDiskCachingTokenSource(inner, dir, testClientID, clientSecret, testTokenURL, testAudience)
}

func cachePath(t *testing.T, source oauth2.TokenSource) string {
	t.Helper()

	cache, ok := source.(*diskCachingTokenSource)
	if !ok {
		t.Fatalf("expected a *diskCachingTokenSource, got %T", source)
	}

	return cache.path
}

func writeCacheFile(t *testing.T, path string, contents []byte) {
	t.Helper()

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("failed to create cache dir: %v", err)
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatalf("failed to write cache file: %v", err)
	}
}

func marshalEntry(t *testing.T, entry cacheEntry) []byte {
	t.Helper()

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("failed to marshal cache entry: %v", err)
	}

	return data
}

func validEntry(accessToken string, expiry time.Time) cacheEntry {
	return cacheEntry{
		SchemaVersion: cacheSchemaVersion,
		AccessToken:   accessToken,
		TokenType:     "Bearer",
		Expiry:        expiry,
		ClientID:      testClientID,
		CachedAt:      time.Now().UTC(),
	}
}

func TestDiskCachingTokenSource_RoundTrip(t *testing.T) {
	dir := newPrivateTestDir(t)
	inner := newFakeTokenSource("minted-token")
	source := newTestCache(t, inner, dir, testClientSecret)

	token, err := source.Token()
	if err != nil {
		t.Fatalf("Token() failed: %v", err)
	}
	if token.AccessToken != "minted-token" {
		t.Fatalf("expected the minted token, got %q", token.AccessToken)
	}
	if inner.callCount() != 1 {
		t.Fatalf("expected exactly one mint, got %d", inner.callCount())
	}

	path := cachePath(t, source)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected a cache file at %s: %v", path, err)
	}

	if _, err := source.Token(); err != nil {
		t.Fatalf("second Token() failed: %v", err)
	}
	if inner.callCount() != 1 {
		t.Fatalf("expected the second call to be served from cache, got %d mints", inner.callCount())
	}

	fresh := newTestCache(t, inner, dir, testClientSecret)

	cached, err := fresh.Token()
	if err != nil {
		t.Fatalf("Token() on a fresh source failed: %v", err)
	}
	if cached.AccessToken != "minted-token" {
		t.Fatalf("expected the cached token, got %q", cached.AccessToken)
	}
	if inner.callCount() != 1 {
		t.Fatalf("expected a fresh source to reuse the cache file, got %d mints", inner.callCount())
	}
}

func TestDiskCachingTokenSource_CacheFilePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits don't apply on Windows")
	}

	dir := filepath.Join(t.TempDir(), "created-on-demand")
	source := newTestCache(t, newFakeTokenSource("minted-token"), dir, testClientSecret)

	if _, err := source.Token(); err != nil {
		t.Fatalf("Token() failed: %v", err)
	}

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("expected the cache dir to be created: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("expected cache dir mode 0700, got %#o", got)
	}

	fileInfo, err := os.Stat(cachePath(t, source))
	if err != nil {
		t.Fatalf("expected a cache file: %v", err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("expected cache file mode 0600, got %#o", got)
	}
}

func TestDiskCachingTokenSource_ExpiryBoundary(t *testing.T) {
	t.Run("expiry inside the safety buffer is a miss", func(t *testing.T) {
		dir := newPrivateTestDir(t)
		inner := newFakeTokenSource("minted-token")
		source := newTestCache(t, inner, dir, testClientSecret)

		writeCacheFile(t, cachePath(t, source),
			marshalEntry(t, validEntry("cached-token", time.Now().Add(cacheExpiryDelta/2))))

		token, err := source.Token()
		if err != nil {
			t.Fatalf("Token() failed: %v", err)
		}
		if token.AccessToken != "minted-token" {
			t.Fatalf("expected a fresh mint for a near-expiry entry, got %q", token.AccessToken)
		}
		if inner.callCount() != 1 {
			t.Fatalf("expected exactly one mint, got %d", inner.callCount())
		}
	})

	t.Run("expiry beyond the safety buffer is a hit", func(t *testing.T) {
		dir := newPrivateTestDir(t)
		inner := newFakeTokenSource("minted-token")
		source := newTestCache(t, inner, dir, testClientSecret)

		writeCacheFile(t, cachePath(t, source),
			marshalEntry(t, validEntry("cached-token", time.Now().Add(10*cacheExpiryDelta))))

		token, err := source.Token()
		if err != nil {
			t.Fatalf("Token() failed: %v", err)
		}
		if token.AccessToken != "cached-token" {
			t.Fatalf("expected the cached token, got %q", token.AccessToken)
		}
		if inner.callCount() != 0 {
			t.Fatalf("expected no mint on a cache hit, got %d", inner.callCount())
		}
	})
}

func TestDiskCachingTokenSource_FailsOpenOnBadCacheFile(t *testing.T) {
	futureEntry := validEntry("cached-token", time.Now().Add(time.Hour))

	staleSchema := futureEntry
	staleSchema.SchemaVersion = cacheSchemaVersion + 1

	cases := []struct {
		name     string
		contents []byte
	}{
		{name: "truncated json", contents: []byte(`{"schema_version":1,"access_token":"cach`)},
		{name: "not json at all", contents: []byte("\x00\x01not json\n")},
		{name: "empty file", contents: nil},
		{name: "mismatched schema version", contents: marshalEntry(t, staleSchema)},
	}

	for _, testCase := range cases {
		testCase := testCase
		t.Run(testCase.name, func(t *testing.T) {
			dir := newPrivateTestDir(t)
			inner := newFakeTokenSource("minted-token")
			source := newTestCache(t, inner, dir, testClientSecret)

			writeCacheFile(t, cachePath(t, source), testCase.contents)

			token, err := source.Token()
			if err != nil {
				t.Fatalf("expected a bad cache file to fail open, got error: %v", err)
			}
			if token.AccessToken != "minted-token" {
				t.Fatalf("expected a fresh mint, got %q", token.AccessToken)
			}
			if inner.callCount() != 1 {
				t.Fatalf("expected exactly one mint, got %d", inner.callCount())
			}
		})
	}
}

func TestDiskCachingTokenSource_FailsOpenOnUnwritableDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(dir, []byte("this is a file, so MkdirAll must fail"), 0o600); err != nil {
		t.Fatalf("failed to set up an unwritable cache dir: %v", err)
	}

	inner := newFakeTokenSource("minted-token")
	source := newTestCache(t, inner, dir, testClientSecret)

	token, err := source.Token()
	if err != nil {
		t.Fatalf("expected an unusable cache dir to fail open, got error: %v", err)
	}
	if token.AccessToken != "minted-token" {
		t.Fatalf("expected a fresh mint, got %q", token.AccessToken)
	}
}

func TestDiskCachingTokenSource_MintErrorIsReturned(t *testing.T) {
	mintErr := errors.New("hydra said no")
	inner := &fakeTokenSource{err: mintErr}
	source := newTestCache(t, inner, newPrivateTestDir(t), testClientSecret)

	if _, err := source.Token(); !errors.Is(err, mintErr) {
		t.Fatalf("expected the inner minting error to be returned unchanged, got: %v", err)
	}
}

func TestDiskCachingTokenSource_RotatedSecretMisses(t *testing.T) {
	dir := newPrivateTestDir(t)
	original := newTestCache(t, newFakeTokenSource("original-token"), dir, testClientSecret)

	writeCacheFile(t, cachePath(t, original),
		marshalEntry(t, validEntry("original-token", time.Now().Add(time.Hour))))

	inner := newFakeTokenSource("rotated-token")
	rotated := newTestCache(t, inner, dir, "a-completely-different-secret")

	if cachePath(t, rotated) == cachePath(t, original) {
		t.Fatal("expected a rotated secret to hash to a different cache file")
	}

	token, err := rotated.Token()
	if err != nil {
		t.Fatalf("Token() failed: %v", err)
	}
	if token.AccessToken != "rotated-token" {
		t.Fatalf("expected a fresh mint under the rotated secret, got %q", token.AccessToken)
	}
	if inner.callCount() != 1 {
		t.Fatalf("expected exactly one mint, got %d", inner.callCount())
	}

	originalData, err := os.ReadFile(cachePath(t, original))
	if err != nil {
		t.Fatalf("expected the original entry to be left alone: %v", err)
	}
	if !strings.Contains(string(originalData), "original-token") {
		t.Fatal("expected the original cache entry to be untouched")
	}
}

func TestDiskCachingTokenSource_PostDefaultingKey(t *testing.T) {
	dir := t.TempDir()

	omitted, err := NewClientSecretTokenSource(
		context.Background(), testClientID, testClientSecret, "", "", WithDiskTokenCache(dir))
	if err != nil {
		t.Fatalf("NewClientSecretTokenSource failed: %v", err)
	}

	spelledOut, err := NewClientSecretTokenSource(
		context.Background(), testClientID, testClientSecret, DefaultTokenURL, DefaultAudience, WithDiskTokenCache(dir))
	if err != nil {
		t.Fatalf("NewClientSecretTokenSource failed: %v", err)
	}

	if cachePath(t, omitted) != cachePath(t, spelledOut) {
		t.Fatal("expected an omitted tokenURL/audience to hash the same as the spelled-out defaults")
	}

	different, err := NewClientSecretTokenSource(
		context.Background(), testClientID, testClientSecret, testTokenURL, DefaultAudience, WithDiskTokenCache(dir))
	if err != nil {
		t.Fatalf("NewClientSecretTokenSource failed: %v", err)
	}
	if cachePath(t, different) == cachePath(t, omitted) {
		t.Fatal("expected a different tokenURL to hash to a different cache file")
	}
}

func TestDiskCachingTokenSource_Concurrent(t *testing.T) {
	const goroutines = 20

	dir := newPrivateTestDir(t)
	inner := newFakeTokenSource("minted-token")

	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		errs   []error
		tokens []string
	)

	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()

			// A separate wrapper per goroutine, so they race on the file rather than on one mutex,
			// the way separate CLI processes sharing a cache dir would.
			token, err := newTestCache(t, inner, dir, testClientSecret).Token()

			mu.Lock()
			defer mu.Unlock()

			if err != nil {
				errs = append(errs, err)

				return
			}

			tokens = append(tokens, token.AccessToken)
		}()
	}

	wg.Wait()

	if len(errs) != 0 {
		t.Fatalf("expected no errors from concurrent Token() calls, got: %v", errs)
	}
	if len(tokens) != goroutines {
		t.Fatalf("expected %d tokens, got %d", goroutines, len(tokens))
	}
	for _, token := range tokens {
		if token != "minted-token" {
			t.Fatalf("expected every caller to get a usable token, got %q", token)
		}
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("failed to read the cache dir: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected exactly one cache file to remain, got %d: %v", len(entries), entries)
	}

	data, err := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if err != nil {
		t.Fatalf("failed to read the cache file: %v", err)
	}

	var entry cacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("expected a well-formed cache file after a concurrent race, got %q: %v", data, err)
	}
	if entry.AccessToken == "" {
		t.Fatal("expected the surviving cache entry to hold a non-empty access token")
	}
	if entry.SchemaVersion != cacheSchemaVersion {
		t.Fatalf("expected schema version %d, got %d", cacheSchemaVersion, entry.SchemaVersion)
	}
}

func TestDiskCachingTokenSource_NeverWritesClientSecret(t *testing.T) {
	dir := newPrivateTestDir(t)
	source := newTestCache(t, newFakeTokenSource("minted-token"), dir, testClientSecret)

	if _, err := source.Token(); err != nil {
		t.Fatalf("Token() failed: %v", err)
	}

	path := cachePath(t, source)

	if strings.Contains(filepath.Base(path), testClientID) {
		t.Fatalf("expected the cache filename to be a hash only, got %q", filepath.Base(path))
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("failed to read the cache file: %v", err)
	}
	if strings.Contains(string(data), testClientSecret) {
		t.Fatalf("the client secret was written to the cache file: %s", data)
	}

	var entry cacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		t.Fatalf("failed to parse the cache file: %v", err)
	}
	if entry.ClientID != testClientID {
		t.Fatalf("expected the client ID to be recorded for debugging, got %q", entry.ClientID)
	}

	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("failed to parse the cache file as a generic object: %v", err)
	}
	for _, field := range []string{"client_secret", "clientSecret", "secret"} {
		if _, found := raw[field]; found {
			t.Fatalf("unexpected %q field in the cache file: %s", field, data)
		}
	}
}

func TestDiskCachingTokenSource_UntrustedDirectoryIsNeverCached(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory ownership/mode checks don't apply on Windows")
	}

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("failed to loosen permissions on the cache dir: %v", err)
	}

	inner := newFakeTokenSource("minted-token")
	source := newTestCache(t, inner, dir, testClientSecret)

	if _, err := source.Token(); err != nil {
		t.Fatalf("Token() failed: %v", err)
	}
	if inner.callCount() != 1 {
		t.Fatalf("expected a fresh mint, got %d", inner.callCount())
	}

	if _, err := source.Token(); err != nil {
		t.Fatalf("second Token() failed: %v", err)
	}
	if inner.callCount() != 2 {
		t.Fatalf("expected an untrusted directory to mint every time, got %d mints", inner.callCount())
	}
}

func TestInvalidateDiskTokenCache(t *testing.T) {
	dir := newPrivateTestDir(t)
	inner := newFakeTokenSource("minted-token")
	source := newTestCache(t, inner, dir, testClientSecret)

	if _, err := source.Token(); err != nil {
		t.Fatalf("Token() failed: %v", err)
	}

	path := cachePath(t, source)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected a cache file before invalidation: %v", err)
	}

	if err := InvalidateDiskTokenCache(dir, testClientID, testClientSecret, testTokenURL, testAudience); err != nil {
		t.Fatalf("InvalidateDiskTokenCache failed: %v", err)
	}

	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("expected the cache file to be removed, stat error: %v", err)
	}

	if err := InvalidateDiskTokenCache(dir, testClientID, testClientSecret, testTokenURL, testAudience); err != nil {
		t.Fatalf("expected invalidating an already-missing entry to be a no-op, got: %v", err)
	}

	if _, err := source.Token(); err != nil {
		t.Fatalf("Token() after invalidation failed: %v", err)
	}
	if inner.callCount() != 2 {
		t.Fatalf("expected invalidation to force a fresh mint, got %d mints", inner.callCount())
	}
}
