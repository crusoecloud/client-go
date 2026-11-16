package credentials

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

// cacheSchemaVersion is stamped into every entry and must match exactly on read. An entry written
// by any other version is discarded rather than interpreted under the wrong schema.
const cacheSchemaVersion = 1

// cacheExpiryDelta is the safety margin a cached token must still have left to count as a hit. It
// restates golang.org/x/oauth2's own defaultExpiryDelta, the point at which its in-memory
// ReuseTokenSource stops handing a token out; oauth2 keeps that constant unexported, so the value
// is duplicated here rather than imported.
const cacheExpiryDelta = 10 * time.Second

// Permissions are set explicitly rather than left to the process umask: these files hold bearer
// tokens, so a permissive umask must not be allowed to widen them.
const (
	cacheDirPerm  = 0o700
	cacheFilePerm = 0o600
)

// cacheTempPattern names the temp file an entry is staged in before being renamed into place. The
// leading dot keeps a partially written entry from looking like a cache file to anything listing
// the directory.
const cacheTempPattern = ".token-*.json.tmp"

// cacheEntry is the on-disk form of a minted token. The client secret is deliberately absent and
// must never be added: the entry is keyed by a hash of the secret, so it never needs to hold one.
//
//nolint:tagliatelle // snake_case mirrors the OAuth2 token response this entry is derived from
type cacheEntry struct {
	SchemaVersion int       `json:"schema_version"`
	AccessToken   string    `json:"access_token"`
	TokenType     string    `json:"token_type"`
	Expiry        time.Time `json:"expiry"`
	ClientID      string    `json:"client_id"`
	CachedAt      time.Time `json:"cached_at"`
}

// diskCachingTokenSource wraps a token source with an on-disk entry shared across processes. The
// mutex only covers same-process concurrency; separate processes are serialized by the atomic
// rename in write.
type diskCachingTokenSource struct {
	mu       sync.Mutex
	inner    oauth2.TokenSource
	dir      string
	path     string
	clientID string
}

// cacheFilePath keys the cache off the full credential tuple, which the caller must pass already
// defaulted: two logically identical configurations - one omitting tokenURL/audience, one spelling
// out the literal defaults - have to resolve to the same entry. Including the secret in the key
// means a rotated secret lands on a different filename, so a stale entry can never be served to new
// credentials. Shared by newDiskCachingTokenSource and InvalidateDiskTokenCache so the two never
// compute the key differently.
func cacheFilePath(dir, clientID, clientSecret, tokenURL, audience string) string {
	// NUL separators keep the tuple unambiguous: no field can contain one, so no combination of
	// values can be rearranged into another tuple's key.
	sum := sha256.Sum256([]byte(clientID + "\x00" + clientSecret + "\x00" + tokenURL + "\x00" + audience))
	key := hex.EncodeToString(sum[:])

	return filepath.Join(dir, key+".json")
}

func newDiskCachingTokenSource(
	inner oauth2.TokenSource, dir, clientID, clientSecret, tokenURL, audience string,
) oauth2.TokenSource {
	// Keyed once here; Token() never recomputes it.
	return &diskCachingTokenSource{
		inner:    inner,
		dir:      dir,
		path:     cacheFilePath(dir, clientID, clientSecret, tokenURL, audience),
		clientID: clientID,
	}
}

// InvalidateDiskTokenCache removes the disk-cached entry for the given credential tuple under dir,
// if one exists. The cache-key design already forces a miss on a rotated client secret; this covers
// the other way a cached token can go bad before its own recorded expiry - for example its signing
// key rotating server-side, or it being explicitly revoked - where a caller that gets a 401 wants to
// discard the cache and force a fresh mint on the next attempt rather than keep reusing the same
// token until it naturally expires. A missing entry is not an error.
//
// tokenURL/audience are defaulted exactly as NewClientSecretTokenSource would - pass the same raw
// values (including "" to mean "use the defaults") that were used to build the token source whose
// entry this should remove, not whatever those defaults happen to resolve to.
//
// This only removes the disk entry. It does not affect any *http.Client/*swagger.Configuration
// already built from this credential tuple - oauth2.NewClient wraps the token source in its own
// in-memory reuse wrapper, which goes on handing out the same bad token regardless of what happens
// on disk. Construct a new token source/config after calling this, and retry on that, not on the
// client that got the 401.
func InvalidateDiskTokenCache(dir, clientID, clientSecret, tokenURL, audience string) error {
	tokenURL, audience = defaultTokenURLAndAudience(tokenURL, audience)
	path := cacheFilePath(dir, clientID, clientSecret, tokenURL, audience)

	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing cached token: %w", err)
	}

	return nil
}

// Token serves a still-valid cached token without contacting the inner source, and otherwise mints
// a fresh one and caches it. The only error it can return is a genuine minting failure: no
// cache-layer problem is ever surfaced as an error, since the cache must not become a new way for
// authentication to break.
func (s *diskCachingTokenSource) Token() (*oauth2.Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if token, ok := s.read(); ok {
		return token, nil
	}

	token, err := s.inner.Token()
	if err != nil {
		//nolint:wrapcheck // a real minting failure must surface exactly as the inner source reported it
		return nil, err
	}

	s.write(token)

	return token, nil
}

// read reports a hit only for a file that is present, parseable, of the current schema, and still
// comfortably short of expiry. Every other outcome - including an unreadable or corrupt file, or a
// directory this process can't be sure is private to it - is an ordinary miss.
func (s *diskCachingTokenSource) read() (*oauth2.Token, bool) {
	if !dirIsSafeForCache(s.dir) {
		return nil, false
	}

	data, err := os.ReadFile(s.path)
	if err != nil {
		return nil, false
	}

	var entry cacheEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, false
	}

	if entry.SchemaVersion != cacheSchemaVersion || entry.AccessToken == "" {
		return nil, false
	}

	// A token minted with no expiry (zero Expiry) can never clear this check, so it's never cached
	// - the safe default for a server that doesn't set expires_in, rather than treating it as
	// eternally valid.
	if !time.Now().Add(cacheExpiryDelta).Before(entry.Expiry) {
		return nil, false
	}

	return &oauth2.Token{
		AccessToken: entry.AccessToken,
		TokenType:   entry.TokenType,
		Expiry:      entry.Expiry,
	}, true
}

// write stages the entry in a temp file in the same directory and renames it into place. Rename is
// atomic within a filesystem, so a concurrent reader never sees a torn write and two processes
// racing on the same key simply resolve to whichever renamed last - both of which are valid tokens.
// Every failure is dropped on purpose: the caller already holds a freshly minted token, and caching
// it is only an optimization.
func (s *diskCachingTokenSource) write(token *oauth2.Token) {
	if err := os.MkdirAll(s.dir, cacheDirPerm); err != nil {
		return
	}

	// MkdirAll only applies cacheDirPerm to a directory it actually creates - a pre-existing one
	// (e.g. a shared or misconfigured CRUSOE_CONFIG_DIR) keeps whatever permissions it already had,
	// so this check is what actually enforces privacy on every write, not just the first one.
	if !dirIsSafeForCache(s.dir) {
		return
	}

	data, err := json.Marshal(cacheEntry{
		SchemaVersion: cacheSchemaVersion,
		AccessToken:   token.AccessToken,
		TokenType:     token.TokenType,
		Expiry:        token.Expiry,
		ClientID:      s.clientID,
		CachedAt:      time.Now().UTC(),
	})
	if err != nil {
		return
	}

	tmpFile, err := os.CreateTemp(s.dir, cacheTempPattern)
	if err != nil {
		return
	}

	tmpPath := tmpFile.Name()

	_, writeErr := tmpFile.Write(data)
	chmodErr := os.Chmod(tmpPath, cacheFilePerm)
	closeErr := tmpFile.Close()

	if writeErr != nil || chmodErr != nil || closeErr != nil {
		removeTempFile(tmpPath)

		return
	}

	if err := os.Rename(tmpPath, s.path); err != nil {
		removeTempFile(tmpPath)
	}
}

// removeTempFile drops an entry that never reached its final path. A removal failure leaves only a
// harmless stray file, and there is nothing further worth doing about it.
func removeTempFile(path string) {
	_ = os.Remove(path)
}

// dirIsSafeForCache reports whether dir is safe to read or write cache entries in. It must be a
// real directory - Lstat, so a symlink standing in for it doesn't count - and, where the platform
// makes that meaningful (see isPrivateDir), owned by this process with no group/other permission
// bits, so no other local user could have planted or substituted a file inside it. A directory that
// fails this check is treated exactly like a missing one: the cache is skipped, never trusted.
func dirIsSafeForCache(dir string) bool {
	info, err := os.Lstat(dir)
	if err != nil {
		return false
	}

	return isPrivateDir(info)
}
