package google

import (
	"context"
	"crypto/x509"
	"fmt"
	"time"

	"github.com/jbrekelmans/go-lib/auth"
	"github.com/jbrekelmans/go-lib/cache"
)

const (
	// DefaultCachingKeySetProviderTimeToLive is a common default for the timeToLive parameter of CachingKeySetProvider.
	DefaultCachingKeySetProviderTimeToLive = time.Minute * 5
)

// KeySet contains entries where each entry represents a key identifier and certificate.
type KeySet = map[string]*x509.Certificate

// KeySetProvider is an interface for getting a set of keys.
type KeySetProvider interface {
	// The returned map should not be modified.
	Get(ctx context.Context) (KeySet, error)
}

type staticKeySetProvider struct {
	keySet KeySet
}

// StaticKeySetProvider is an in-memory KeySetProvider.
// The values of the keySet parameter should be PEM encoded X509 certificates.
func StaticKeySetProvider(keySet map[string]string) (KeySetProvider, error) {
	s := &staticKeySetProvider{
		keySet: KeySet{},
	}
	for keyID, certificatePEM := range keySet {
		certificate, err := auth.ParseCertificate(certificatePEM)
		if err != nil {
			return nil, fmt.Errorf("keySet[%#v] is invalid: %w", keyID, err)
		}
		s.keySet[keyID] = certificate
	}
	return s, nil
}

// Get implements KeySetProvider.
func (s *staticKeySetProvider) Get(ctx context.Context) (KeySet, error) {
	return s.keySet, nil
}

type cachingKeySetProvider struct {
	base            KeySetProvider
	cachedEvaluator cache.CachedEvaluator
	timeToLive      time.Duration
}

type keySetWithExpires struct {
	keySet  KeySet
	expires time.Time
}

// CachingKeySetProvider wrapss a KeySetProvider and adds caching.
func CachingKeySetProvider(timeToLive time.Duration, base KeySetProvider) KeySetProvider {
	c := &cachingKeySetProvider{
		base:       base,
		timeToLive: timeToLive,
	}
	c.cachedEvaluator, _ = cache.NewCachedEvaluator(c.evaluator)
	return c
}

func (c *cachingKeySetProvider) evaluator(ctx context.Context) (value interface{}, err error) {
	keySet, err := c.base.Get(ctx)
	if keySet != nil {
		value = &keySetWithExpires{
			keySet:  keySet,
			expires: time.Now().Add(c.timeToLive),
		}
	}
	return
}

// Get implements KeySetProvider.
func (c *cachingKeySetProvider) Get(ctx context.Context) (KeySet, error) {
	value := c.cachedEvaluator.GetCacheOnly()
	if value != nil {
		valueT := value.(*keySetWithExpires)
		if !time.Now().Before(valueT.expires) {
			value = nil
		}
	}
	if value == nil {
		var err error
		value, err = c.cachedEvaluator.Evaluate(ctx)
		if err != nil {
			return nil, err
		}
	}
	return value.(*keySetWithExpires).keySet, nil
}
