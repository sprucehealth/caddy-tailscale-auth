package caddytailscaleauth

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
	"golang.org/x/oauth2/clientcredentials"
	"tailscale.com/client/tailscale"
)

// tsClientCache stores *tailscaleClients by oauth client ID and tailnet. This avoids having to create
// a client per-module instance. The clients are cleaned up when the module cleanup is triggered.
var tsClientCache = caddy.NewUsagePool()

type tsClientCacheKey struct {
	oauthClientID string
	tailnet       string
}

type tailscaleClient struct {
	cacheKey        tsClientCacheKey
	refreshInternal time.Duration
	c               *tailscale.Client
	logger          *zap.Logger
	gpsStop         chan struct{}
	once            sync.Once
	mu              sync.RWMutex
	gpsFetchTime    time.Time
	gps             map[string][]string // {"group:name": []{"login@tailnet"}}
}

func newTailscaleClient(ctx context.Context, oauthClientID, oauthClientSecret, tailnet string, logger *zap.Logger) (*tailscaleClient, error) {
	cacheKey := tsClientCacheKey{
		oauthClientID: oauthClientID,
		tailnet:       tailnet,
	}
	v, _, err := tsClientCache.LoadOrNew(cacheKey, func() (caddy.Destructor, error) {
		oauthConfig := &clientcredentials.Config{
			ClientID:     oauthClientID,
			ClientSecret: oauthClientSecret,
			TokenURL:     "https://api.tailscale.com/api/v2/oauth/token",
		}
		httpClient := oauthConfig.Client(ctx)
		tc := tailscale.NewClient(tailnet, nil)
		tc.HTTPClient = httpClient
		return &tailscaleClient{
			cacheKey: tsClientCacheKey{
				oauthClientID: oauthClientID,
				tailnet:       tailnet,
			},
			c:      tc,
			logger: logger,
		}, nil
	})
	if err != nil {
		return nil, err
	}
	return v.(*tailscaleClient), nil
}

func (tc *tailscaleClient) startFetchingGroups(ctx context.Context, interval time.Duration) error {
	if err := tc.refreshGroupsFromACL(ctx); err != nil {
		return err
	}
	tc.once.Do(func() {
		tc.refreshInternal = interval
		tc.gpsStop = make(chan struct{})
		go func() {
			t := time.NewTicker(tc.refreshInternal)
			defer t.Stop()
			for {
				select {
				case <-tc.gpsStop:
					return
				case <-t.C:
				}
				ctx, cancel := context.WithTimeout(context.Background(), time.Second*30)
				err := tc.refreshGroupsFromACL(ctx)
				cancel()
				if err != nil {
					tc.logger.Error("failed to fetch Tailscale ACL", zap.Error(err))
				}
			}
		}()
	})
	return nil
}

// release decrements the reference count of the client in the usagepool and should be
// called by any code that initially used "newTailscaleClient".
func (tc *tailscaleClient) release() error {
	_, err := tsClientCache.Delete(tc.cacheKey)
	return err
}

// Destruct implements usagepool.Destructor and should not be called otherwise.
func (tc *tailscaleClient) Destruct() error {
	close(tc.gpsStop)
	return nil
}

// refreshGroupsFromACL fetches a list of groups from the Tailscale ACL.
func (tc *tailscaleClient) refreshGroupsFromACL(ctx context.Context) error {
	acl, err := tc.c.ACL(ctx)
	if err != nil {
		return fmt.Errorf("failed to query Tailscale ACLs: %w", err)
	}

	tc.mu.Lock()
	defer tc.mu.Unlock()
	tc.gpsFetchTime = time.Now()
	tc.gps = acl.ACL.Groups
	tc.logger.Debug("fetched tailscale groups", zap.Any("groups", tc.gps))
	return nil
}

func (tc *tailscaleClient) groups() map[string][]string {
	tc.mu.RLock()
	defer tc.mu.RUnlock()
	return tc.gps
}
