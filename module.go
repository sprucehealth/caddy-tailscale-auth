package caddytailscaleauth

import (
	"context"
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	"go.uber.org/zap"
	"golang.org/x/oauth2/clientcredentials"
	"tailscale.com/client/tailscale"
)

const defaultTailscaleAPIRefreshInterval = time.Minute * 10

const (
	globalKeyTailscaleAPIRefreshInterval = "tailscale_api_refresh_interval"
	globalKeyTailscaleAPITailnet         = "tailscale_api_tailnet"
	globalKeyTailscaleGroups             = "tailscale_groups"
	globalKeyTailscaleOAuthClientID      = "tailscale_oauth_client_id"
	globalKeyTailscaleOAuthClientSecret  = "tailscale_oauth_client_secret"
)

func init() {
	caddy.RegisterModule(&TailscaleAuth{})
	httpcaddyfile.RegisterHandlerDirective("tailscaleauth", parseCaddyfile)
	httpcaddyfile.RegisterGlobalOption(globalKeyTailscaleAPIRefreshInterval, parseDurationValue)
	httpcaddyfile.RegisterGlobalOption(globalKeyTailscaleAPITailnet, parseSimpleValue)
	httpcaddyfile.RegisterGlobalOption(globalKeyTailscaleGroups, parseGroups)
	httpcaddyfile.RegisterGlobalOption(globalKeyTailscaleOAuthClientID, parseSimpleValue)
	httpcaddyfile.RegisterGlobalOption(globalKeyTailscaleOAuthClientSecret, parseSimpleValue)
	tailscale.I_Acknowledge_This_API_Is_Unstable = true
}

const (
	groupPrefix = "group:"
	tagPrefix   = "tag:"
)

const (
	PolicyAllow = "allow"
	PolicyDeny  = "deny"
)

type PolicyMatches struct {
	Policy  string
	Matches []string
}

type TailscaleAuth struct {
	APITailnet                  string              `json:"api_tailnet,omitempty"`
	ExpectedTailnet             string              `json:"expected_tailnet,omitempty"`
	DefaultPolicy               string              `json:"default_policy,omitempty"`
	Policies                    []PolicyMatches     `json:"policies,omitempty"`
	Groups                      map[string][]string `json:"groups,omitempty"`
	TailscaleAPIRefreshInterval time.Duration       `json:"tailscale_api_refresh_interval,omitempty"`
	TailscaleOAuthClientID      string              `json:"tailscale_oauth_client_id,omitempty"`
	TailscaleOAuthClientSecret  string              `json:"tailscale_oauth_client_secret,omitempty"`

	logger         *zap.Logger
	tc             *tailscale.Client
	needGroup      bool
	mu             sync.RWMutex
	groupFetchTime time.Time
	groups         map[string][]string // {"group:name": []{"login@tailnet"}}
}

// CaddyModule returns the Caddy module information.
func (*TailscaleAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.authentication.providers.tailscale",
		New: func() caddy.Module { return new(TailscaleAuth) },
	}
}

func (ta *TailscaleAuth) Provision(ctx caddy.Context) error {
	ta.logger = ctx.Logger(ta)
	if ta.TailscaleOAuthClientID != "" {
		tailnet := ta.APITailnet
		if tailnet == "" {
			tailnet = ta.ExpectedTailnet
		}
		var oauthConfig = &clientcredentials.Config{
			ClientID:     ta.TailscaleOAuthClientID,
			ClientSecret: ta.TailscaleOAuthClientSecret,
			TokenURL:     "https://api.tailscale.com/api/v2/oauth/token",
		}
		httpClient := oauthConfig.Client(ctx)
		ta.tc = tailscale.NewClient(tailnet, nil)
		ta.tc.HTTPClient = httpClient
		if _, err := ta.userGroups(ctx); err != nil {
			return err
		}
	}
	for _, p := range ta.Policies {
		for _, m := range p.Matches {
			if strings.HasPrefix(m, groupPrefix) {
				ta.needGroup = true
				break
			}
		}
		if ta.needGroup {
			break
		}
	}
	return nil
}

func (ta *TailscaleAuth) userGroups(ctx context.Context) (map[string][]string, error) {
	if len(ta.Groups) != 0 {
		return ta.Groups, nil
	}
	if ta.tc == nil {
		return nil, nil
	}

	now := time.Now()

	ta.mu.RLock()
	groups := ta.groups
	lastFetch := ta.groupFetchTime
	ta.mu.RUnlock()
	if dt := now.Sub(lastFetch); dt < ta.TailscaleAPIRefreshInterval {
		return groups, nil
	}

	ta.mu.Lock()
	defer ta.mu.Unlock()
	// Recheck since we may have been waiting on this lock.
	if time.Since(lastFetch) < ta.TailscaleAPIRefreshInterval {
		return ta.groups, nil
	}
	// Update the time ever if we get an error to rate limit the lookups
	ta.groupFetchTime = now
	acl, err := ta.tc.ACL(ctx)
	if err != nil {
		return groups, fmt.Errorf("failed to query Tailscale ACLs: %w", err)
	}
	ta.groups = acl.ACL.Groups
	ta.logger.Debug("fetched tailscale groups", zap.Any("groups", ta.groups))
	return ta.groups, nil
}

func (ta *TailscaleAuth) Authenticate(w http.ResponseWriter, r *http.Request) (caddyauth.User, bool, error) {
	// TODO: fix this for IPv6 and when behind proxies
	raddr := r.RemoteAddr
	if !strings.Contains(raddr, ":") {
		raddr += ":443"
	}
	remoteAddr, err := netip.ParseAddrPort(raddr)
	if err != nil {
		return caddyauth.User{}, false, fmt.Errorf("remote address and port are not valid: %w", err)
	}

	info, err := tailscale.WhoIs(r.Context(), remoteAddr.String())
	if err != nil {
		return caddyauth.User{}, false, fmt.Errorf("tailscale whois failed: %w", err)
	}

	_, tailnet, ok := strings.Cut(info.Node.Name, info.Node.ComputedName+".")
	if !ok {
		ta.logger.Error("can't extract tailnet name from hostname", zap.String("hostname", info.Node.Name))
		return caddyauth.User{}, false, nil
	}
	tailnet, _, ok = strings.Cut(tailnet, ".ts.net")
	if !ok {
		ta.logger.Error("can't extract tailnet name from hostname", zap.String("hostname", info.Node.Name))
		return caddyauth.User{}, false, nil
	}

	if ta.ExpectedTailnet != "" && ta.ExpectedTailnet != tailnet {
		ta.logger.Warn("user is part of unexpected tailnet", zap.String("expected_tailnet", ta.ExpectedTailnet), zap.String("unexpected_tailnet", tailnet))
		return caddyauth.User{}, false, nil
	}

	var groups map[string][]string
	if ta.needGroup {
		groups, err = ta.userGroups(r.Context())
		if err != nil {
			ta.logger.Error("failed to fetch Tailscale user groups", zap.Error(err))
		}
	}
	allow := ta.DefaultPolicy == PolicyAllow
	for _, p := range ta.Policies {
		matchAll := true
		for _, m := range p.Matches {
			switch {
			case strings.HasPrefix(m, groupPrefix):
				var isMember bool
				for _, gm := range groups[m] {
					if gm == info.UserProfile.LoginName {
						isMember = true
						break
					}
				}
				if !isMember {
					matchAll = false
				}
			case strings.HasPrefix(m, tagPrefix):
				var hasTag bool
				for _, t := range info.Node.Tags {
					if t == m {
						hasTag = true
						break
					}
				}
				if !hasTag {
					matchAll = false
				}
			case strings.Contains(m, "@"):
				if m != info.UserProfile.LoginName {
					matchAll = false
				}
			default:
				matchAll = false
			}
			if !matchAll {
				break
			}
		}
		if matchAll {
			if p.Policy == PolicyAllow {
				allow = true
			} else if p.Policy == PolicyDeny {
				allow = false
			}
			break
		}
	}

	if !allow {
		return caddyauth.User{}, false, nil
	}

	user := caddyauth.User{
		ID: info.UserProfile.LoginName,
		Metadata: map[string]string{
			"login":           info.UserProfile.LoginName,
			"name":            info.UserProfile.DisplayName,
			"profile_pic_url": info.UserProfile.ProfilePicURL,
			"tailnet":         tailnet,
			"node_name":       info.Node.Name,
			"node_tags":       strings.Join(info.Node.Tags, ","),
		},
	}
	ta.logger.Debug("tailscale auth successful", zap.Any("user", user))
	return user, true, nil
}

// UnmarshalCaddyfile implements caddyfile.Unmarshaler.
func (ta *TailscaleAuth) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if !d.Args(&ta.ExpectedTailnet) {
			return d.ArgErr()
		}
	}
	return nil
}

// parseCaddyfile sets up the handler from Caddyfile tokens. Syntax:
//
//	tailscaleauth [<expected_tailnet>] [<default policy allow|deny>] {
//	    <policy> <login>
//	    <policy> tag:<tag> tag:<tag>
//	    <policy> group:<group>
//	}
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	ta := TailscaleAuth{
		DefaultPolicy: PolicyAllow,
	}
	ta.TailscaleAPIRefreshInterval, _ = h.Option(globalKeyTailscaleAPIRefreshInterval).(time.Duration)
	if ta.TailscaleAPIRefreshInterval == 0 {
		ta.TailscaleAPIRefreshInterval = defaultTailscaleAPIRefreshInterval
	}
	ta.APITailnet, _ = h.Option(globalKeyTailscaleAPITailnet).(string)
	ta.TailscaleOAuthClientID, _ = h.Option(globalKeyTailscaleOAuthClientID).(string)
	ta.TailscaleOAuthClientSecret, _ = h.Option(globalKeyTailscaleOAuthClientSecret).(string)
	ta.Groups, _ = h.Option(globalKeyTailscaleGroups).(map[string][]string)
	for h.Next() {
		args := h.RemainingArgs()

		switch len(args) {
		case 0:
		case 1:
			ta.ExpectedTailnet = args[0]
		case 2:
			ta.ExpectedTailnet = args[0]
			switch args[1] {
			case PolicyAllow, PolicyDeny:
				ta.DefaultPolicy = args[1]
			default:
				return nil, h.Errf("unknown policy: %s", args[1])
			}
		default:
			return nil, h.ArgErr()
		}

		for h.NextBlock(0) {
			policy := h.Val()
			if policy == "" {
				return nil, h.Err("policy cannot be empty or is missing")
			}
			var matches []string
			for h.NextArg() {
				name := h.Val()
				if name == "" {
					break
				}
				matches = append(matches, name)
			}
			if len(matches) == 0 {
				return nil, h.Err("name or tags required")
			}
			switch policy {
			case PolicyAllow, PolicyDeny:
			default:
				return nil, h.Errf("unknown policy: %s", policy)
			}
			ta.Policies = append(ta.Policies, PolicyMatches{
				Policy:  policy,
				Matches: matches,
			})
		}
	}

	return caddyauth.Authentication{
		ProvidersRaw: caddy.ModuleMap{
			"tailscale": caddyconfig.JSON(&ta, nil),
		},
	}, nil
}

func parseSimpleValue(d *caddyfile.Dispenser, _ interface{}) (interface{}, error) {
	replacer := caddy.NewReplacer()
	d.Next() // consume parameter name
	if !d.Next() {
		return "", d.ArgErr()
	}
	val := replacer.ReplaceKnown(d.Val(), "")
	if d.Next() {
		return "", d.ArgErr()
	}
	return val, nil
}

func parseDurationValue(d *caddyfile.Dispenser, _ interface{}) (interface{}, error) {
	replacer := caddy.NewReplacer()
	d.Next() // consume parameter name
	if !d.Next() {
		return "", d.ArgErr()
	}
	val := replacer.ReplaceKnown(d.Val(), "")
	if d.Next() {
		return "", d.ArgErr()
	}
	dur, err := time.ParseDuration(val)
	if err != nil {
		return "", d.Errf("%q is not a valid duration: %s", err)
	}
	return dur, nil
}

func parseGroups(d *caddyfile.Dispenser, _ interface{}) (interface{}, error) {
	groups := make(map[string][]string)
	for d.Next() {
		for d.NextBlock(0) {
			groupName := d.Val()
			if groupName == "" {
				return nil, d.Err("tailscale group name missing")
			}
			for d.NextBlock(1) {
				member := d.Val()
				if member == "" {
					return nil, d.Err("tailscale group member missing")
				}
				groups[groupName] = append(groups[groupName], member)
			}
		}
	}
	return groups, nil
}

// Interface guards
var (
	_ caddy.Provisioner       = (*TailscaleAuth)(nil)
	_ caddyauth.Authenticator = (*TailscaleAuth)(nil)
	_ caddyfile.Unmarshaler   = (*TailscaleAuth)(nil)
)
