package caddytailscaleauth

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	lru "github.com/hashicorp/golang-lru"
	"go.uber.org/zap"
	"tailscale.com/client/tailscale"
	"tailscale.com/tailcfg"
)

const defaultTailscaleAPIRefreshInterval = time.Minute * 10

const capCacheSize = 100

const (
	globalKeyTailscaleAPIRefreshInterval = "tailscale_api_refresh_interval"
	globalKeyTailscaleAPITailnet         = "tailscale_api_tailnet"
	globalKeyTailscaleOAuthClientID      = "tailscale_oauth_client_id"
	globalKeyTailscaleOAuthClientSecret  = "tailscale_oauth_client_secret"
)

func init() {
	caddy.RegisterModule(&TailscaleAuth{})
	httpcaddyfile.RegisterHandlerDirective("tailscaleauth", parseCaddyfile)
	httpcaddyfile.RegisterGlobalOption(globalKeyTailscaleAPIRefreshInterval, parseDurationValue)
	httpcaddyfile.RegisterGlobalOption(globalKeyTailscaleAPITailnet, parseSimpleValue)
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
	CapabilityName              string              `json:"capability_name,omitempty"`
	Policies                    []PolicyMatches     `json:"policies,omitempty"`
	Groups                      map[string][]string `json:"groups,omitempty"`
	TailscaleAPIRefreshInterval time.Duration       `json:"tailscale_api_refresh_interval,omitempty"`
	TailscaleOAuthClientID      string              `json:"tailscale_oauth_client_id,omitempty"`
	TailscaleOAuthClientSecret  string              `json:"tailscale_oauth_client_secret,omitempty"`

	logger    *zap.Logger
	tlc       tailscale.LocalClient
	tc        *tailscaleClient
	needGroup bool
	capCache  *lru.Cache
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
	if ta.CapabilityName != "" {
		var err error
		ta.capCache, err = lru.New(capCacheSize)
		if err != nil {
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
	if ta.TailscaleOAuthClientID != "" {
		tailnet := ta.APITailnet
		if tailnet == "" {
			tailnet = ta.ExpectedTailnet
		}
		var err error
		ta.tc, err = newTailscaleClient(ctx, ta.TailscaleOAuthClientID, ta.TailscaleOAuthClientSecret, tailnet, ta.logger)
		if err != nil {
			return err
		}
		// If groups are not static then start a processes to periodically
		// fetch the groups from the ACL.
		if ta.needGroup {
			if err := ta.tc.startFetchingGroups(ctx, ta.TailscaleAPIRefreshInterval); err != nil {
				return err
			}
		}
	}
	return nil
}

func (ta *TailscaleAuth) Cleanup() error {
	if ta.tc == nil {
		return nil
	}
	return ta.tc.release()
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

	info, err := ta.tlc.WhoIs(r.Context(), remoteAddr.String())
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
		ta.logger.Warn("user is part of unexpected tailnet",
			zap.String("expected_tailnet", ta.ExpectedTailnet),
			zap.String("unexpected_tailnet", tailnet))
		return caddyauth.User{}, false, nil
	}

	var groups map[string][]string
	if ta.needGroup && ta.tc != nil {
		groups = ta.tc.groups()
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
	if ta.CapabilityName != "" {
		caps, err := ta.capabilitiesFromMap(info.CapMap)
		if err != nil {
			ta.logger.Error("Failed to get capabilities", zap.Error(err))
		} else {
			if caps.defaultAction != "" {
				allow = caps.defaultAction == actionAllow
			}
			for _, ru := range caps.rules {
				// If the rule has methods, then make sure one of them matches
				// the request. Otherwise, skip this rule.
				if len(ru.methods) != 0 {
					var found bool
					for _, m := range ru.methods {
						if m == r.Method {
							found = true
							break
						}
					}
					if !found {
						continue
					}
				}
				if !ru.pathRE.MatchString(r.URL.Path) {
					continue
				}
				allow = ru.action == actionAllow
				ta.logger.Debug("matched capability",
					zap.Any("action", ru.action),
					zap.Any("cap_methods", ru.methods),
					zap.Any("cap_path_re", ru.pathRE),
					zap.String("req_method", r.Method),
					zap.String("req_path", r.URL.Path))
				// Stop at the first matching rule.
				break
			}
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

func (ta *TailscaleAuth) capabilitiesFromMap(capMap tailcfg.PeerCapMap) (*compiledCapabilities, error) {
	caps := capMap[tailcfg.PeerCapability(ta.CapabilityName)]
	if len(caps) == 0 {
		return &compiledCapabilities{}, nil
	}
	if v, ok := ta.capCache.Get(caps[0]); ok {
		return v.(*compiledCapabilities), nil
	}
	ta.logger.Debug("parsing capabilities", zap.String("json", string(caps[0])))
	ccaps, err := parseCapabilities(caps[0])
	if err != nil {
		return nil, err
	}
	// TODO: cache the failure so we don't keep trying with the same input?
	ta.capCache.Add(caps[0], ccaps)
	return ccaps, nil
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
//	tailscaleauth [<expected_tailnet>] [<default policy allow|deny>] [<capability name>] {
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
	for h.Next() {
		args := h.RemainingArgs()

		if len(args) > 3 {
			return nil, h.ArgErr()
		}

		if len(args) >= 1 {
			ta.ExpectedTailnet = args[0]
		}
		if len(args) >= 2 {
			ta.ExpectedTailnet = args[0]
			switch args[1] {
			case PolicyAllow, PolicyDeny:
				ta.DefaultPolicy = args[1]
			default:
				if len(args) == 3 {
					return nil, h.Errf("unknown policy: %s", args[1])
				}
				ta.CapabilityName = args[1]
			}
			if len(args) == 3 {
				ta.CapabilityName = args[2]
			}
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

func parseSimpleValue(d *caddyfile.Dispenser, _ any) (any, error) {
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

func parseDurationValue(d *caddyfile.Dispenser, _ any) (any, error) {
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
		return "", d.Errf("%q is not a valid duration: %s", val, err)
	}
	return dur, nil
}

// Interface guards
var (
	_ caddy.Provisioner       = (*TailscaleAuth)(nil)
	_ caddy.CleanerUpper      = (*TailscaleAuth)(nil)
	_ caddyauth.Authenticator = (*TailscaleAuth)(nil)
	_ caddyfile.Unmarshaler   = (*TailscaleAuth)(nil)
)
