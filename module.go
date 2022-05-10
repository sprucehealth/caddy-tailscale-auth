package caddytailscaleauth

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	"go.uber.org/zap"
	"tailscale.com/client/tailscale"
)

func init() {
	caddy.RegisterModule(TailscaleAuth{})
	httpcaddyfile.RegisterHandlerDirective("tailscaleauth", parseCaddyfile)
}

const (
	PolicyAllow = "allow"
	PolicyDeny  = "deny"
)

type TailscaleAuth struct {
	ExpectedTailnet string            `json:"expected_tailnet,omitempty"`
	DefaultPolicy   string            `json:"default_policy,omitempty"`
	Policies        map[string]string `json:"policies,omitempty"`

	logger *zap.Logger
}

// CaddyModule returns the Caddy module information.
func (TailscaleAuth) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.authentication.providers.tailscale",
		New: func() caddy.Module { return new(TailscaleAuth) },
	}
}

func (ta *TailscaleAuth) Provision(ctx caddy.Context) error {
	ta.logger = ctx.Logger(ta)
	return nil
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

	if len(info.Node.Tags) != 0 {
		ta.logger.Warn("node is tagged", zap.String("hostname", info.Node.Hostinfo.Hostname()))
		return caddyauth.User{}, false, nil
	}

	_, tailnet, ok := strings.Cut(info.Node.Name, info.Node.ComputedName+".")
	if !ok {
		ta.logger.Error("can't extract tailnet name from hostname", zap.String("hostname", info.Node.Name))
		return caddyauth.User{}, false, nil
	}
	tailnet, _, ok = strings.Cut(tailnet, ".beta.tailscale.net")
	if !ok {
		ta.logger.Error("can't extract tailnet name from hostname", zap.String("hostname", info.Node.Name))
		return caddyauth.User{}, false, nil
	}

	if ta.ExpectedTailnet != "" && ta.ExpectedTailnet != tailnet {
		ta.logger.Warn("user is part of unexpected tailnet", zap.String("expected_tailnet", ta.ExpectedTailnet), zap.String("unexpected_tailnet", tailnet))
		return caddyauth.User{}, false, nil
	}

	allow := ta.DefaultPolicy == PolicyAllow
	for login, policy := range ta.Policies {
		if login == info.UserProfile.LoginName {
			if policy == PolicyAllow {
				allow = true
			} else if policy == PolicyDeny {
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
		},
	}
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
//     tailscaleauth [<expected_tailnet>] [<default policy allow|deny>] {
//         <policy> <login>
//     }
//
// If no hash algorithm is supplied, bcrypt will be assumed.
func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	ta := TailscaleAuth{
		DefaultPolicy: PolicyAllow,
		Policies:      make(map[string]string),
	}
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
			var name string
			if !h.Args(&name) {
				return nil, h.Err("policy and name required")
			}
			if policy == "" || name == "" {
				return nil, h.Err("policy and name cannot be empty or missing")
			}
			switch policy {
			case PolicyAllow, PolicyDeny:
			default:
				return nil, h.Errf("unknown policy: %s", policy)
			}
			ta.Policies[name] = policy
		}
	}

	return caddyauth.Authentication{
		ProvidersRaw: caddy.ModuleMap{
			"tailscale": caddyconfig.JSON(ta, nil),
		},
	}, nil
}

// Interface guards
var (
	_ caddy.Provisioner       = (*TailscaleAuth)(nil)
	_ caddyauth.Authenticator = (*TailscaleAuth)(nil)
	_ caddyfile.Unmarshaler   = (*TailscaleAuth)(nil)
)
