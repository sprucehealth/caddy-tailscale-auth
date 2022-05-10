package caddytailscaleauth

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp/caddyauth"
	"go.uber.org/zap"
	"tailscale.com/client/tailscale"
)

func init() {
	caddy.RegisterModule(TailscaleAuth{})
}

type TailscaleAuth struct {
	ExpectedTailnet string `json:"expected_tailnet,omitempty"`

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

	user := caddyauth.User{
		ID: info.UserProfile.LoginName,
		Metadata: map[string]string{
			"login":           strings.Split(info.UserProfile.LoginName, "@")[0],
			"name":            info.UserProfile.DisplayName,
			"profile_pic_url": info.UserProfile.ProfilePicURL,
			"tailnet":         tailnet,
		},
	}
	return user, true, nil
}

// Interface guards
var (
	_ caddy.Provisioner       = (*TailscaleAuth)(nil)
	_ caddyauth.Authenticator = (*TailscaleAuth)(nil)
)
