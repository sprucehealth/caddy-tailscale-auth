# Tailscale authentication plugin for Caddy

This package provides a module for Caddy that implements authentication using the
Tailscale network (Tailnet). When a connection comes in over a Tailnet information
about the remote party is available such as the user account (for personal devices)
and tags (for non-personal "tagged" devices). This information can then be used to
limit access to routes.

# Building

The [xcaddy](https://github.com/caddyserver/xcaddy) tool can be used to build Caddy
to include this plugin:

    xcaddy build --with github.com/sprucehealth/caddy-tailscale-auth
