package caddytailscaleauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"tailscale.com/tailcfg"
)

type capabilities struct {
	DefaultAction string           `json:"default_action"`
	Rules         []capabilityRule `json:"rules"`
}

type capabilityRule struct {
	Action  string   `json:"action"`
	PathRE  string   `json:"path_re"`
	Methods []string `json:"method"`
}

type action string

const (
	actionAllow action = "allow"
	actionDeny  action = "deny"
)

func parseAction(s string) (action, error) {
	act := action(strings.ToLower(s))
	switch act {
	case actionAllow, actionDeny:
	default:
		return "", fmt.Errorf("invalid capability action %q", s)
	}
	return act, nil
}

type compiledCapabilities struct {
	defaultAction action
	rules         []*compiledCapabilityRule
}

type compiledCapabilityRule struct {
	action  action
	pathRE  *regexp.Regexp
	methods []string
}

func parseCapabilities(rawCaps tailcfg.RawMessage) (*compiledCapabilities, error) {
	var caps capabilities
	if err := json.Unmarshal([]byte(rawCaps), &caps); err != nil {
		return nil, fmt.Errorf("failed to unmarshal capabilities %q: %w", rawCaps, err)
	}
	cc := &compiledCapabilities{
		rules: make([]*compiledCapabilityRule, 0, len(caps.Rules)),
	}
	if caps.DefaultAction != "" {
		var err error
		cc.defaultAction, err = parseAction(caps.DefaultAction)
		if err != nil {
			return nil, err
		}
	}
	for _, r := range caps.Rules {
		pr, err := regexp.Compile(r.PathRE)
		if err != nil {
			return nil, fmt.Errorf("invalid capability path regular expression %q: %w", r.PathRE, err)
		}
		act, err := parseAction(r.Action)
		if err != nil {
			return nil, err
		}
		for i, m := range r.Methods {
			m = strings.ToUpper(m)
			r.Methods[i] = m
			switch m {
			case http.MethodGet,
				http.MethodHead,
				http.MethodPost,
				http.MethodPut,
				http.MethodPatch,
				http.MethodDelete,
				http.MethodConnect,
				http.MethodOptions,
				http.MethodTrace:
			default:
				return nil, fmt.Errorf("invalid capability method %q", m)
			}
		}
		cc.rules = append(cc.rules, &compiledCapabilityRule{
			action:  act,
			pathRE:  pr,
			methods: r.Methods,
		})
	}
	return cc, nil
}
