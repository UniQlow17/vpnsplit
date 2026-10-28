//go:build !linux

package router

import (
	"errors"

	"github.com/UniQlow17/vpnsplit/internal/config"
)

// Policy routing rules exist on Linux only: Windows and macOS decide by the
// longest prefix and the metric, so a VPN client cannot hide a route.

func addRule(config.Rule) error {
	return errors.New("policy routing rules are not supported on this OS")
}
func delRule(config.Rule) error    { return nil }
func listRules() ([]OSRule, error) { return nil, nil }
