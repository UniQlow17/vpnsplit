//go:build windows

package router

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/UniQlow17/vpnsplit/internal/config"
	"github.com/UniQlow17/vpnsplit/internal/sysexec"
)

// ps runs a PowerShell script (see sysexec.PowerShell: system binary, minimal
// environment). The script text is always a constant: every value reaches it
// through an environment variable ($env:VS_...), so no data can ever be
// parsed as PowerShell code, whatever quotes it contains.
func ps(env map[string]string, script string) ([]byte, error) {
	cmd := sysexec.PowerShell(script, env)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String() + stdout.String())
		if msg == "" {
			msg = err.Error()
		}
		return stdout.Bytes(), errors.New(msg)
	}
	return stdout.Bytes(), nil
}

// corpDNS: the DNS servers and suffixes the corp client set on its adapter.
func corpDNS(iface string) (servers, zones []string) {
	if !config.ValidIface(iface) {
		return nil, nil
	}
	out, err := ps(map[string]string{"IFACE": iface},
		"$a=$env:VS_IFACE; "+
			"$s=@((Get-DnsClientServerAddress -InterfaceAlias $a -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses); "+
			"$c=Get-DnsClient -InterfaceAlias $a -ErrorAction SilentlyContinue; "+
			"$d=@(@($c.ConnectionSpecificSuffix) + @($c.ConnectionSpecificSuffixSearchList) | Where-Object { $_ }); "+
			"ConvertTo-Json -Compress @{s=$s; d=$d}")
	if err != nil {
		return nil, nil
	}
	var r struct{ S, D []string }
	if json.Unmarshal(out, &r) != nil {
		return nil, nil
	}
	return r.S, r.D
}

// resolverPlan: Windows sends a zone to given servers through a Name
// Resolution Policy Table rule; the journal holds the zone, and our rules
// are tagged with a comment so others' rules are never touched.
func resolverPlan(_ string, servers, zones []string) []string {
	if len(servers) == 0 {
		return nil
	}
	return zones
}

func addResolver(zone string, servers []string) error {
	if !config.ValidZone(zone) {
		return fmt.Errorf("invalid DNS zone %q", zone)
	}
	if err := config.ValidateServers(servers); err != nil {
		return err
	}
	env := map[string]string{"ZONE": zone, "SERVERS": strings.Join(servers, ",")}
	out, err := ps(env, "$z=$env:VS_ZONE; @(Get-DnsClientNrptRule | Where-Object { $_.Namespace -contains ('.'+$z) }).Count")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(out)) != "0" {
		return fmt.Errorf("an NRPT rule for %s exists, left as is", zone)
	}
	_, err = ps(env, "$z=$env:VS_ZONE; Add-DnsClientNrptRule -Namespace ('.'+$z),$z "+
		"-NameServers ($env:VS_SERVERS -split ',') -Comment 'vpnsplit'")
	return err
}

func delResolver(zone string) error {
	if !config.ValidZone(zone) {
		return fmt.Errorf("invalid DNS zone %q", zone)
	}
	_, err := ps(map[string]string{"ZONE": zone},
		"$z=$env:VS_ZONE; Get-DnsClientNrptRule | Where-Object { $_.Comment -eq 'vpnsplit' -and $_.Namespace -contains ('.'+$z) } | "+
			"Remove-DnsClientNrptRule -Force")
	return err
}

func flushDNS() { _, _ = ps(nil, "Clear-DnsClientCache") }
