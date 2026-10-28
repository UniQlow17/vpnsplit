//go:build windows

package router

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/UniQlow17/vpnsplit/internal/config"
	"github.com/UniQlow17/vpnsplit/internal/sysexec"
)

// psStop starts every script: an error stops it and fails the call instead of
// being printed and forgotten (the exit code is then non-zero).
const psStop = "$ErrorActionPreference='Stop'; "

// nrptHas is the filter on the namespace $z of a rule: a rule is written as
// ".zone" (what we create) but read back as either form, so both are compared.
const nrptHas = "($_.Namespace -contains ('.'+$z) -or $_.Namespace -contains $z)"

// ps runs a PowerShell script (see sysexec.PowerShell: system binary, minimal
// environment). The script text is always a constant: every value reaches it
// through an environment variable ($env:VS_...), so no data can ever be
// parsed as PowerShell code, whatever quotes it contains.
func ps(env map[string]string, script string) ([]byte, error) {
	cmd := sysexec.PowerShell(psStop+script, env)
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
	if !validNrptID(zone) {
		return fmt.Errorf("invalid DNS zone %q", zone)
	}
	if err := config.ValidateServers(servers); err != nil {
		return err
	}
	env := map[string]string{"ZONE": zone, "SERVERS": strings.Join(servers, ",")}
	// a rule of somebody else stays; a rule with our comment is a leftover of
	// ours (the journal was lost) and is replaced, not left behind for ever
	out, err := ps(env, "$z=$env:VS_ZONE; @(Get-DnsClientNrptRule | Where-Object { "+nrptHas+" -and $_.Comment -ne 'vpnsplit' }).Count")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(out)) != "0" {
		return fmt.Errorf("%w: an NRPT rule for %s exists, left as is", errResolverExists, zone)
	}
	_, err = ps(env, "$z=$env:VS_ZONE; Get-DnsClientNrptRule | Where-Object { $_.Comment -eq 'vpnsplit' -and "+nrptHas+" } | "+
		"Remove-DnsClientNrptRule -Force; "+
		"if ($z -eq '.') { $ns=@('.') } else { $ns=@(('.'+$z),$z) }; "+
		"Add-DnsClientNrptRule -Namespace $ns -NameServers ($env:VS_SERVERS -split ',') -Comment 'vpnsplit'")
	return err
}

func delResolver(zone string) error {
	if !validNrptID(zone) {
		return fmt.Errorf("invalid DNS zone %q", zone)
	}
	_, err := ps(map[string]string{"ZONE": zone},
		"$z=$env:VS_ZONE; Get-DnsClientNrptRule | Where-Object { $_.Comment -eq 'vpnsplit' -and "+nrptHas+" } | "+
			"Remove-DnsClientNrptRule -Force")
	return err
}

// DelResolvers removes every NRPT rule with our comment in one PowerShell call
// (a process per zone takes about a second each, which a cleanup with a few
// seconds to live cannot afford). The rules with our comment are all ours
// whatever the journal lists, and a rule without it is never touched. ids are
// only checked: an entry that would not be valid is an error, as in delResolver.
func (osBackend) DelResolvers(ids []string) error {
	for _, id := range ids {
		if !validNrptID(id) {
			return fmt.Errorf("invalid DNS zone %q", id)
		}
	}
	_, err := ps(nil, "Get-DnsClientNrptRule | Where-Object { $_.Comment -eq 'vpnsplit' } | Remove-DnsClientNrptRule -Force")
	return err
}

// MissingResolvers lists the zones of the journal that have no NRPT rule of ours
// any more (one PowerShell call for all of them).
func (osBackend) MissingResolvers(ids []string) ([]string, error) {
	out, err := ps(nil, "ConvertTo-Json -Compress @(Get-DnsClientNrptRule | Where-Object { $_.Comment -eq 'vpnsplit' } | "+
		"ForEach-Object { $_.Namespace } | Where-Object { $_ })")
	if err != nil {
		return nil, err
	}
	have, err := parseNrptNamespaces(out)
	if err != nil {
		return nil, err
	}
	var missing []string
	for _, id := range ids {
		if !have[nrptNamespace(id)] {
			missing = append(missing, id)
		}
	}
	return missing, nil
}

// parseNrptNamespaces reads the JSON list (or a single string, which is how
// PowerShell writes a one-element array) of NRPT namespaces.
func parseNrptNamespaces(out []byte) (map[string]bool, error) {
	out = bytes.TrimSpace(out)
	var list []string
	if len(out) == 0 {
		return map[string]bool{}, nil
	}
	if out[0] == '"' {
		var one string
		if err := json.Unmarshal(out, &one); err != nil {
			return nil, err
		}
		list = []string{one}
	} else if err := json.Unmarshal(out, &list); err != nil {
		return nil, err
	}
	have := map[string]bool{}
	for _, n := range list {
		have[strings.ToLower(n)] = true
	}
	return have, nil
}

func flushDNS() { _, _ = ps(nil, "Clear-DnsClientCache") }

// ListResolvers lists the NRPT rules of the computer: the zone (the first
// namespace without its dot), the name servers and the comment. A rule with
// our comment is ours.
func (osBackend) ListResolvers() ([]OSResolver, error) {
	out, err := ps(nil, "ConvertTo-Json -Compress -Depth 3 @(Get-DnsClientNrptRule | ForEach-Object { "+
		"@{ n = (@($_.Namespace) -join ','); s = (@($_.NameServers) -join ','); c = [string]$_.Comment } })")
	if err != nil {
		return nil, err
	}
	return parseNrptRules(out)
}

// parseNrptRules reads the JSON of ListResolvers: a list, or a single object
// (how PowerShell writes a one-element array).
func parseNrptRules(out []byte) ([]OSResolver, error) {
	out = bytes.TrimSpace(out)
	if len(out) == 0 {
		return nil, nil
	}
	type rule struct{ N, S, C string }
	var list []rule
	if out[0] == '{' {
		var one rule
		if err := json.Unmarshal(out, &one); err != nil {
			return nil, err
		}
		list = []rule{one}
	} else if err := json.Unmarshal(out, &list); err != nil {
		return nil, err
	}
	var res []OSResolver
	for _, r := range list {
		id := r.N
		for _, ns := range strings.Split(r.N, ",") {
			if ns == "." {
				id = "."
				break
			}
			if strings.HasPrefix(ns, ".") {
				id = strings.TrimPrefix(ns, ".")
				break
			}
		}
		res = append(res, OSResolver{ID: strings.ToLower(id), Detail: "servers " + r.S + " comment " + strconv.Quote(r.C), Ours: r.C == nrptComment})
	}
	return res, nil
}

// nrptComment marks the NRPT rules vpnsplit creates.
const nrptComment = "vpnsplit"

// validNrptID: a zone, or "." for the rule that sends everything else to the DNS of the home VPN.
func validNrptID(id string) bool { return id == "." || config.ValidZone(id) }

// nrptNamespace is the namespace the rule of an entry has when it is read back.
func nrptNamespace(id string) string {
	if id == "." {
		return "."
	}
	return "." + id
}

// restDNS: Windows sends everything else to the home DNS through the NRPT rule ".".
const restDNS = true
