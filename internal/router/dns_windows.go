//go:build windows

package router

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

func ps(script string) ([]byte, error) {
	out, err := exec.Command("powershell", "-NoProfile", "-Command", script).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s", strings.TrimSpace(string(out)))
	}
	return out, nil
}

// psQuote makes s safe inside a single-quoted PowerShell string.
func psQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", "''") + "'" }

func psList(items []string) string {
	q := make([]string, len(items))
	for i, s := range items {
		q[i] = psQuote(s)
	}
	return strings.Join(q, ",")
}

// corpDNS: the DNS servers and suffixes the corp client set on its adapter.
func corpDNS(iface string) (servers, zones []string) {
	out, err := ps("$a=" + psQuote(iface) + "; " +
		"$s=@((Get-DnsClientServerAddress -InterfaceAlias $a -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses); " +
		"$c=Get-DnsClient -InterfaceAlias $a -ErrorAction SilentlyContinue; " +
		"$d=@(@($c.ConnectionSpecificSuffix) + @($c.ConnectionSpecificSuffixSearchList) | Where-Object { $_ }); " +
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

const nrptComment = "vpnsplit"

func addResolver(zone string, servers []string) error {
	out, err := ps("@(Get-DnsClientNrptRule | Where-Object { $_.Namespace -contains " + psQuote("."+zone) + " }).Count")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(out)) != "0" {
		return fmt.Errorf("an NRPT rule for %s exists, left as is", zone)
	}
	_, err = ps("Add-DnsClientNrptRule -Namespace " + psList([]string{"." + zone, zone}) +
		" -NameServers " + psList(servers) + " -Comment " + psQuote(nrptComment))
	return err
}

func delResolver(zone string) error {
	_, err := ps("Get-DnsClientNrptRule | Where-Object { $_.Comment -eq " + psQuote(nrptComment) +
		" -and $_.Namespace -contains " + psQuote("."+zone) + " } | Remove-DnsClientNrptRule -Force")
	return err
}

func flushDNS() { _, _ = ps("Clear-DnsClientCache") }
