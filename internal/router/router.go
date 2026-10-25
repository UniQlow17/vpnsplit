// Package router adds and removes OS routes and keeps a journal of them.
//
// Only routes recorded in the journal are ever removed; the system default
// route and DNS settings are never modified.
package router

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/UniQlow17/vpnsplit/internal/config"
	"github.com/UniQlow17/vpnsplit/internal/netif"
)

// Reset removes every route recorded in the journal and clears it.
// It needs no config, so it works even if config.json is broken or missing.
func Reset() (removed int, errs []error) {
	st := config.LoadState()
	for _, r := range st.Routes {
		if err := delRoute(r); err != nil {
			errs = append(errs, err)
			continue
		}
		removed++
	}
	if len(errs) == 0 {
		_ = config.SaveState(&config.State{})
	}
	return
}

// Apply sends corp networks/domains through the corp adapter and, if
// configured, everything else through the home adapter. Progress goes to w.
func Apply(cfg *config.Config, w io.Writer) error {
	if !netif.Up(cfg.Corp) {
		return fmt.Errorf("corp VPN adapter %q is not up (connect the corporate VPN first)", cfg.Corp)
	}
	if !netif.Up(cfg.Home) {
		return fmt.Errorf("home VPN adapter %q is not up (connect your home VPN first)", cfg.Home)
	}
	if n, errs := Reset(); len(errs) > 0 {
		return fmt.Errorf("could not clear previous routes: %v", errs[0])
	} else if n > 0 {
		fmt.Fprintf(w, "cleared %d previous routes\n", n)
	}

	var routes []config.Route
	corp := func(dest string) {
		routes = append(routes, config.Route{Dest: dest, Iface: cfg.Corp, Gateway: cfg.CorpGateway})
	}
	if cfg.CorpDNS != "" {
		corp(cfg.CorpDNS + "/32") // the corp DNS itself must be reachable through corp
		// install it right away so domain resolution below can use it
		if err := addRoute(routes[0]); err != nil {
			fmt.Fprintf(w, "  ! corp dns route: %v\n", err)
		}
	}
	for _, n := range cfg.Networks {
		corp(n)
	}
	if len(cfg.Domains) > 0 {
		fmt.Fprintln(w, "resolving corp domains...")
		for _, ip := range resolveDomains(cfg.Domains, cfg.CorpDNS, w) {
			corp(ip)
		}
	}
	if cfg.HomeDefault {
		// two halves of the address space beat the default route without touching it
		for _, d := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
			routes = append(routes, config.Route{Dest: d, Iface: cfg.Home})
		}
	}

	// write-ahead journal: if we crash mid-way, Reset still knows what to undo
	if err := config.SaveState(&config.State{Routes: routes}); err != nil {
		return err
	}
	failed := 0
	for _, r := range routes {
		if err := addRoute(r); err != nil {
			failed++
			fmt.Fprintf(w, "  ! %s via %s: %v\n", r.Dest, r.Iface, err)
			continue
		}
		fmt.Fprintf(w, "  + %-18s -> %s\n", r.Dest, r.Iface)
	}
	fmt.Fprintf(w, "done: %d routes added, %d failed. Undo anytime with: vpnsplit reset\n", len(routes)-failed, failed)
	return nil
}

func resolveDomains(domains []string, dns string, w io.Writer) []string {
	res := net.DefaultResolver
	if dns != "" {
		res = &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, "udp", net.JoinHostPort(dns, "53"))
		}}
	}
	var cidrs []string
	for _, d := range domains {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		ips, err := res.LookupIP(ctx, "ip4", d)
		cancel()
		if err != nil {
			fmt.Fprintf(w, "  ! cannot resolve %s: %v\n", d, err)
			continue
		}
		for _, ip := range ips {
			cidrs = config.AddUnique(cidrs, ip.String()+"/32")
		}
	}
	return cidrs
}
