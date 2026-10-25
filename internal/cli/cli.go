// Package cli implements the vpnsplit command line.
package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/UniQlow17/vpnsplit/internal/config"
	"github.com/UniQlow17/vpnsplit/internal/netif"
	"github.com/UniQlow17/vpnsplit/internal/router"
	"github.com/UniQlow17/vpnsplit/internal/tui"
)

const usage = `vpnsplit - route part of traffic through corp VPN, the rest through home VPN

  vpnsplit [menu]                interactive menu (default)
  vpnsplit list                  show network adapters and detected VPNs
  vpnsplit init                  choose corp / home adapters interactively
  vpnsplit add <cidr|ip|domain>...     send these to the corp VPN
  vpnsplit remove <cidr|ip|domain>...
  vpnsplit rules                 show current rules
  vpnsplit set <key> <value>     corp-dns | corp-gateway | home-default (true/false); "none" clears
  vpnsplit apply                 add routes (needs admin/root)
  vpnsplit watch                 keep routes in sync when VPNs connect/disconnect
  vpnsplit status                show config and routes owned by this tool
  vpnsplit reset [--purge]       remove ALL routes added by this tool and
                                 restore original routing (--purge also deletes config)
  vpnsplit version

Only routes created by vpnsplit are ever touched; the system default route,
DNS and VPN clients are never modified.`

// Run executes the command line and returns the process exit code.
func Run(args []string, version string) int {
	if err := run(args, version); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}

func run(args []string, version string) error {
	cmd, rest := "menu", []string(nil)
	if len(args) > 0 {
		cmd, rest = args[0], args[1:]
	}
	switch cmd {
	case "menu":
		return tui.Run()
	case "list":
		return cmdList(os.Stdout)
	case "init":
		return cmdInit(os.Stdin, os.Stdout)
	case "add", "remove":
		return cmdRules(cmd, rest)
	case "rules":
		return cmdRulesShow()
	case "set":
		return cmdSet(rest)
	case "apply":
		return needAdmin(func() error {
			cfg, err := config.Load()
			if err != nil {
				return err
			}
			return router.Apply(cfg, os.Stdout)
		})
	case "watch":
		return needAdmin(cmdWatch)
	case "status":
		return cmdStatus()
	case "reset":
		return needAdmin(func() error { return cmdReset(len(rest) > 0 && rest[0] == "--purge") })
	case "version", "--version", "-v":
		fmt.Println("vpnsplit", version)
		return nil
	case "help", "--help", "-h":
		fmt.Println(usage)
		return nil
	default:
		fmt.Println(usage)
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func needAdmin(f func() error) error {
	if !router.IsPrivileged() {
		return fmt.Errorf("administrator rights required: %s", router.PrivHint)
	}
	return f()
}

func cmdList(w io.Writer) error {
	ifs, err := netif.List()
	if err != nil {
		return err
	}
	for _, i := range ifs {
		state := "down"
		if i.Up {
			state = "up"
		}
		fmt.Fprintf(w, "%-30s %-5s %-9s %-16s %s\n", i.Name, state, i.Kind, strings.Join(i.Addrs, ","), i.Desc)
	}
	fmt.Fprintln(w, "\nkind: corp? = looks like the corporate VPN adapter, vpn = tunnel adapter")
	return nil
}

func cmdInit(r io.Reader, w io.Writer) error {
	ifs, err := netif.List()
	if err != nil {
		return err
	}
	in := bufio.NewReader(r)
	pick := func(title string, hint netif.Kind) (string, error) {
		fmt.Fprintf(w, "\n%s\n", title)
		for n, i := range ifs {
			mark := " "
			if i.Kind == hint {
				mark = "*"
			}
			st := "down"
			if i.Up {
				st = "up"
			}
			fmt.Fprintf(w, " %s %2d) %-28s %-5s %-8s %s %s\n", mark, n+1, i.Name, st, i.Kind, strings.Join(i.Addrs, ","), i.Desc)
		}
		fmt.Fprint(w, "number or exact adapter name (can be one that is not connected yet): ")
		line, _ := in.ReadString('\n')
		line = strings.TrimSpace(line)
		if n, e := strconv.Atoi(line); e == nil && n >= 1 && n <= len(ifs) {
			return ifs[n-1].Name, nil
		}
		if line == "" {
			return "", fmt.Errorf("nothing selected")
		}
		return line, nil
	}
	cfg, err := config.Load()
	if err != nil {
		cfg = config.New()
	}
	if cfg.Corp, err = pick("Select CORPORATE VPN adapter, * = suggested:", netif.KindCorp); err != nil {
		return err
	}
	if cfg.Home, err = pick("Select HOME VPN adapter, * = suggested:", netif.KindVPN); err != nil {
		return err
	}
	if cfg.Corp == cfg.Home {
		return fmt.Errorf("corp and home adapters must differ")
	}
	if err := config.Save(cfg); err != nil {
		return err
	}
	fmt.Fprintln(w, "\nsaved. Next: vpnsplit add 10.0.0.0/8 corp.example.com ; vpnsplit apply")
	return nil
}

func cmdRules(op string, items []string) error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	if len(items) == 0 {
		return fmt.Errorf("usage: vpnsplit %s <cidr|ip|domain>...", op)
	}
	for _, it := range items {
		isNet, v, err := config.NormalizeRule(it)
		if err != nil {
			return err
		}
		list := &cfg.Domains
		if isNet {
			list = &cfg.Networks
		}
		if op == "add" {
			*list = config.AddUnique(*list, v)
		} else {
			var found bool
			if *list, found = config.RemoveVal(*list, v); !found {
				fmt.Printf("%s: not in rules\n", v)
			}
		}
	}
	if err := config.Save(cfg); err != nil {
		return err
	}
	fmt.Println("saved. Run `vpnsplit apply` to activate.")
	return nil
}

func cmdRulesShow() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	fmt.Println("networks:", strings.Join(cfg.Networks, ", "))
	fmt.Println("domains: ", strings.Join(cfg.Domains, ", "))
	return nil
}

func cmdSet(a []string) error {
	if len(a) != 2 {
		return fmt.Errorf("usage: vpnsplit set <corp-dns|corp-gateway|home-default> <value>")
	}
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	val := a[1]
	if val == "none" {
		val = ""
	}
	switch a[0] {
	case "corp-dns":
		cfg.CorpDNS = val
	case "corp-gateway":
		cfg.CorpGateway = val
	case "home-default":
		cfg.HomeDefault = val == "true"
	default:
		return fmt.Errorf("unknown key %q", a[0])
	}
	return config.Save(cfg)
}

func cmdStatus() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	fmt.Printf("corp: %-24s connected=%v\n", cfg.Corp, netif.Up(cfg.Corp))
	fmt.Printf("home: %-24s connected=%v\n", cfg.Home, netif.Up(cfg.Home))
	fmt.Printf("corp-dns=%q corp-gateway=%q home-default=%v\n", cfg.CorpDNS, cfg.CorpGateway, cfg.HomeDefault)
	st := config.LoadState()
	fmt.Printf("routes owned by vpnsplit: %d\n", len(st.Routes))
	for _, r := range st.Routes {
		fmt.Printf("  %-18s -> %s\n", r.Dest, r.Iface)
	}
	return nil
}

func cmdReset(purge bool) error {
	n, errs := router.Reset()
	fmt.Printf("removed %d routes\n", n)
	for _, e := range errs {
		fmt.Println("  !", e)
	}
	if purge {
		if err := config.Remove(); err == nil {
			fmt.Println("config deleted")
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%d routes could not be removed; journal kept, run reset again", len(errs))
	}
	fmt.Println("routing is back to what your VPN clients and OS set up. Reconnect the VPNs if something still looks off.")
	return nil
}

func cmdWatch() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	fmt.Println("watching (Ctrl+C to stop; run `vpnsplit reset` to clean up)...")
	applied := len(config.LoadState().Routes) > 0
	for {
		both := netif.Up(cfg.Corp) && netif.Up(cfg.Home)
		switch {
		case both && !applied:
			fmt.Println(time.Now().Format("15:04:05"), "both VPNs up, applying")
			if err := router.Apply(cfg, os.Stdout); err != nil {
				fmt.Println("  !", err)
			} else {
				applied = true
			}
		case !both && applied:
			fmt.Println(time.Now().Format("15:04:05"), "a VPN went down, removing routes")
			router.Reset()
			applied = false
		}
		time.Sleep(10 * time.Second)
	}
}
