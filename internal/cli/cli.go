// Package cli implements the vpnsplit command line.
package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/UniQlow17/vpnsplit/internal/config"
	"github.com/UniQlow17/vpnsplit/internal/netif"
	"github.com/UniQlow17/vpnsplit/internal/router"
	"github.com/UniQlow17/vpnsplit/internal/tui"
)

const usage = `vpnsplit - corp traffic through the corp VPN, chosen sites past every VPN, the rest through the home VPN

  vpnsplit [menu]                interactive menu (default)
  vpnsplit list                  show network adapters and the VPN clients behind them
  vpnsplit init                  choose corp / home VPN (default: detect automatically)
  vpnsplit add <cidr|ip|domain|AS>...        send these to the corp VPN
                                 (AS49675 = every network the AS announces, from RIPE)
  vpnsplit add --direct <cidr|ip|domain>...  send these past every VPN (Wi-Fi/Ethernet)
  vpnsplit remove [--direct] <cidr|ip|domain>...
  vpnsplit rules                 show current rules
  vpnsplit import <file>         add the rules of a rules file (from export or someone else)
  vpnsplit export [file]         write the rules as a rules file (stdout by default)
  vpnsplit set <key> <value>     corp | home (auto, client or adapter name),
                                 corp-dns | corp-gateway ("none" clears),
                                 home-default | split-dns (yes/no, true/false, 1/0, on/off, да/нет)
  vpnsplit apply                 add routes and leave them in place (needs admin/root)
  vpnsplit watch                 keep routes in sync when VPNs connect, switch or disconnect;
                                 routes stay after Ctrl+C
  vpnsplit run                   like watch, but a session: everything is removed when it ends
                                 (SIGINT/SIGTERM/SIGHUP, console closed), or by the next start
                                 if it was killed; for scripts and services
  vpnsplit status                show what is connected and what vpnsplit added
  vpnsplit reset [--purge] [--force]
                                 remove ALL routes added by this tool and restore original
                                 routing (--purge also deletes config.json; --force removes
                                 the journal's routes even if it thinks the computer was
                                 restarted since)
  vpnsplit version

Only routes created by vpnsplit are ever touched; the system default route
and the VPN clients' own routes are never modified.`

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
	case "import":
		return cmdImport(rest)
	case "export":
		return cmdExport(rest)
	case "set":
		return cmdSet(rest)
	case "apply":
		return needAdmin(cmdApply)
	case "watch":
		return needAdmin(func() error { return cmdSync(config.ModePersistent) })
	case "run":
		return needAdmin(func() error { return cmdSync(config.ModeSession) })
	case "status":
		return cmdStatus()
	case "reset":
		o, err := parseReset(rest)
		if err != nil {
			return err
		}
		return needAdmin(func() error { return cmdReset(router.NewManager(), o, os.Stdout) })
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

// loadConfig loads the config and tells about every value dropped as invalid.
func loadConfig() (*config.Config, error) {
	cfg, warns, err := config.LoadChecked()
	printWarnings(warns)
	return cfg, err
}

func printWarnings(warns []string) {
	for _, w := range warns {
		fmt.Fprintln(os.Stderr, "warning:", w)
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
		fmt.Fprintf(w, "%-12s %-5s %-9s %-20s %-16s %s\n", i.Name, state, i.Kind, i.Provider, strings.Join(i.Addrs, ","), i.Desc)
	}
	fmt.Fprintln(w, "\nkind: corp? = corporate VPN, vpn = other tunnel; the client name is detected from the app behind the adapter")
	if !router.IsPrivileged() {
		fmt.Fprintln(w, "tip: some VPN clients are recognised reliably only with admin rights (", router.PrivHint, ")")
	}
	return nil
}

// selector is what gets saved for an adapter: the VPN client name when it is
// known (it survives reconnects onto another adapter), else the adapter name.
func selector(i netif.Info) string {
	if i.Provider != "" {
		return i.Provider
	}
	return i.Name
}

func cmdInit(r io.Reader, w io.Writer) error {
	ifs, err := netif.List()
	if err != nil {
		return err
	}
	var vpns []netif.Info
	for _, i := range ifs {
		if i.Connected() && (i.Kind == netif.KindCorp || i.Kind == netif.KindVPN) {
			vpns = append(vpns, i)
		}
	}
	in := bufio.NewReader(r)
	pick := func(title string, hint netif.Kind) (string, error) {
		fmt.Fprintf(w, "\n%s\n", title)
		fmt.Fprintf(w, "    0) auto: detect the connected VPN every time (recommended)\n")
		for n, i := range vpns {
			mark := " "
			if i.Kind == hint {
				mark = "*"
			}
			fmt.Fprintf(w, " %s %2d) %-28s %s\n", mark, n+1, i.Label(), strings.Join(i.Addrs, ","))
		}
		fmt.Fprint(w, "number, VPN client or adapter name [0]: ")
		line, _ := in.ReadString('\n')
		line = strings.TrimSpace(line)
		if n, e := strconv.Atoi(line); e == nil && n >= 1 && n <= len(vpns) {
			return selector(vpns[n-1]), nil
		}
		if line == "" || line == "0" {
			return netif.Auto, nil
		}
		return line, nil
	}
	cfg, err := loadConfig()
	if err != nil {
		cfg = config.New()
	}
	if cfg.Corp, err = pick("CORPORATE VPN, * = looks corporate:", netif.KindCorp); err != nil {
		return err
	}
	if cfg.Home, err = pick("HOME VPN, * = looks like a home VPN:", netif.KindVPN); err != nil {
		return err
	}
	if cfg.Corp == cfg.Home && !netif.IsAuto(cfg.Corp) {
		return fmt.Errorf("corp and home VPN must differ")
	}
	if err := config.Save(cfg); err != nil {
		return err
	}
	fmt.Fprintln(w, "\nsaved. Next: vpnsplit add 10.0.0.0/8 corp.example.com ; vpnsplit add --direct bank.example.ru ; sudo vpnsplit apply")
	return nil
}

func cmdRules(op string, items []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	direct := len(items) > 0 && items[0] == "--direct"
	if direct {
		items = items[1:]
	}
	if len(items) == 0 {
		return fmt.Errorf("usage: vpnsplit %s [--direct] <cidr|ip|domain>...", op)
	}
	nets, domains := cfg.Lists(direct)
	for _, it := range items {
		isNet, v, err := config.NormalizeRule(it)
		if err != nil {
			return err
		}
		list := domains
		if isNet {
			list = nets
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
	fmt.Println("saved. Run `vpnsplit apply` to activate (watch and the menu's auto mode pick it up by themselves).")
	return nil
}

func cmdRulesShow() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	fmt.Println("corp networks:  ", strings.Join(cfg.Networks, ", "))
	fmt.Println("corp domains:   ", strings.Join(cfg.Domains, ", "))
	fmt.Println("direct networks:", strings.Join(cfg.DirectNetworks, ", "))
	fmt.Println("direct domains: ", strings.Join(cfg.DirectDomains, ", "))
	return nil
}

func cmdImport(a []string) error {
	if len(a) != 1 {
		return fmt.Errorf("usage: vpnsplit import <file>")
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	b, err := os.ReadFile(a[0])
	if err != nil {
		return err
	}
	added, errs := cfg.ImportRules(string(b))
	for _, e := range errs {
		fmt.Println("  skipped:", e)
	}
	if err := config.Save(cfg); err != nil {
		return err
	}
	fmt.Printf("imported %d new rules. Run `vpnsplit apply` to activate (watch and the menu's auto mode pick it up by themselves).\n", added)
	return nil
}

func cmdExport(a []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	if len(a) == 0 {
		fmt.Print(cfg.ExportRules())
		return nil
	}
	return config.WriteUserFile(a[0], []byte(cfg.ExportRules()))
}

func cmdSet(a []string) error {
	if len(a) != 2 {
		return fmt.Errorf("usage: vpnsplit set <corp|home|corp-dns|corp-gateway|home-default|split-dns> <value>")
	}
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	val := a[1]
	if val == "none" {
		val = ""
	}
	switch a[0] {
	case "corp", "home":
		if val != "" && !config.ValidIface(val) {
			return fmt.Errorf("invalid %s value %q", a[0], val)
		}
		if a[0] == "corp" {
			cfg.Corp = val
		} else {
			cfg.Home = val
		}
	case "corp-dns", "corp-gateway":
		if val != "" {
			ip, err := config.ParseIPv4(val)
			if err != nil {
				return fmt.Errorf("%s: %w", a[0], err)
			}
			val = ip
		}
		if a[0] == "corp-dns" {
			cfg.CorpDNS = val
		} else {
			cfg.CorpGateway = val
		}
	case "home-default", "split-dns":
		b, err := config.ParseBool(a[1])
		if err != nil {
			return fmt.Errorf("%s: %w", a[0], err)
		}
		if a[0] == "home-default" {
			cfg.HomeDefault = b
		} else {
			cfg.SplitDNS = b
		}
	default:
		return fmt.Errorf("unknown key %q", a[0])
	}
	return config.Save(cfg)
}

func cmdStatus() error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}
	e := router.Detect(cfg)
	line := func(role, sel string, ok bool, i netif.Info) {
		got := "not connected"
		if ok {
			got = i.Label()
		}
		fmt.Printf("%s: %-14s -> %s\n", role, sel, got)
	}
	line("corp", cfg.Corp, e.CorpOK, e.Corp)
	line("home", cfg.Home, e.HomeOK, e.Home)
	if e.GWOK {
		fmt.Printf("direct: %s via %s\n", e.GW.Iface, e.GW.Router)
	} else {
		fmt.Println("direct: no Wi-Fi/Ethernet gateway found")
	}
	fmt.Printf("corp-dns=%q corp-gateway=%q home-default=%v split-dns=%v\n", cfg.CorpDNS, cfg.CorpGateway, cfg.HomeDefault, cfg.SplitDNS)
	st, warns, jstatus := config.LoadStateStatus()
	printWarnings(warns)
	switch jstatus {
	case config.JournalDenied:
		fmt.Printf("journal of applied routes: available only with administrator rights (%s); what is applied is unknown\n", router.PrivHint)
		return nil
	case config.JournalUnreadable:
		fmt.Println("journal of applied routes: cannot be read (see the warnings above); what is applied is unknown")
		return nil
	}
	printOwner(os.Stdout, st)
	printLastSession(os.Stdout)
	fmt.Printf("routes owned by vpnsplit: %d\n", len(st.Routes))
	for _, r := range st.Routes {
		fmt.Printf("  %-18s -> %-6s %s\n", r.Dest, r.Via, r.Iface)
	}
	for _, p := range st.Resolvers {
		fmt.Printf("  dns file %s\n", p)
	}
	if apply, _ := router.Sync(cfg, e, st); apply && !st.Empty() {
		fmt.Println("connections or rules changed since the last apply: run apply again (or use watch)")
	}
	return nil
}

// parseReset reads the flags of `reset`.
func parseReset(args []string) (resetOpts, error) {
	var o resetOpts
	for _, a := range args {
		switch a {
		case "--purge":
			o.purge = true
		case "--force":
			o.force = true
		default:
			return o, fmt.Errorf("usage: vpnsplit reset [--purge] [--force] (unknown argument %q)", a)
		}
	}
	return o, nil
}
