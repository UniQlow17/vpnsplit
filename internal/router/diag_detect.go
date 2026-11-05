package router

import (
	"fmt"
	"net/netip"
	"runtime"
	"sort"
	"strings"

	"github.com/UniQlow17/vpnsplit/internal/clientcfg"
	"github.com/UniQlow17/vpnsplit/internal/config"
	"github.com/UniQlow17/vpnsplit/internal/netif"
	"github.com/UniQlow17/vpnsplit/internal/ripe"
)

func goos() string { return runtime.GOOS }

func ripeCached(as string) ([]string, bool) { return ripe.Cached(as) }

// diagIn is everything the detectors look at; they are pure functions of it,
// so tests give them tables, rules, config texts and command output.
type diagIn struct {
	goos   string
	cfg    *config.Config
	env    Env
	st     *config.State
	tbl    *table
	rs     *ruleSet
	cl     clientcfg.Result
	asNets func(as string) ([]string, bool) // the networks of an AS from the cache; nil: none known
}

// maxDiagLines bounds the findings of one kind that list items (overlaps).
const maxDiagLines = 4

// diagnose runs all the detectors. Each detector returns nothing for what it
// cannot judge (an unknown table, a client that is not there).
func diagnose(in diagIn) []Diag {
	if in.cfg == nil {
		return nil
	}
	if in.tbl == nil {
		in.tbl = &table{byKey: map[rkey]OSRoute{}}
	}
	if in.rs == nil {
		in.rs = &ruleSet{}
	}
	var out []Diag
	for _, f := range []func(diagIn) []Diag{
		diagProxy, diagTunCfgs, diagFullTunnels, diagBlockOutsideDNS, diagGPO,
		diagOverlaps, diagEndpoint, diagBigDirect, diagHyperV, diagCorpOnLink,
	} {
		out = append(out, f(in)...)
	}
	diagSort(out)
	return out
}

// subj makes a name from the OS fit to be put into a message.
func subj(s string) string { return printable(strings.TrimSpace(s)) }

// --- 1. the proxy mode ---

func diagProxy(in diagIn) []Diag {
	p := in.cl.Proxy
	if !in.env.Any() || !p.On() {
		return nil
	}
	what, whatRU := "", ""
	switch {
	case p.Enabled && p.PAC != "":
		what, whatRU = fmt.Sprintf("%s and a script %s", p.Server, p.PAC), fmt.Sprintf("%s и скрипт %s", p.Server, p.PAC)
	case p.Enabled:
		what, whatRU = p.Server, p.Server
	default:
		what, whatRU = "script "+p.PAC, "скрипт "+p.PAC
	}
	return []Diag{{
		Code: "PROXY_ON", Level: DiagWarn,
		TextEN:   fmt.Sprintf("a system proxy is on (%s, read from %s): programs that use it send their traffic to the proxy, whatever the routes say", what, p.Source),
		TextRU:   fmt.Sprintf("включён системный прокси (%s, прочитано из %s): программы, которые им пользуются, шлют трафик в прокси независимо от маршрутов", whatRU, p.Source),
		AdviceEN: "turn off the \"system proxy\" / Proxy mode in the VPN client and use its TUN mode; vpnsplit does not change the proxy settings",
		AdviceRU: "выключите «системный прокси» / режим «Прокси» в клиенте и используйте его режим TUN; vpnsplit настройки прокси не меняет",
	}}
}

// --- 2. sing-box, Hiddify, Mihomo ---

func diagTunCfgs(in diagIn) []Diag {
	if !in.env.Any() {
		return nil // the files may be old: only a VPN in use makes them matter
	}
	var out []Diag
	var strict, fake []string
	var ranges []string
	hasDomains := len(in.cfg.Domains)+len(in.cfg.DirectDomains)+len(in.cfg.HomeDomains) > 0
	for _, c := range in.cl.Tun {
		if c.Tun && c.StrictRoute {
			strict = config.AddUnique(strict, c.Client)
		}
		if c.FakeIP {
			fake = config.AddUnique(fake, c.Client)
			for _, r := range c.FakeRanges {
				ranges = config.AddUnique(ranges, r.String())
			}
		}
	}
	if len(strict) > 0 {
		who := strings.Join(strict, ", ")
		out = append(out, Diag{
			Code: "STRICT_ROUTE", Level: DiagWarn,
			TextEN:   fmt.Sprintf("%s: the TUN has strict_route on: the client may block traffic that goes around its tunnel (other adapters, local routes), and routes made for \"direct\" and corp networks can be cut off", who),
			TextRU:   fmt.Sprintf("%s: у TUN включён strict_route: клиент может блокировать трафик мимо своего туннеля (другие адаптеры, локальные маршруты), и маршруты «напрямую» и корпоративные могут не работать", who),
			AdviceEN: "turn strict_route off in the client's TUN settings if the direct or corp traffic does not pass",
			AdviceRU: "выключите strict_route в настройках TUN клиента, если трафик «напрямую» или корпоративный не проходит",
		})
	}
	if len(fake) > 0 {
		who := strings.Join(fake, ", ")
		lvl := DiagInfo
		if hasDomains {
			lvl = DiagWarn
		}
		extra, extraRU := "", ""
		if len(ranges) > 0 {
			extra = " (range " + strings.Join(ranges, ", ") + " is not routed)"
			extraRU = " (диапазон " + strings.Join(ranges, ", ") + " не маршрутизируется)"
		}
		out = append(out, Diag{
			Code: "FAKE_IP", Level: lvl,
			TextEN:   fmt.Sprintf("%s: the DNS of the client answers with fake addresses (fake-ip)%s: a rule by domain cannot be turned into the real address, the answer is dropped", who, extra),
			TextRU:   fmt.Sprintf("%s: DNS клиента отвечает фиктивными адресами (fake-ip)%s: правило по домену не превратить в настоящий адрес, такие ответы отбрасываются", who, extraRU),
			AdviceEN: "use networks or AS numbers instead of domains for the rules, or ask the corp/provider DNS directly (vpnsplit does that); or switch the client's DNS to redir-host / normal",
			AdviceRU: "задавайте сети или AS вместо доменов или спрашивайте DNS корпорации/провайдера напрямую (vpnsplit так и делает); либо переключите DNS клиента на redir-host / обычный",
		})
	}
	return out
}

// --- 3 and 6. full tunnels: WireGuard, the corp VPN ---

// fullTunnel says how an adapter takes all the traffic.
type fullTunnel struct {
	iface string
	how   string // "0.0.0.0/0", "0.0.0.0/1 + 128.0.0.0/1" or "policy table N"
}

// fullTunnels finds the adapters that take every packet by a route of a client
// (not ours): a default route in the main table that is not worse than the
// best default route of another adapter, the two halves of the address space, or
// a default route in the table that a diverting rule sends all traffic to (wg-quick,
// sing-box).
func fullTunnels(tbl *table, rs *ruleSet, st *config.State) []fullTunnel {
	if tbl == nil || !tbl.known {
		return nil
	}
	type acc struct {
		def, h0, h128 bool
		defTbl        int
		bestMetric    int
	}
	divTables := map[int]bool{}
	if rs != nil && rs.known {
		for _, d := range diverting(rs.all) {
			divTables[d.Table] = true
		}
	}
	// the best (lowest) total metric of the default routes of the main table, per adapter
	best := map[string]int{}
	for _, r := range tbl.all {
		if r.Table == 0 && !r.Ours && r.Dest.Addr().Is4() && r.Dest.Bits() == 0 && r.Iface != "" {
			m := r.Metric + r.IfMetric
			if cur, ok := best[r.Iface]; !ok || m < cur {
				best[r.Iface] = m
			}
		}
	}
	mine := map[[2]string]bool{} // routes of the journal (destination, adapter): ours, where the OS has no tag
	if st != nil {
		for _, r := range st.Routes {
			mine[[2]string{r.Dest, r.Iface}] = true
		}
	}
	by := map[string]*acc{}
	get := func(i string) *acc {
		if by[i] == nil {
			by[i] = &acc{}
		}
		return by[i]
	}
	for _, r := range tbl.all {
		if r.Ours || mine[[2]string{r.Dest.String(), r.Iface}] || r.Iface == "" || !r.Dest.Addr().Is4() || r.Dest.Bits() > 1 || config.IsOwnTable(r.Table) {
			continue
		}
		if r.Table != 0 && !divTables[r.Table] {
			continue // a table nothing sends all traffic to
		}
		a := get(r.Iface)
		switch {
		case r.Dest.Bits() == 0:
			if r.Table == 0 {
				// does not count where another adapter has a better default route
				win := true
				for o, m := range best {
					if o != r.Iface && m < r.Metric+r.IfMetric {
						win = false
					}
				}
				if !win {
					continue
				}
			}
			a.def, a.defTbl = true, r.Table
		case r.Dest.Addr() == netip.AddrFrom4([4]byte{}):
			a.h0 = true
		default:
			a.h128 = true
		}
	}
	var out []fullTunnel
	for i, a := range by {
		switch {
		case a.def && a.defTbl != 0:
			out = append(out, fullTunnel{i, fmt.Sprintf("policy table %d", a.defTbl)})
		case a.def:
			out = append(out, fullTunnel{i, "0.0.0.0/0"})
		case a.h0 && a.h128:
			out = append(out, fullTunnel{i, "0.0.0.0/1 + 128.0.0.0/1"})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].iface < out[j].iface })
	return out
}

func isWireGuard(i netif.Info) bool {
	n := strings.ToLower(i.Name)
	return i.Provider == "WireGuard" || strings.HasPrefix(n, "wg") || strings.Contains(strings.ToLower(i.Desc), "wireguard")
}

// corpTunnelMatters says whether a full tunnel of the corp VPN clashes with
// what the user asked for: rules of the kinds that count (direct, home) that
// have something in them, or the rest of the traffic sent to the home VPN or
// past the VPNs.
func corpTunnelMatters(in diagIn) bool {
	cfg, e := in.cfg, in.env
	kinds := cfg.Kinds()
	for _, k := range []string{config.DestDirect, config.DestHome} {
		if !has(kinds, k) {
			continue
		}
		if nets, doms := cfg.ListsOf(k); nets != nil && doms != nil && len(*nets)+len(*doms) > 0 {
			return true
		}
	}
	return cfg.Rest == config.RestHome && e.HomeOK || cfg.Rest == config.RestDirect && e.GWOK
}

func diagFullTunnels(in diagIn) []Diag {
	var out []Diag
	e := in.env
	for _, ft := range fullTunnels(in.tbl, in.rs, in.st) {
		info, ok := netif.FindIn(e.Ifs, ft.iface)
		if !ok || !info.Connected() {
			continue
		}
		name := subj(info.Label())
		switch {
		case e.CorpOK && ft.iface == e.Corp.Name:
			if !corpTunnelMatters(in) {
				// all goes to the company anyway and no rule asks for another way: a note
				out = append(out, Diag{
					Code: "CORP_FULL_TUNNEL", Level: DiagInfo,
					TextEN: fmt.Sprintf("the corp VPN %s takes all the traffic (%s); no \"direct\" or home rules and no redirected rest are set, so nothing competes with it", name, ft.how),
					TextRU: fmt.Sprintf("корпоративный VPN %s забирает весь трафик (%s); правил «напрямую» и «через домашний VPN» и перенаправления остального нет, так что конкурировать с ним нечему", name, ft.how),
				})
				break
			}
			out = append(out, Diag{
				Code: "CORP_FULL_TUNNEL", Level: DiagWarn,
				TextEN:   fmt.Sprintf("the corp VPN %s takes all the traffic (%s): the rest of the Internet goes through the company, the direct and home rules compete with its routes", name, ft.how),
				TextRU:   fmt.Sprintf("корпоративный VPN %s забирает весь трафик (%s): остальной интернет идёт через компанию, правила «напрямую» и «через домашний VPN» конкурируют с его маршрутами", name, ft.how),
				AdviceEN: "ask for (or switch on) split tunnelling in the corp client; if it is enforced by the company, the direct and home rules may not work",
				AdviceRU: "включите (или запросите у администратора) раздельное туннелирование в корп. клиенте; если его навязывает компания, правила «напрямую» и «через домашний VPN» могут не сработать",
			})
		case isWireGuard(info) && e.HomeOK && ft.iface == e.Home.Name:
			out = append(out, Diag{
				Code: "WG_FULL_TUNNEL", Level: DiagInfo,
				TextEN:   fmt.Sprintf("WireGuard %s has AllowedIPs 0.0.0.0/0 (%s): it takes all the traffic by its own routes, vpnsplit adds nothing of its own for the rest", name, ft.how),
				TextRU:   fmt.Sprintf("у WireGuard %s AllowedIPs 0.0.0.0/0 (%s): он забирает весь трафик своими маршрутами, для «остального» vpnsplit ничего не добавляет", name, ft.how),
				AdviceEN: "nothing to do: the corp and direct routes are placed so that they win over the tunnel",
				AdviceRU: "делать ничего не нужно: корп. и прямые маршруты ставятся так, чтобы быть главнее туннеля",
			})
		case isWireGuard(info):
			out = append(out, Diag{
				Code: "WG_FULL_TUNNEL", Level: DiagWarn,
				TextEN:   fmt.Sprintf("WireGuard %s (not the corp or home VPN of vpnsplit) has AllowedIPs 0.0.0.0/0 (%s): it takes all the traffic and competes with the routes of both", name, ft.how),
				TextRU:   fmt.Sprintf("WireGuard %s (не корп. и не домашний VPN для vpnsplit) с AllowedIPs 0.0.0.0/0 (%s): забирает весь трафик и конкурирует с маршрутами обоих", name, ft.how),
				AdviceEN: "disconnect it, or choose it as the home VPN in the settings",
				AdviceRU: "отключите его или выберите домашним VPN в настройках",
			})
		}
	}
	if e.CorpOK && in.cl.CiscoFailClosed && e.Corp.Provider == "Cisco Secure Client" {
		out = append(out, Diag{
			Code: "CORP_LOCKDOWN", Level: DiagWarn,
			TextEN:   fmt.Sprintf("the profile of %s fails closed (ConnectFailurePolicy Closed): when the tunnel is down, the client cuts the network", subj(e.Corp.Label())),
			TextRU:   fmt.Sprintf("профиль %s блокирует сеть при обрыве туннеля (ConnectFailurePolicy Closed): без туннеля клиент отключает сеть", subj(e.Corp.Label())),
			AdviceEN: "vpnsplit cannot override this: direct and home traffic may stop when the corp VPN drops",
			AdviceRU: "vpnsplit это не обходит: при обрыве корп. VPN трафик «напрямую» и домашний тоже может перестать ходить",
		})
	} else if e.CorpOK && in.cl.CiscoAlwaysOn && e.Corp.Provider == "Cisco Secure Client" {
		out = append(out, Diag{
			Code: "CORP_LOCKDOWN", Level: DiagInfo,
			TextEN: fmt.Sprintf("the profile of %s has AlwaysOn: the client reconnects by itself, routes will have to be re-applied after every reconnect", subj(e.Corp.Label())),
			TextRU: fmt.Sprintf("в профиле %s включён AlwaysOn: клиент переподключается сам, маршруты придётся применять заново после каждого переподключения", subj(e.Corp.Label())),
		})
	}
	return out
}

// --- 4. block-outside-dns ---

func diagBlockOutsideDNS(in diagIn) []Diag {
	if in.cl.OvpnBlockDNS == "" {
		return nil
	}
	ovpn := false
	for _, i := range in.env.Ifs {
		if i.Connected() && i.Provider == "OpenVPN" {
			ovpn = true
		}
	}
	if !ovpn {
		return nil
	}
	// The filters of the firewall (WFP) that the option sets cannot be read in a
	// reliable way; the config or the log of the client shows that they are asked for.
	return []Diag{{
		Code: "BLOCK_OUTSIDE_DNS", Level: DiagInfo,
		TextEN:   fmt.Sprintf("OpenVPN has block-outside-dns (found in %s): DNS queries that do not go through the tunnel are blocked, so the names that go direct (provider DNS) and the split DNS of other adapters may not resolve", subj(in.cl.OvpnBlockDNS)),
		TextRU:   fmt.Sprintf("в OpenVPN включён block-outside-dns (найдено в %s): DNS-запросы мимо туннеля блокируются, поэтому имена «напрямую» (DNS провайдера) и split DNS других адаптеров могут не резолвиться", subj(in.cl.OvpnBlockDNS)),
		AdviceEN: "remove block-outside-dns from the config (or the pushed options) if names do not resolve; this is a guess from the config, not from the firewall",
		AdviceRU: "уберите block-outside-dns из конфига (или из push-опций сервера), если имена не резолвятся; это вывод по конфигу, а не по состоянию файрвола",
	}}
}

// --- 5. NRPT from Group Policy ---

func diagGPO(in diagIn) []Diag {
	if in.goos != "windows" || !in.cl.GPOKnown || in.cl.GPONRPT == 0 {
		return nil
	}
	return []Diag{{
		Code: "GPO_NRPT", Level: DiagDanger,
		TextEN:   fmt.Sprintf("Group Policy sets %d NRPT rule(s): Windows then ignores the local NRPT, including the rules of vpnsplit (corp zones and \".\" for the home VPN)", in.cl.GPONRPT),
		TextRU:   fmt.Sprintf("групповая политика задаёт правил NRPT: %d; Windows тогда игнорирует локальную NRPT, в том числе правила vpnsplit (корп. зоны и «.» для домашнего VPN)", in.cl.GPONRPT),
		AdviceEN: "split DNS will not work: use IP/CIDR/AS rules, or ask the administrator to add the zones to the policy",
		AdviceRU: "split DNS работать не будет: используйте правила по IP/CIDR/AS или попросите администратора добавить зоны в политику",
	}}
}

// --- 7. overlapping networks ---

// ruleNet is a network of a rule with the adapter its traffic is meant for.
type ruleNet struct {
	p      netip.Prefix
	kind   string // config.DestCorp, DestDirect, DestHome
	target string // the adapter of that kind ("" if not connected)
}

// ruleNets lists the networks of the rules that are in force: the ones that
// are written out in the rules of the kinds that matter, and the networks of
// the corp rules in the journal (AS and domains, resolved when they were applied).
func ruleNets(in diagIn) []ruleNet {
	var out []ruleNet
	kinds := in.cfg.Kinds()
	seen := map[ruleNet]bool{}
	add := func(p netip.Prefix, kind, target string) {
		r := ruleNet{p.Masked(), kind, target}
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	e := in.env
	if e.CorpOK {
		for _, p := range literalNets(in.cfg.Networks) {
			add(p, config.DestCorp, e.Corp.Name)
		}
	}
	if e.GWOK && has(kinds, config.DestDirect) {
		for _, p := range literalNets(in.cfg.DirectNetworks) {
			add(p, config.DestDirect, e.GW.Iface)
		}
	}
	if e.HomeOK && has(kinds, config.DestHome) {
		for _, p := range literalNets(in.cfg.HomeNetworks) {
			add(p, config.DestHome, e.Home.Name)
		}
	}
	if in.st != nil {
		for _, r := range in.st.Routes {
			if r.Via != ViaCorp || e.Corp.Name == "" || r.Iface != e.Corp.Name {
				continue
			}
			if p, err := netip.ParsePrefix(r.Dest); err == nil && p.Addr().Is4() && p.Bits() < 32 {
				add(p, config.DestCorp, e.Corp.Name)
			}
		}
	}
	return out
}

var wellKnownNets = []struct {
	p      netip.Prefix
	en, ru string
}{
	{netip.MustParsePrefix("100.64.0.0/10"), "100.64.0.0/10 (CGNAT, Tailscale)", "100.64.0.0/10 (CGNAT, Tailscale)"},
	{netip.MustParsePrefix("172.17.0.0/16"), "172.17.0.0/16 (Docker)", "172.17.0.0/16 (Docker)"},
	{netip.MustParsePrefix("198.18.0.0/15"), "198.18.0.0/15 (tests, fake-ip of clients)", "198.18.0.0/15 (тесты, fake-ip клиентов)"},
}

func diagOverlaps(in diagIn) []Diag {
	e := in.env
	rules := ruleNets(in)
	kindRU := map[string]string{config.DestCorp: "корп.", config.DestDirect: "«напрямую»", config.DestHome: "«через домашний VPN»"}
	var lan, ad []string
	var lanRU, adRU []string
	reported := map[netip.Prefix]bool{} // well-known zones that an adapter sits in and a rule overlaps: said already
	for _, r := range rules {
		for _, i := range e.Ifs {
			if !i.Up || i.Name == r.target {
				continue
			}
			for _, n := range i.Nets {
				if !r.p.Overlaps(n) {
					continue
				}
				for _, w := range wellKnownNets {
					if w.p.Overlaps(n) {
						reported[w.p] = true
					}
				}
				s := fmt.Sprintf("%s rule %s overlaps %s of %s", r.kind, r.p, n, subj(i.Name))
				sRU := fmt.Sprintf("правило %s %s пересекается с %s на %s", kindRU[r.kind], r.p, n, subj(i.Name))
				if e.GWOK && i.Name == e.GW.Iface {
					lan, lanRU = append(lan, s+" (your local network)"), append(lanRU, sRU+" (ваша локальная сеть)")
				} else {
					ad, adRU = append(ad, s), append(adRU, sRU)
				}
			}
		}
	}
	var out []Diag
	if len(lan) > 0 {
		out = append(out, Diag{
			Code: "OVERLAP_LAN", Level: DiagWarn,
			TextEN:   joinLimited(lan, "; ", maxDiagLines, false),
			TextRU:   joinLimited(lanRU, "; ", maxDiagLines, true),
			AdviceEN: "hosts of your local network and of the rule cannot both be reached: narrow the rule or change the network of the router",
			AdviceRU: "хосты вашей локальной сети и правила не будут доступны одновременно: сузьте правило или смените сеть роутера",
		})
	}
	if len(ad) > 0 {
		out = append(out, Diag{
			Code: "OVERLAP_ADAPTER", Level: DiagWarn,
			TextEN:   joinLimited(ad, "; ", maxDiagLines, false),
			TextRU:   joinLimited(adRU, "; ", maxDiagLines, true),
			AdviceEN: "the more specific route wins: traffic to the hosts of that network may go to the wrong adapter; narrow the rule",
			AdviceRU: "побеждает более точный маршрут: трафик в ту сеть может уйти не на тот адаптер; сузьте правило",
		})
	}
	// well-known zones: a rule over them clashes with whatever is there when it starts
	var wk, wkRU []string
	for _, r := range rules {
		for _, w := range wellKnownNets {
			if reported[w.p] || !r.p.Overlaps(w.p) || r.p.Bits() >= 32 {
				continue
			}
			wk = append(wk, fmt.Sprintf("%s rule %s overlaps %s", r.kind, r.p, w.en))
			wkRU = append(wkRU, fmt.Sprintf("правило %s %s пересекается с %s", kindRU[r.kind], r.p, w.ru))
		}
	}
	if len(wk) > 0 {
		out = append(out, Diag{
			Code: "OVERLAP_WELLKNOWN", Level: DiagInfo,
			TextEN:   joinLimited(wk, "; ", maxDiagLines, false),
			TextRU:   joinLimited(wkRU, "; ", maxDiagLines, true),
			AdviceEN: "Tailscale, Docker and VPN clients use these networks: when they start, their addresses and the rule overlap",
			AdviceRU: "Tailscale, Docker и VPN-клиенты используют эти сети: при их запуске адреса и правило пересекутся",
		})
	}
	// the networks of the VPNs with the local network, and with each other
	type named struct {
		role string
		i    netif.Info
	}
	var ends []named
	if e.CorpOK {
		ends = append(ends, named{"corp VPN", e.Corp})
	}
	if e.HomeOK {
		ends = append(ends, named{"home VPN", e.Home})
	}
	if e.GWOK {
		if i, ok := netif.FindIn(e.Ifs, e.GW.Iface); ok {
			ends = append(ends, named{"local network", i})
		}
	}
	var vl, vlRU []string
	for a := 0; a < len(ends); a++ {
		for b := a + 1; b < len(ends); b++ {
			for _, na := range ends[a].i.Nets {
				for _, nb := range ends[b].i.Nets {
					if na.Overlaps(nb) {
						vl = append(vl, fmt.Sprintf("%s (%s of %s) overlaps %s (%s of %s)", ends[a].role, na, subj(ends[a].i.Name), ends[b].role, nb, subj(ends[b].i.Name)))
						vlRU = append(vlRU, fmt.Sprintf("%s (%s на %s) пересекается: %s (%s на %s)", roleRU(ends[a].role), na, subj(ends[a].i.Name), roleRU(ends[b].role), nb, subj(ends[b].i.Name)))
					}
				}
			}
		}
	}
	if len(vl) > 0 {
		out = append(out, Diag{
			Code: "OVERLAP_VPN_LAN", Level: DiagWarn,
			TextEN:   joinLimited(vl, "; ", maxDiagLines, false),
			TextRU:   joinLimited(vlRU, "; ", maxDiagLines, true),
			AdviceEN: "the addresses of two networks are the same: routing cannot tell their hosts apart; change the subnet of one of them",
			AdviceRU: "адреса двух сетей совпадают: маршрутизация не отличит их хосты; смените подсеть одной из них",
		})
	}
	return out
}

func roleRU(r string) string {
	switch r {
	case "corp VPN":
		return "корп. VPN"
	case "home VPN":
		return "домашний VPN"
	}
	return "локальная сеть"
}

// joinLimited joins at most n items and says how many were left out.
func joinLimited(items []string, sep string, n int, ru bool) string {
	if len(items) <= n {
		return strings.Join(items, sep)
	}
	return strings.Join(items[:n], sep) + fmt.Sprintf(word(ru, "; and %d more", "; и ещё %d"), len(items)-n)
}

// --- 8. a corp rule over the address of a VPN server ---

func diagEndpoint(in diagIn) []Diag {
	e := in.env
	if !e.CorpOK || in.tbl == nil || !in.tbl.known {
		return nil
	}
	cands := endpointCandidates(e, in.tbl, in.st)
	if len(cands) == 0 {
		return nil
	}
	var hits, hitsRU []string
	for _, r := range ruleNets(in) {
		if r.kind != config.DestCorp {
			continue
		}
		for _, a := range cands {
			if r.p.Contains(a) {
				hits = append(hits, fmt.Sprintf("corp rule %s covers %s", r.p, a))
				hitsRU = append(hitsRU, fmt.Sprintf("корп. правило %s накрывает %s", r.p, a))
			}
		}
	}
	if len(hits) == 0 {
		return nil
	}
	return []Diag{{
		Code: "ENDPOINT_COVERED", Level: DiagWarn,
		TextEN:   joinLimited(hits, "; ", maxDiagLines, false) + ": the address of a VPN server: its packets would go into the corp tunnel (the tunnel would carry its own packets)",
		TextRU:   joinLimited(hitsRU, "; ", maxDiagLines, true) + ": это адрес сервера VPN, его пакеты ушли бы в корп. туннель (туннель вёз бы собственные пакеты)",
		AdviceEN: "vpnsplit does not apply such a rule; exclude the server from the rule (a narrower network) or keep it out of the corp list",
		AdviceRU: "vpnsplit такое правило не применяет; исключите адрес сервера из правила (сеть поуже) или уберите правило из корп. списка",
	}}
}

// --- 9. CDN and big AS in "direct" ---

// bigAS are autonomous systems of CDNs and clouds: thousands of unrelated sites
// share their addresses, so a "direct" rule for one takes along sites that
// should go through a VPN (and the ones that only work through it).
var bigAS = map[string]string{
	"AS13335": "Cloudflare", "AS209242": "Cloudflare",
	"AS20940": "Akamai", "AS16625": "Akamai", "AS12222": "Akamai", "AS35994": "Akamai", "AS34164": "Akamai",
	"AS15169": "Google", "AS396982": "Google Cloud", "AS19527": "Google", "AS36040": "Google",
	"AS16509": "Amazon", "AS14618": "Amazon", "AS8987": "Amazon",
	"AS8075": "Microsoft", "AS8068": "Microsoft", "AS8069": "Microsoft",
	"AS54113": "Fastly", "AS32934": "Meta", "AS14061": "DigitalOcean", "AS16276": "OVH", "AS24940": "Hetzner",
	"AS31898": "Oracle Cloud", "AS45102": "Alibaba Cloud", "AS132203": "Tencent Cloud", "AS22822": "Edgio",
	"AS19551": "Imperva", "AS60068": "CDN77", "AS199524": "G-Core", "AS714": "Apple", "AS2906": "Netflix",
}

// bigDirectAddrs is the size of the direct rules in addresses above which they are
// reported: a /10 (4 194 304 addresses).
const bigDirectAddrs = 1 << 22

func diagBigDirect(in diagIn) []Diag {
	if !has(in.cfg.Kinds(), config.DestDirect) || len(in.cfg.DirectNetworks) == 0 {
		return nil
	}
	var names, namesRU []string
	nets := []string{}
	for _, r := range in.cfg.DirectNetworks {
		if config.IsAS(r) {
			as := strings.ToUpper(strings.TrimSpace(r))
			if n, ok := bigAS[as]; ok {
				names = append(names, fmt.Sprintf("%s (%s)", as, n))
				namesRU = append(namesRU, fmt.Sprintf("%s (%s)", as, n))
			}
			if in.asNets != nil {
				if l, ok := in.asNets(as); ok {
					nets = append(nets, l...)
				}
			}
			continue
		}
		if p, err := config.ParseCIDR(r); err == nil {
			nets = append(nets, p.Masked().String())
		}
	}
	var total uint64
	for _, c := range ripe.Collapse(nets) {
		if p, err := netip.ParsePrefix(c); err == nil && p.Addr().Is4() {
			total += 1 << (32 - p.Bits())
		}
	}
	var out []Diag
	if len(names) > 0 {
		sort.Strings(names)
		out = append(out, Diag{
			Code: "DIRECT_CDN_AS", Level: DiagWarn,
			TextEN:   fmt.Sprintf("direct rules include a CDN or cloud AS: %s; many sites share these addresses, they all go past the VPN", joinLimited(names, ", ", 6, false)),
			TextRU:   fmt.Sprintf("в правилах «напрямую» есть AS CDN или облака: %s; на этих адресах сидят множество сайтов, все они пойдут мимо VPN", joinLimited(namesRU, ", ", 6, true)),
			AdviceEN: "list the domains or networks you need instead of the whole AS",
			AdviceRU: "укажите нужные домены или сети вместо всей AS целиком",
		})
	}
	if total > bigDirectAddrs {
		out = append(out, Diag{
			Code: "DIRECT_BIG", Level: DiagWarn,
			TextEN:   fmt.Sprintf("direct rules cover about %s addresses (more than a /10): a large part of the Internet goes past the VPN", millions(total)),
			TextRU:   fmt.Sprintf("правила «напрямую» покрывают около %s адресов (больше /10): значительная часть интернета пойдёт мимо VPN", millions(total)),
			AdviceEN: "narrow the list; the size is counted from the networks written out and the AS lists already fetched from RIPE",
			AdviceRU: "сузьте список; размер считается по записанным сетям и уже загруженным из RIPE спискам AS",
		})
	}
	return out
}

func millions(n uint64) string {
	return fmt.Sprintf("%.1f million", float64(n)/1e6)
}

// --- 10. Wi-Fi behind a Hyper-V switch ---

func diagHyperV(in diagIn) []Diag {
	if in.goos != "windows" || in.tbl == nil || !in.tbl.known {
		return nil
	}
	e := in.env
	var best *OSRoute
	for i, r := range in.tbl.routes {
		if r.Dest.Addr().Is4() && r.Dest.Bits() == 0 && r.Gateway.IsValid() && r.Iface != "" && !r.Ours &&
			strings.Contains(strings.ToLower(r.Iface), "vethernet") {
			if best == nil || r.Metric+r.IfMetric < best.Metric+best.IfMetric {
				best = &in.tbl.routes[i]
			}
		}
	}
	if best == nil {
		return nil
	}
	name := subj(best.Iface)
	if !e.GWOK {
		return []Diag{{
			Code: "HYPERV_UPLINK", Level: DiagWarn,
			TextEN:   fmt.Sprintf("the default route goes through %s: the physical adapter is probably behind a Hyper-V virtual switch, and vpnsplit takes only physical adapters, so no uplink for \"direct\" was found", name),
			TextRU:   fmt.Sprintf("маршрут по умолчанию идёт через %s: физический адаптер, вероятно, за виртуальным коммутатором Hyper-V, а vpnsplit выбирает только физические адаптеры, поэтому шлюз для «напрямую» не найден", name),
			AdviceEN: "the detection of the physical adapter can be wrong here: direct rules are skipped; connect without the vSwitch, or tell the author",
			AdviceRU: "определение физического адаптера здесь может ошибаться: правила «напрямую» пропускаются; подключитесь без vSwitch или сообщите автору",
		}}
	}
	if best.Metric+best.IfMetric <= bestDefaultMetric(in.tbl, e.GW.Iface) {
		return []Diag{{
			Code: "HYPERV_UPLINK", Level: DiagWarn,
			TextEN:   fmt.Sprintf("the default route through %s is better than the one through %s, which vpnsplit uses for \"direct\": the Wi-Fi/Ethernet is probably behind a Hyper-V switch, the detection of the physical adapter can be wrong", name, subj(e.GW.Iface)),
			TextRU:   fmt.Sprintf("маршрут по умолчанию через %s лучше, чем через %s, который vpnsplit использует для «напрямую»: Wi-Fi/Ethernet, вероятно, за коммутатором Hyper-V, определение физического адаптера может ошибаться", name, subj(e.GW.Iface)),
			AdviceEN: "check that \"direct\" traffic leaves through the right adapter",
			AdviceRU: "проверьте, что трафик «напрямую» уходит через нужный адаптер",
		}}
	}
	return nil
}

// bestDefaultMetric is the lowest total metric of the default routes of iface (a big number if none).
func bestDefaultMetric(t *table, iface string) int {
	best := 1 << 30
	for _, r := range t.routes {
		if r.Iface == iface && r.Dest.Addr().Is4() && r.Dest.Bits() == 0 {
			best = min(best, r.Metric+r.IfMetric)
		}
	}
	return best
}

// --- 11. the corp gateway without a next hop ---

// corpRoutesPlanned says whether vpnsplit makes (or has made) routes into the corp VPN.
func corpRoutesPlanned(in diagIn) bool {
	if len(in.cfg.Networks)+len(in.cfg.Domains) > 0 {
		return true
	}
	if in.st != nil {
		for _, r := range in.st.Routes {
			if r.Via == ViaCorp {
				return true
			}
		}
	}
	return false
}

func diagCorpOnLink(in diagIn) []Diag {
	e := in.env
	if !e.CorpOK || in.cfg.CorpGateway != "" || in.tbl == nil || !in.tbl.known || !corpRoutesPlanned(in) {
		return nil // with no corp route of ours the lack of a next hop changes nothing
	}
	own := map[netip.Prefix]bool{} // the networks the adapter is in: their routes are on-link by nature
	for _, p := range e.Corp.Nets {
		own[p.Masked()] = true
	}
	n := 0
	for _, r := range in.tbl.all {
		if r.Iface == e.Corp.Name && !r.Ours && !r.Gateway.IsValid() && r.Dest.Addr().Is4() && r.Dest.Bits() > 1 && r.Dest.Bits() < 32 && !own[r.Dest.Masked()] && !config.IsOwnTable(r.Table) {
			n++
		}
	}
	if n == 0 {
		return nil
	}
	return []Diag{{
		Code: "CORP_ONLINK", Level: DiagInfo,
		TextEN: fmt.Sprintf("the corp VPN %s has no next hop (point-to-point / on-link): its routes have no gateway, and the routes of vpnsplit for it are made without one", subj(e.Corp.Label())),
		TextRU: fmt.Sprintf("у корп. VPN %s нет следующего узла (point-to-point / on-link): его маршруты без шлюза, и маршруты vpnsplit для него тоже делаются без шлюза", subj(e.Corp.Label())),
	}}
}
