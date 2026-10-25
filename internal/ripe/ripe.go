// Package ripe turns autonomous system numbers ("AS49675") into the IPv4
// networks they announce, using RIPEstat.
package ripe

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/UniQlow17/vpnsplit/internal/config"
)

const (
	api      = "https://stat.ripe.net/data/announced-prefixes/data.json?resource="
	cacheTTL = 24 * time.Hour
)

var client = &http.Client{Timeout: 15 * time.Second}

type entry struct {
	Prefixes []string  `json:"prefixes"`
	Fetched  time.Time `json:"fetched"`
}

// Prefixes returns the IPv4 networks as announces, merged into as few as
// possible. Answers are cached for a day; when RIPE cannot be reached the last
// answer is used however old, and fetched tells when it was received.
func Prefixes(as string) (nets []string, fetched time.Time, err error) {
	as = strings.ToUpper(as)
	cache := map[string]entry{}
	_ = config.LoadJSON("ripe-cache.json", &cache)
	old, cached := cache[as]
	if cached && time.Since(old.Fetched) < cacheTTL {
		return old.Prefixes, old.Fetched, nil
	}
	nets, err = fetch(as)
	if err != nil {
		if cached {
			return old.Prefixes, old.Fetched, nil
		}
		return nil, time.Time{}, err
	}
	cache[as] = entry{nets, time.Now()}
	_ = config.SaveJSON("ripe-cache.json", cache)
	return nets, time.Now(), nil
}

func fetch(as string) ([]string, error) {
	resp, err := client.Get(api + as)
	if err != nil {
		return nil, fmt.Errorf("RIPE: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("RIPE: %s", resp.Status)
	}
	var r struct {
		Data struct {
			Prefixes []struct{ Prefix string } `json:"prefixes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil, fmt.Errorf("RIPE: %w", err)
	}
	var all []string
	for _, p := range r.Data.Prefixes {
		all = append(all, p.Prefix)
	}
	nets := Collapse(all)
	if len(nets) == 0 {
		return nil, fmt.Errorf("RIPE: %s announces no IPv4 networks", as)
	}
	return nets, nil
}

// Collapse merges IPv4 networks into the fewest covering exactly the same
// addresses; IPv6 and malformed entries are dropped.
func Collapse(cidrs []string) []string {
	type block struct {
		start uint32
		bits  int
	}
	var bs []block
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil || n.IP.To4() == nil {
			continue
		}
		bits, _ := n.Mask.Size()
		bs = append(bs, block{binary.BigEndian.Uint32(n.IP.To4()), bits})
	}
	size := func(b block) uint64 { return 1 << (32 - b.bits) }
	sort.Slice(bs, func(i, j int) bool {
		return bs[i].start < bs[j].start || bs[i].start == bs[j].start && bs[i].bits < bs[j].bits
	})
	var out []block
	for _, b := range bs {
		if n := len(out); n > 0 && uint64(b.start) < uint64(out[n-1].start)+size(out[n-1]) {
			continue // inside the previous block
		}
		out = append(out, b)
		// two halves of a bigger aligned block become that block
		for n := len(out); n >= 2; n = len(out) {
			a, c := out[n-2], out[n-1]
			if a.bits != c.bits || a.bits == 0 || uint64(a.start)+size(a) != uint64(c.start) ||
				uint64(a.start)%(2*size(a)) != 0 {
				break
			}
			out = append(out[:n-2], block{a.start, a.bits - 1})
		}
	}
	res := make([]string, len(out))
	for i, b := range out {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, b.start)
		res[i] = fmt.Sprintf("%s/%d", ip, b.bits)
	}
	return res
}
