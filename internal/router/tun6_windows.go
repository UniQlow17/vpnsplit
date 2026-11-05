//go:build windows

package router

import (
	"encoding/json"
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/UniQlow17/vpnsplit/internal/config"
)

// Tunnels6 reads the settings of Teredo, 6to4 and ISATAP. A setting that cannot
// be read (the cmdlet is missing on this edition) stays empty: it is not touched.
// A value that is not one the cmdlets are known to take is left out as well and
// named in unknown, so that the report can say it.
func (osBackend) Tunnels6() (config.Tunnels6, []string, error) {
	out, err := ps(nil, "function g($b){ try { [string](& $b) } catch { '' } }; "+
		"ConvertTo-Json -Compress @{ t = g { (Get-NetTeredoConfiguration).Type }; "+
		"s = g { (Get-Net6to4Configuration).State }; i = g { (Get-NetIsatapConfiguration).State } }")
	if err != nil {
		return config.Tunnels6{}, nil, err
	}
	var r struct{ T, S, I string }
	if err := json.Unmarshal(out, &r); err != nil {
		return config.Tunnels6{}, nil, fmt.Errorf("IPv6 tunnel settings: %w", err)
	}
	var t config.Tunnels6
	t.Teredo, t.SixToFour, t.ISATAP = r.T, r.S, r.I
	var unknown []string
	for _, f := range []struct {
		name string
		v    *string
		ok   func(string) (string, bool)
	}{{"Teredo", &t.Teredo, config.CanonTeredo}, {"6to4", &t.SixToFour, config.CanonSixToFour}, {"ISATAP", &t.ISATAP, config.CanonISATAP}} {
		if *f.v == "" {
			continue
		}
		if c, ok := f.ok(*f.v); ok {
			*f.v = c
		} else {
			unknown = append(unknown, fmt.Sprintf("%s %q", f.name, clipValue(*f.v)))
			*f.v = ""
		}
	}
	return t, unknown, nil
}

// clipValue shortens a value of the OS for a message.
func clipValue(s string) string {
	if r := []rune(s); len(r) > 40 {
		return string(r[:40]) + "..."
	}
	return s
}

// SetTunnels6 sets the settings that are not empty. The values are checked
// against the lists of config and reach the script through the environment only.
func (osBackend) SetTunnels6(t config.Tunnels6) error {
	t, err := checkTun6(t)
	if err != nil {
		return err
	}
	if t.Empty() {
		return nil
	}
	env := map[string]string{"TEREDO": t.Teredo, "SIXTOFOUR": t.SixToFour, "ISATAP": t.ISATAP}
	_, err = ps(env, "$e=@(); "+
		"if ($env:VS_TEREDO) { try { Set-NetTeredoConfiguration -Type $env:VS_TEREDO } catch { $e += \"Teredo: $_\" } }; "+
		"if ($env:VS_SIXTOFOUR) { try { Set-Net6to4Configuration -State $env:VS_SIXTOFOUR } catch { $e += \"6to4: $_\" } }; "+
		"if ($env:VS_ISATAP) { try { Set-NetIsatapConfiguration -State $env:VS_ISATAP } catch { $e += \"ISATAP: $_\" } }; "+
		"if ($e.Count -gt 0) { throw ($e -join '; ') }")
	return err
}

var _ tunnels6 = osBackend{}

// physicalDNS reads the IPv4 DNS servers of an adapter from the OS (the
// addresses DHCP of the provider handed out, or the user set).
func physicalDNS(iface string) []string {
	size := uint32(15000)
	for range 3 {
		buf := make([]byte, size)
		aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_INET,
			windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_UNICAST,
			0, aa, &size)
		if err != nil {
			if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
				continue
			}
			return nil
		}
		var out []string
		for a := aa; a != nil; a = a.Next {
			if windows.UTF16PtrToString(a.FriendlyName) != iface {
				continue
			}
			for d := a.FirstDnsServerAddress; d != nil; d = d.Next {
				sa := d.Address.Sockaddr
				if sa == nil || sa.Addr.Family != windows.AF_INET {
					continue
				}
				p := (*syscall.RawSockaddrInet4)(unsafe.Pointer(sa))
				out = append(out, fmt.Sprintf("%d.%d.%d.%d", p.Addr[0], p.Addr[1], p.Addr[2], p.Addr[3]))
			}
		}
		return out
	}
	return nil
}
