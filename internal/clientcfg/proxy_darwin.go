//go:build darwin

package clientcfg

import "github.com/UniQlow17/vpnsplit/internal/sysexec"

// readProxy asks `scutil --proxy`: the proxy of the network service in use,
// the same for every user of the machine.
func readProxy() Proxy {
	out, err := runLimited(sysexec.Command("scutil", "--proxy"))
	if err != nil {
		return Proxy{}
	}
	return ParseScutilProxy(out)
}

// readGPONRPT: there is no Group Policy for DNS here.
func readGPONRPT() (known bool, rules int) { return false, 0 }
