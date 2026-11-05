//go:build !windows && !linux && !darwin

package clientcfg

func readProxy() Proxy { return Proxy{} }

func readGPONRPT() (known bool, rules int) { return false, 0 }
