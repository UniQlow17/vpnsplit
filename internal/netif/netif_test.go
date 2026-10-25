package netif

import "testing"

func TestClassify(t *testing.T) {
	tests := []struct {
		in   string
		want Kind
	}{
		{"Check Point Virtual Network Adapter For Endpoint VPN Client", KindCorp},
		{"happ-xray Happ Tunnel", KindVPN},
		{"utun4", KindVPN},
		{"wg0", KindVPN},
		{"vEthernet (Default Switch) Hyper-V Virtual Ethernet Adapter", KindVirtual},
		{"docker0", KindVirtual},
		{"Беспроводная сеть Intel(R) Wi-Fi 6 AX201 160MHz", KindPhysical},
		{"eth0", KindPhysical},
	}
	for _, tt := range tests {
		if got := Classify(tt.in); got != tt.want {
			t.Errorf("Classify(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
