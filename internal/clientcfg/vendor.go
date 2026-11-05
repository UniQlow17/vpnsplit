package clientcfg

import (
	"bufio"
	"bytes"
	"encoding/xml"
	"io"
	"strings"
)

// maxXMLTokens bounds how much of a profile is walked.
const maxXMLTokens = 100000

// OvpnBlocksOutsideDNS reports whether an OpenVPN config (or the text of a
// log with the options the server pushed) has the directive block-outside-dns:
// a line that starts with it (comments with # or ; and "push" lines count: a
// pushed option is meant). The text is not interpreted otherwise.
func OvpnBlocksOutsideDNS(data []byte) bool {
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for n := 0; sc.Scan() && n < 200000; n++ {
		l := strings.TrimSpace(sc.Text())
		if l == "" || l[0] == '#' || l[0] == ';' {
			continue
		}
		f := strings.Fields(l)
		if len(f) > 0 && strings.EqualFold(f[0], "block-outside-dns") {
			return true
		}
		if len(f) > 1 && strings.EqualFold(f[0], "push") && strings.EqualFold(strings.Trim(f[1], `"'`), "block-outside-dns") {
			return true
		}
	}
	return false
}

// OvpnLogPushedBlockOutsideDNS looks for the pushed option in the log of
// OpenVPN ("PUSH: Received control message: 'PUSH_REPLY,...,block-outside-dns,...'").
func OvpnLogPushedBlockOutsideDNS(data []byte) bool {
	return bytes.Contains(data, []byte("PUSH_REPLY")) && bytes.Contains(bytes.ToLower(data), []byte("block-outside-dns"))
}

// CiscoProfile is what matters in a Cisco AnyConnect / Secure Client profile.
type CiscoProfile struct {
	FailClosed bool // ConnectFailurePolicy = Closed: no network when the tunnel cannot be made
	AlwaysOn   bool // AlwaysOn = true
}

// ParseCiscoProfile reads the XML profile of Cisco AnyConnect / Secure Client.
// Only the elements AlwaysOn and ConnectFailurePolicy are taken; entities are
// not expanded (the standard library does not), a broken document is an error
// and gives what was found before it.
func ParseCiscoProfile(data []byte) (CiscoProfile, error) {
	var p CiscoProfile
	d := xml.NewDecoder(bytes.NewReader(data))
	d.Strict = true
	d.CharsetReader = nil
	var cur string
	for n := 0; n < maxXMLTokens; n++ {
		t, err := d.Token()
		if err == io.EOF {
			return p, nil
		}
		if err != nil {
			return p, err
		}
		switch v := t.(type) {
		case xml.StartElement:
			cur = v.Name.Local
		case xml.EndElement:
			cur = ""
		case xml.CharData:
			s := strings.TrimSpace(string(v))
			switch cur {
			case "AlwaysOn":
				p.AlwaysOn = p.AlwaysOn || strings.EqualFold(s, "true")
			case "ConnectFailurePolicy":
				p.FailClosed = p.FailClosed || strings.EqualFold(s, "Closed")
			}
		}
	}
	return p, nil
}
