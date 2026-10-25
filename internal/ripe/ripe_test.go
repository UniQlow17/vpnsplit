package ripe

import (
	"slices"
	"testing"
)

func TestCollapse(t *testing.T) {
	// AS15632 as announced: 13 prefixes, some overlapping
	in := []string{"217.12.96.0/21", "217.12.96.0/24", "217.12.97.0/24", "217.12.104.0/24", "217.12.105.0/24",
		"217.12.106.0/24", "217.12.108.0/24", "217.12.110.0/24", "2a00:1fa0::/32", "bogus"}
	want := []string{"217.12.96.0/21", "217.12.104.0/23", "217.12.106.0/24", "217.12.108.0/24", "217.12.110.0/24"}
	if got := Collapse(in); !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	// AS49675: four /24s become one /22, unaligned neighbours stay apart
	if got := Collapse([]string{"89.169.19.0/24", "89.169.16.0/24", "89.169.18.0/24", "89.169.17.0/24"}); !slices.Equal(got, []string{"89.169.16.0/22"}) {
		t.Errorf("got %v", got)
	}
	if got := Collapse([]string{"10.0.1.0/24", "10.0.2.0/24"}); len(got) != 2 {
		t.Errorf("unaligned pair must not merge: %v", got)
	}
}
