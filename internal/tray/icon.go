package tray

import "math"

// RGB is a colour of an icon.
type RGB struct{ R, G, B uint8 }

// Colour is the colour of the disc for an icon: grey (off), green (on), red
// (a finding of the level danger).
func (i Icon) Colour() RGB {
	switch i {
	case IconOn:
		return RGB{46, 160, 67}
	case IconDanger:
		return RGB{220, 53, 69}
	}
	return RGB{128, 128, 128}
}

// Pixels draws the icon as a size x size picture of 32-bit pixels in the order
// B, G, R, A (as Windows wants them): a disc of the colour of the icon with a
// darker rim and a soft edge, on a transparent background. The icon is drawn
// at run time, so the program needs no resource files.
func (i Icon) Pixels(size int) []byte {
	px := make([]byte, size*size*4)
	c := i.Colour()
	r := float64(size)/2 - 0.5
	rim := math.Max(1, float64(size)/12)
	for y := 0; y < size; y++ {
		for x := 0; x < size; x++ {
			d := math.Hypot(float64(x)-float64(size-1)/2, float64(y)-float64(size-1)/2)
			cover := clamp01(r + 0.5 - d) // 1 inside, 0 outside, soft over one pixel
			if cover == 0 {
				continue
			}
			shade := 1.0
			if d > r-rim {
				shade = 0.65 // the rim
			}
			o := (y*size + x) * 4
			px[o+0] = uint8(float64(c.B) * shade)
			px[o+1] = uint8(float64(c.G) * shade)
			px[o+2] = uint8(float64(c.R) * shade)
			px[o+3] = uint8(cover * 255)
		}
	}
	return px
}

func clamp01(v float64) float64 { return math.Max(0, math.Min(1, v)) }
