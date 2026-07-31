package httpapi

import "rsc.io/qr"

// renderQRCodePNG encodes text as a QR code and returns raw PNG bytes.
// Medium error-correction level matches what the CLI's terminal QR code
// uses, balancing scan reliability against QR density.
func renderQRCodePNG(text string) ([]byte, error) {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return nil, err
	}
	return code.PNG(), nil
}
