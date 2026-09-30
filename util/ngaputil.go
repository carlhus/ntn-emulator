package util

import (
	"encoding/hex"
	"strings"

	"github.com/free5gc/ngap/ie"
)

// PlmnIdToNgap converts MCC and MNC strings to NGAP PLMNIdentity with proper BCD encoding
// MCC is 3 digits, MNC is 2 or 3 digits
// Example: MCC=208, MNC=93 -> hex "20f893" -> bytes {0x20, 0xf8, 0x93}
func PlmnIdToNgap(mcc, mnc string) (ie.PLMNIdentity, error) {
	var hexString string
	mccDigits := strings.Split(mcc, "")
	mncDigits := strings.Split(mnc, "")

	// 2-digit MNC: encode with filler 'f'
	if len(mnc) == 2 {
		hexString = mccDigits[1] + mccDigits[0] + "f" + mccDigits[2] + mncDigits[1] + mncDigits[0]
	} else {
		// 3-digit MNC
		hexString = mccDigits[1] + mccDigits[0] + mncDigits[0] + mccDigits[2] + mncDigits[2] + mncDigits[1]
	}

	plmnBytes, err := hex.DecodeString(hexString)
	if err != nil {
		return ie.PLMNIdentity{}, err
	}
	return ie.PLMNIdentity{Value: plmnBytes}, nil
}

// TacToNgap converts TAC hex string to NGAP TAC
// Example: TAC="000001" -> bytes {0x00, 0x00, 0x01}
func TacToNgap(tacHex string) (ie.TAC, error) {
	tacBytes, err := hex.DecodeString(tacHex)
	if err != nil {
		return ie.TAC{}, err
	}
	return ie.TAC{Value: tacBytes}, nil
}
