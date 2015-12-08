package frames

import (
	"encoding/hex"
	"strings"
)

type MAC [6]byte

func ParseMAC(s string) (m MAC, err error) {
	parts := strings.Split(s, ":")
	if len(parts) != 6 {
		return m, ErrInvalidMAC
	}
	for i, p := range parts {
		decoded, err := hex.DecodeString(p)
		if err != nil {
			return m, ErrInvalidMAC
		} else if len(decoded) != 1 {
			return m, ErrInvalidMAC
		}
		m[i] = decoded[0]
	}
	return
}

func (m MAC) String() string {
	parts := make([]string, 6)
	for i := range parts {
		parts[i] = hex.EncodeToString(m[i : i+1])
	}
	return strings.Join(parts, ":")
}
