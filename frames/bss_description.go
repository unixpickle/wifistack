package frames

type BSSType int

const (
	BSSTypeIndependent BSSType = iota
	BSSTypeInfrastructure
	BSSTypeMesh
)

// BSSDescription contains fields described in section 6.3.3.3.2 in the IEEE 802.11-2012 spec.
type BSSDescription struct {
	BSSID MAC
	SSID  string
	Type  BSSType

	BasicRates       []byte
	OperationalRates []byte
}
