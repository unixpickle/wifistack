package frames

import (
	"bytes"
	"encoding/binary"
)

// A Beacon stores information specific to wireless beacons.
type Beacon struct {
	BSSID MAC

	Timestamp    uint64
	Interval     uint16
	Capabilities uint16

	Elements ManagementElements
}

// DecodeBeacon extracts beacon information from a Frame.
func DecodeBeacon(f *Frame) (beacon *Beacon, err error) {
	if len(f.Payload) < 12 {
		return nil, ErrBufferUnderflow
	}
	var res Beacon

	res.BSSID = f.MAC2

	res.Timestamp = binary.LittleEndian.Uint64(f.Payload)
	res.Interval = binary.LittleEndian.Uint16(f.Payload[8:])
	res.Capabilities = binary.LittleEndian.Uint16(f.Payload[10:])

	res.Elements, err = DecodeManagementElements(f.Payload[12:])
	if err != nil {
		return
	}

	return &res, nil
}

// SSID returns a string representation of the SSID element.
func (f *Beacon) SSID() string {
	ssidTag := f.Elements.Get(ManagementTagSSID)
	if ssidTag == nil {
		return ""
	}
	return string(ssidTag)
}

// Channel returns an integer representation of the channel element.
func (f *Beacon) Channel() int {
	channel := f.Elements.Get(ManagementTagDSSSParameterSet)
	if channel == nil || len(channel) != 1 {
		return -1
	}
	return int(channel[0])
}

// BSSDescription generates a BSSDescription based on the information from
// this beacon.
func (f *Beacon) BSSDescription() BSSDescription {
	res := BSSDescription{
		BSSID: f.BSSID,
		SSID:  f.SSID(),
	}

	// TODO: figure out the best way to determine the type.
	// See section 8.4.1.4 of the IEEE 802.11-2012 spec.
	if (f.Capabilities & 2) != 0 {
		res.Type = BSSTypeInfrastructure
	} else if (f.Capabilities & 3) == 0 {
		res.Type = BSSTypeMesh
	}

	res.BasicRates = []byte{}
	res.OperationalRates = []byte{}

	for _, rate := range f.Elements.Get(ManagementTagSupportedRates) {
		if (rate & 0x80) != 0 {
			res.BasicRates = append(res.BasicRates, rate&0x7f)
		}
		res.OperationalRates = append(res.OperationalRates, rate&0x7f)
	}
	for _, rate := range f.Elements.Get(ManagementTagExtendedSupportedRates) {
		if (rate & 0x80) != 0 {
			res.BasicRates = append(res.BasicRates, rate&0x7f)
		}
		res.OperationalRates = append(res.OperationalRates, rate&0x7f)
	}

	return res
}

// EncodeToFrame generates an 802.11 frame which represents this beacon.
func (f *Beacon) EncodeToFrame() *Frame {
	var buf bytes.Buffer

	header := make([]byte, 12)
	binary.LittleEndian.PutUint64(header, f.Timestamp)
	binary.LittleEndian.PutUint16(header[8:], f.Interval)
	binary.LittleEndian.PutUint16(header[10:], f.Capabilities)

	buf.Write(header)
	buf.Write(f.Elements.Encode())

	return &Frame{
		Version: 0,
		Type:    FrameTypeBeacon,
		MAC1:    MAC{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		MAC2:    f.BSSID,
		MAC3:    f.BSSID,
		Payload: buf.Bytes(),
	}
}
