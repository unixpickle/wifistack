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

	Elements Elements
}

// DecodeBeacon extracts beacon information from a Frame.
func DecodeBeacon(f *Frame) (beacon *Beacon, err error) {
	if len(f.Payload) < 12 {
		return nil, ErrBufferUnderflow
	}
	var res Beacon

	res.BSSID = f.Addresses[1]

	res.Timestamp = binary.LittleEndian.Uint64(f.Payload)
	res.Interval = binary.LittleEndian.Uint16(f.Payload[8:])
	res.Capabilities = binary.LittleEndian.Uint16(f.Payload[10:])

	res.Elements, err = DecodeElements(f.Payload[12:])
	if err != nil {
		return
	}

	return &res, nil
}

// SSID returns a string representation of the SSID element.
func (f *Beacon) SSID() string {
	return string(f.Elements.Get(ElementIDSSID))
}

// Channel returns the station's self-reported channel number.
func (f *Beacon) Channel() int {
	channel := f.Elements.Get(ElementIDDSSSParameterSet)
	if channel == nil || len(channel) != 1 {
		return -1
	}
	return int(channel[0])
}

// BSSDescription generates a BSSDescription based on the information from
// this beacon.
func (f *Beacon) BSSDescription() BSSDescription {
	res := BSSDescription{
		BSSID:   f.BSSID,
		SSID:    f.SSID(),
		Channel: f.Channel(),
	}

	// NOTE: see section 8.4.1.4 of the IEEE 802.11-2012 spec.
	if (f.Capabilities & 3) == 0 {
		res.Type = BSSTypeMesh
	} else if (f.Capabilities & 2) != 0 {
		res.Type = BSSTypeIndependent
	} else if (f.Capabilities & 1) != 0 {
		res.Type = BSSTypeInfrastructure
	}

	res.OperationalRates = []byte{}

	// NOTE: basic rates have the highest bit set, others do not.

	for _, rate := range f.Elements.Get(ElementIDSupportedRates) {
		if (rate & 0x80) != 0 {
			res.BasicRates = append(res.BasicRates, rate&0x7f)
		}
		res.OperationalRates = append(res.OperationalRates, rate&0x7f)
	}
	for _, rate := range f.Elements.Get(ElementIDExtendedSupportedRates) {
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

	var seqControl uint16
	return &Frame{
		Version:         0,
		Type:            FrameTypeBeacon,
		SequenceControl: &seqControl,
		Addresses: []MAC{
			MAC{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
			f.BSSID,
			f.BSSID,
		},
		Payload: buf.Bytes(),
	}
}
