package wifistack

import (
	"bytes"
	"encoding/binary"
)

// A Beacon stores information specific to wireless beacons.
type Beacon struct {
	BSSID [6]byte

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

	// TODO: figure out if these are really supposed to be little endian.
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
		MAC1:    [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		MAC2:    f.BSSID,
		MAC3:    f.BSSID,
		Payload: buf.Bytes(),
	}
}
