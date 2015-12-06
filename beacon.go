package wifistack

import (
	"bytes"
	"encoding/binary"
	"strconv"
)

type BeaconTag int

var beaconTagNames = map[BeaconTag]string{
	0: "SSID",
	1: "rates",
	3: "channel",
}

// String returns a human-readable version of the beacon, if available.
func (b BeaconTag) String() string {
	if name, ok := beaconTagNames[b]; ok {
		return name
	} else {
		return "BeaconTag(" + strconv.Itoa(int(b)) + ")"
	}
}

const (
	BeaconTagSSID    BeaconTag = 0
	BeaconTagRates             = 1
	BeaconTagChannel           = 3
)

// A Beacon stores information specific to wireless beacons.
type Beacon struct {
	BSSID [6]byte

	Timestamp    uint64
	Interval     uint16
	Capabilities uint16

	Tags map[BeaconTag][]byte
}

// DecodeBeacon extracts beacon information from a Frame.
func DecodeBeacon(f *Frame) (*Beacon, error) {
	if len(f.Payload) < 12 {
		return nil, ErrBufferUnderflow
	}
	var res Beacon

	res.BSSID = f.MAC2

	// TODO: figure out if these are really supposed to be little endian.
	res.Timestamp = binary.LittleEndian.Uint64(f.Payload)
	res.Interval = binary.LittleEndian.Uint16(f.Payload[8:])
	res.Capabilities = binary.LittleEndian.Uint16(f.Payload[10:])

	res.Tags = map[BeaconTag][]byte{}
	decodedTags, err := decodeManagementTags(f.Payload[12:])
	if err != nil {
		return nil, err
	}
	for tag, value := range decodedTags {
		res.Tags[BeaconTag(tag)] = value
	}

	return &res, nil
}

// SSID returns a string representation of the SSID tag.
func (f *Beacon) SSID() string {
	ssidTag := f.Tags[BeaconTagSSID]
	if ssidTag == nil {
		return ""
	}
	return string(ssidTag)
}

// Channel returns an integer representation of the channel tag.
func (f *Beacon) Channel() int {
	channelTag := f.Tags[BeaconTagChannel]
	if channelTag == nil || len(channelTag) == 0 {
		return -1
	}
	return int(channelTag[0])
}

// EncodeToFrame generates an 802.11 frame which represents this beacon.
func (f *Beacon) EncodeToFrame() *Frame {
	var buf bytes.Buffer

	header := make([]byte, 12)
	binary.LittleEndian.PutUint64(header, f.Timestamp)
	binary.LittleEndian.PutUint16(header[8:], f.Interval)
	binary.LittleEndian.PutUint16(header[10:], f.Capabilities)

	buf.Write(header)

	tagIds := map[int][]byte{}
	for tag, value := range f.Tags {
		tagIds[int(tag)] = value
	}
	buf.Write(encodeManagementTags(tagIds))

	return &Frame{
		Version: 0,
		Type:    FrameTypeBeacon,
		MAC1:    [6]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		MAC2:    f.BSSID,
		MAC3:    f.BSSID,
		Payload: buf.Bytes(),
	}
}
