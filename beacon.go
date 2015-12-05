package wifistack

import (
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

	i := 12
	for i+2 < len(f.Payload) {
		tagType := BeaconTag(f.Payload[i])
		length := int(f.Payload[i+1])
		if length+i+2 > len(f.Payload) {
			return nil, ErrBufferUnderflow
		}
		res.Tags[tagType] = f.Payload[i+2 : i+2+length]
		i += 2 + length
	}
	if i < len(f.Payload) {
		return nil, ErrBufferOverflow
	}

	return &res, nil
}

func (f *Beacon) SSID() string {
	ssidTag := f.Tags[BeaconTagSSID]
	if ssidTag == nil {
		return ""
	}
	return string(ssidTag)
}

func (f *Beacon) Channel() int {
	channelTag := f.Tags[BeaconTagChannel]
	if channelTag == nil || len(channelTag) == 0 {
		return -1
	}
	return int(channelTag[0])
}
