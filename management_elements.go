package wifistack

import (
	"bytes"
	"strconv"
)

// A ManagementTag is an element ID for fields in 802.11 management frames.
// These IDs are defined in section 8.4.2.1 of the IEEE 802.11-2012 standard.
type ManagementTag int

const (
	ManagementTagSSID                   ManagementTag = 0
	ManagementTagSupportedRates                       = 1
	ManagementTagDSSSParameterSet                     = 3
	ManagementTagCountry                              = 7
	ManagementTagChallengeText                        = 16
	ManagementTagSupportedChannels                    = 36
	ManagementTagExtendedSupportedRates               = 50
)

var managementTagNames = map[ManagementTag]string{
	ManagementTagSSID:                   "SSID",
	ManagementTagSupportedRates:         "Supported Rates",
	ManagementTagDSSSParameterSet:       "DSSS Parameter Set (Channel)",
	ManagementTagCountry:                "Country",
	ManagementTagChallengeText:          "Challenge Text",
	ManagementTagSupportedChannels:      "Supported Channels",
	ManagementTagExtendedSupportedRates: "Extended Supported Rates",
}

func (m ManagementTag) String() string {
	if name, ok := managementTagNames[m]; ok {
		return name
	} else {
		return "ManagementTag(" + strconv.Itoa(int(m)) + ")"
	}
}

// A ManagementElement represents an ID, value pair.
type ManagementElement struct {
	ID    ManagementTag
	Value []byte
}

// ManagementElements is an ordered list of ManagementElement pairs.
type ManagementElements []ManagementElement

// DecodeManagementElements decodes an array of management elements from a
// management packet's body.
func DecodeManagementElements(buf []byte) (ManagementElements, error) {
	res := ManagementElements{}
	i := 0
	for i+2 < len(buf) {
		id := ManagementTag(buf[i])
		length := int(buf[i+1])
		if length+i+2 > len(buf) {
			return nil, ErrBufferUnderflow
		}
		value := buf[i+2 : i+2+length]
		res = append(res, ManagementElement{id, value})
		i += 2 + length
	}
	if i < len(buf) {
		return nil, ErrBufferOverflow
	}
	return res, nil
}

// Encode generates a binary representation of the management elements.
func (m ManagementElements) Encode() []byte {
	var buf bytes.Buffer
	for _, pair := range m {
		buf.WriteByte(byte(pair.ID))
		buf.WriteByte(byte(len(pair.Value)))
		buf.Write(pair.Value)
	}
	return buf.Bytes()
}

// Get returns the value of an element, or nil if the element was not set.
func (m ManagementElements) Get(t ManagementTag) []byte {
	for _, pair := range m {
		if pair.ID == t {
			return pair.Value
		}
	}
	return nil
}
