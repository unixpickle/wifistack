package wifistack

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"strconv"
)

// A FrameType represents a pair (type, subtype) where type is
// two bits and subtype is four bits.
// A FrameType is encoded as (type << 4) | subtype.
type FrameType int

// NewFrame generates a frame type using a type and subtype.
func NewFrameType(majorType, subtype int) FrameType {
	return FrameType((majorType << 4) | subtype)
}

// Type returns the two-bit major type number.
func (f FrameType) Type() int {
	return int(f) >> 4
}

// Subtype returns the four-bit subtype number.
func (f FrameType) Subtype() int {
	return int(f) & 0xf
}

// String returns a long, human-readable name for this FrameType
// if one is available.
func (f FrameType) String() string {
	if name, ok := frameTypeNames[f]; ok {
		return name
	} else {
		return "FrameType(" + strconv.Itoa(int(f)) + ")"
	}
}

const (
	FrameTypeAssocRequest    FrameType = 0
	FrameTypeAssocResponse             = 1
	FrameTypeReassocRequest            = 2
	FrameTypeReassocResponse           = 3
	FrameTypeProbeRequest              = 4
	FrameTypeProbeResponse             = 5
	FrameTypeBeacon                    = 8
	FrameTypeATIM                      = 9
	FrameTypeDisassoc                  = 0xa
	FrameTypeAuth                      = 0xb
	FrameTypeDeauth                    = 0xc
)

var frameTypeNames map[FrameType]string = map[FrameType]string{
	FrameTypeAssocRequest:    "Association Request",
	FrameTypeAssocResponse:   "Association Response",
	FrameTypeReassocRequest:  "Reassociation Request",
	FrameTypeReassocResponse: "Reassociation Response",
	FrameTypeProbeRequest:    "Probe Request",
	FrameTypeProbeResponse:   "Probe Response",
	FrameTypeBeacon:          "Beacon",
	FrameTypeATIM:            "Announcement Traffic Indication Message",
	FrameTypeDisassoc:        "Disassociation",
	FrameTypeAuth:            "Authentication",
	FrameTypeDeauth:          "Deauthentication",
}

// A Frame is the fundamental unit used for communication on WiFi networks.
type Frame struct {
	Version         int
	Type            FrameType
	FromDS          bool
	ToDS            bool
	MoreFrag        bool
	Retry           bool
	PowerManagement bool
	MoreData        bool
	Encrypted       bool
	Order           bool

	DurationID uint16

	MAC1 [6]byte
	MAC2 [6]byte
	MAC3 [6]byte

	SequenceControl uint16

	// MAC4 is the fourth MAC address which is not present in every
	// 802.11 MAC frame.
	// If this is nil, then it is not present.
	MAC4 []byte

	Payload []byte
}

// DecodeFrame decodes a raw WiFi frame.
// The data should include a 32-bit checksum.
func DecodeFrame(data []byte) (*Frame, error) {
	// TODO: some frames actually may be less than 28 bytes (I think).
	if len(data) < 28 {
		return nil, ErrBufferUnderflow
	}

	calculatedChecksum := crc32.ChecksumIEEE(data[:len(data)-4])
	sentChecksum := binary.LittleEndian.Uint32(data[len(data)-4:])
	if calculatedChecksum != sentChecksum {
		return nil, ErrBadChecksum
	}

	res := Frame{}
	res.Version = int(data[0]) & 3

	majorType := int(data[0]>>2) & 3
	subtype := int(data[0]>>4) & 0xf
	res.Type = NewFrameType(majorType, subtype)

	flags := []*bool{&res.FromDS, &res.ToDS, &res.MoreFrag, &res.Retry, &res.PowerManagement,
		&res.MoreData, &res.Encrypted, &res.Order}
	for i, flagPtr := range flags {
		if (data[1] & (1 << uint(i))) != 0 {
			*flagPtr = true
		}
	}

	res.DurationID = binary.BigEndian.Uint16(data[2:])

	copy(res.MAC1[:], data[4:])
	copy(res.MAC2[:], data[10:])
	copy(res.MAC3[:], data[16:])

	res.SequenceControl = binary.BigEndian.Uint16(data[22:])

	// TODO: figure out if the packet has an extra MAC field.

	res.Payload = data[24 : len(data)-4]

	return &res, nil
}

// Becon returns true if the frame is a WiFi beacon.
func (f *Frame) Beacon() bool {
	return f.Version == 0 && f.Type == FrameTypeBeacon
}

// Encode encodes the frame as binary.
// This generates the trailing checksum automatically.
func (f *Frame) Encode() []byte {
	var buf bytes.Buffer

	buf.WriteByte(byte((f.Type.Type() << 2) | (f.Type.Subtype() << 4) | f.Version))

	var flagByte byte
	flags := []bool{f.FromDS, f.ToDS, f.MoreFrag, f.Retry, f.PowerManagement,
		f.MoreData, f.Encrypted, f.Order}
	for i, flag := range flags {
		if flag {
			flagByte |= byte(1 << uint(i))
		}
	}
	buf.WriteByte(flagByte)

	numBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(numBuf, f.DurationID)
	buf.Write(numBuf)

	buf.Write(f.MAC1[:])
	buf.Write(f.MAC2[:])
	buf.Write(f.MAC3[:])

	binary.BigEndian.PutUint16(numBuf, f.SequenceControl)
	buf.Write(numBuf)

	if f.MAC4 != nil {
		buf.Write(f.MAC4)
	}

	buf.Write(f.Payload)

	checksum := crc32.ChecksumIEEE(buf.Bytes())
	checksumBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(checksumBuf, checksum)
	buf.Write(checksumBuf)

	return buf.Bytes()
}

// String generates a pretty string to represent the packet.
func (f *Frame) String() string {
	var description bytes.Buffer

	description.WriteString(f.Type.String())
	description.WriteString(" (v")
	description.WriteString(strconv.Itoa(f.Version))
	description.WriteString("):")

	flags := []bool{f.FromDS, f.ToDS, f.MoreFrag, f.Retry, f.PowerManagement,
		f.MoreData, f.Encrypted, f.Order}
	for _, b := range flags {
		if b {
			description.WriteRune('1')
		} else {
			description.WriteRune('0')
		}
	}

	description.WriteRune(' ')
	description.WriteString(macToString(f.MAC3))
	description.WriteString(",")
	description.WriteString(macToString(f.MAC2))
	description.WriteString(",")
	description.WriteString(macToString(f.MAC1))

	description.WriteRune(' ')
	description.WriteString(strconv.Itoa(int(f.DurationID)))
	description.WriteRune(' ')
	description.WriteString(strconv.Itoa(int(f.SequenceControl)))

	if len(f.Payload) > 0 {
		description.WriteRune(':')
	}

	for _, b := range f.Payload {
		description.WriteRune(' ')
		description.WriteString(byteToHex(b))
	}

	return description.String()
}

func byteToHex(n byte) string {
	n1 := n >> 4
	n2 := n & 0xf
	res := ""
	if n1 < 10 {
		res += string('0' + n1)
	} else {
		res += string('a' + (n1 - 10))
	}
	if n2 < 10 {
		res += string('0' + n2)
	} else {
		res += string('a' + (n2 - 10))
	}
	return res
}

func macToString(m [6]byte) string {
	var buf bytes.Buffer
	for i := 0; i < 6; i++ {
		if i != 0 {
			buf.WriteRune(':')
		}
		buf.WriteString(byteToHex(m[i]))
	}
	return buf.String()
}
