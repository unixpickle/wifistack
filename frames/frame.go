package frames

import (
	"bytes"
	"encoding/binary"
	"fmt"
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

// Unknown returns false if this frame type is defined in the 2012
// IEEE 802.11 specification.
func (f FrameType) Unknown() bool {
	_, ok := frameTypeNames[f]
	return !ok
}

const (
	FrameMajorTypeManagement = 0
	FrameMajorTypeControl    = 1
	FrameMajorTypeData       = 2
)

// These are the types of management frames defined in the
// IEEE 802.11 specification from 2012, page 382.
const (
	FrameTypeAssocRequest        FrameType = 0
	FrameTypeAssocResponse                 = 1
	FrameTypeReassocRequest                = 2
	FrameTypeReassocResponse               = 3
	FrameTypeProbeRequest                  = 4
	FrameTypeProbeResponse                 = 5
	FrameTypeTimingAdvertisement           = 6
	FrameTypeBeacon                        = 8
	FrameTypeATIM                          = 9
	FrameTypeDisassoc                      = 0xa
	FrameTypeAuthentication                = 0xb
	FrameTypeDeauthentication              = 0xc
	FrameTypeAction                        = 0xd
	FrameTypeActionNoAck                   = 0xe
)

// These are the types of control frames defined in the
// IEEE 802.11 specification from 2012, page 383.
const (
	FrameTypeControlWrapper  = 0x17
	FrameTypeBlockAckRequest = 0x18
	FrameTypeBlockAck        = 0x19
	FrameTypePSPoll          = 0x1a
	FrameTypeRTS             = 0x1b
	FrameTypeCTS             = 0x1c
	FrameTypeACK             = 0x1d
	FrameTypeCFEnd           = 0x1e
	FrameTypeCFEndCFAck      = 0x1f
)

// These are the types of data frames defined in the
// IEEE 802.11 specification from 2012, page 383.
const (
	FrameTypeData               = 0x20
	FrameTypeDataCFAck          = 0x21
	FrameTypeDataCFPoll         = 0x22
	FrameTypeDataCFAckCFPoll    = 0x23
	FrameTypeNull               = 0x24
	FrameTypeNullCFAck          = 0x25
	FrameTypeNullCFPoll         = 0x26
	FrameTypeNullCFAckCFPoll    = 0x27
	FrameTypeQoSData            = 0x28
	FrameTypeQoSDataCFAck       = 0x29
	FrameTypeQoSDataCFPoll      = 0x2a
	FrameTypeQoSDataCFAckCFPoll = 0x2b
	FrameTypeQoSNull            = 0x2c
	FrameTypeQoSNullCFPoll      = 0x2e
	FrameTypeQoSNullCFAckCFPoll = 0x2f
)

var frameTypeNames map[FrameType]string = map[FrameType]string{
	FrameTypeAssocRequest:     "Association Request",
	FrameTypeAssocResponse:    "Association Response",
	FrameTypeReassocRequest:   "Reassociation Request",
	FrameTypeReassocResponse:  "Reassociation Response",
	FrameTypeProbeRequest:     "Probe Request",
	FrameTypeProbeResponse:    "Probe Response",
	FrameTypeBeacon:           "Beacon",
	FrameTypeATIM:             "Announcement Traffic Indication Message",
	FrameTypeDisassoc:         "Disassociation",
	FrameTypeAuthentication:   "Authentication",
	FrameTypeDeauthentication: "Deauthentication",
	FrameTypeAction:           "Action",
	FrameTypeActionNoAck:      "Action (No Ack)",

	FrameTypeControlWrapper:  "Control Wrapper",
	FrameTypeBlockAckRequest: "Block Ack Request",
	FrameTypeBlockAck:        "Block Ack",
	FrameTypePSPoll:          "PS-Poll",
	FrameTypeRTS:             "Request to Send",
	FrameTypeCTS:             "Clear to Send",
	FrameTypeACK:             "Acknowledgement",
	FrameTypeCFEnd:           "CF-End",
	FrameTypeCFEndCFAck:      "CF-End + CF-Ack",

	FrameTypeData:               "Data",
	FrameTypeDataCFAck:          "Data + CF-Ack",
	FrameTypeDataCFPoll:         "Data + CF-Poll",
	FrameTypeDataCFAckCFPoll:    "Data + CF-Ack + CF-Poll",
	FrameTypeNull:               "Null",
	FrameTypeNullCFAck:          "Null + CF-Ack",
	FrameTypeNullCFPoll:         "Null + CF-Poll",
	FrameTypeNullCFAckCFPoll:    "Null + CF-Ack + CF-Poll",
	FrameTypeQoSData:            "QoS Data",
	FrameTypeQoSDataCFAck:       "Qos Data + CF-Ack",
	FrameTypeQoSDataCFPoll:      "Qos Data + CF-Poll",
	FrameTypeQoSDataCFAckCFPoll: "Qos Data + CF-Ack + CF-Poll",
	FrameTypeQoSNull:            "Qos Null",
	FrameTypeQoSNullCFPoll:      "Qos Null + CF-Poll",
	FrameTypeQoSNullCFAckCFPoll: "Qos Null + CF-Ack + CF-Poll",
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

	// DurationID is present in all frames, but its meaning varies across frames.
	DurationID uint16

	// Addresses in an ordered list of MAC addresses from the frame header.
	// The number of MAC addresses is determined by the packet's type and flags.
	Addresses []MAC

	// SquenceControl is present in management and data frames, but not in
	// control frames (in which case it will be nil).
	SequenceControl *uint16

	// CarriedFrameControl is used in control wrapper frames to store the
	// frame control field of the carried frame.
	// In all other frames, it is nil.
	CarriedFrameControl *uint16

	// QoSControl is a flag on QoS data frames.
	// In all other frames, it is nil.
	QoSControl *uint16

	// HTControlField is used in some QoS data frames, management frames, and the control
	// wrapper frame.
	// In all other frames, it is nil.
	HTControlField *uint32

	// Payload is the body of the frame, not including the header or checksum.
	Payload []byte
}

// DecodeFrame decodes a raw WiFi frame.
// The data should include a 32-bit checksum.
func DecodeFrame(data []byte) (*Frame, error) {
	if len(data) < 8 {
		return nil, ErrBufferUnderflow
	}

	calculatedChecksum := crc32.ChecksumIEEE(data[:len(data)-4])
	sentChecksum := binary.LittleEndian.Uint32(data[len(data)-4:])
	if calculatedChecksum != sentChecksum {
		return nil, ErrBadChecksum
	}

	var res Frame

	res.Version = int(data[0]) & 3

	if res.Version != 0 {
		return nil, ErrUnknownFrameVersion
	}

	majorType := int(data[0]>>2) & 3
	subtype := int(data[0]>>4) & 0xf
	res.Type = NewFrameType(majorType, subtype)

	if res.Type.Unknown() {
		return nil, ErrUnknownFrameType
	}

	flags := []*bool{&res.FromDS, &res.ToDS, &res.MoreFrag, &res.Retry, &res.PowerManagement,
		&res.MoreData, &res.Encrypted, &res.Order}
	for i, flagPtr := range flags {
		if (data[1] & (1 << uint(i))) != 0 {
			*flagPtr = true
		}
	}

	res.DurationID = binary.LittleEndian.Uint16(data[2:])

	headerSize, err := res.decodeHeaderFields(data[4 : len(data)-4])
	if err != nil {
		return nil, err
	}

	res.Payload = data[4+headerSize : len(data)-4]

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

	for i := 0; i < 3 && i < len(f.Addresses); i++ {
		buf.Write(f.Addresses[i][:])
	}

	if f.SequenceControl != nil {
		binary.BigEndian.PutUint16(numBuf, *f.SequenceControl)
		buf.Write(numBuf)
	}

	if len(f.Addresses) == 4 {
		buf.Write(f.Addresses[3][:])
	}

	if f.CarriedFrameControl != nil {
		binary.BigEndian.PutUint16(numBuf, *f.CarriedFrameControl)
		buf.Write(numBuf)
	}

	if f.QoSControl != nil {
		binary.BigEndian.PutUint16(numBuf, *f.QoSControl)
		buf.Write(numBuf)
	}

	if f.HTControlField != nil {
		bigNumBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(bigNumBuf, *f.HTControlField)
		buf.Write(bigNumBuf)
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

	description.WriteString(" durID=")
	description.WriteString(strconv.Itoa(int(f.DurationID)))
	description.WriteString(" addrs=")
	description.WriteString(fmt.Sprint(f.Addresses))

	if f.SequenceControl != nil {
		description.WriteString(" seq=")
		description.WriteString(strconv.Itoa(int(*f.SequenceControl)))
	}

	if f.CarriedFrameControl != nil {
		description.WriteString(" carriedFC=")
		description.WriteString(strconv.Itoa(int(*f.CarriedFrameControl)))
	}

	if f.QoSControl != nil {
		description.WriteString(" qosCtl=")
		description.WriteString(strconv.Itoa(int(*f.QoSControl)))
	}

	if f.HTControlField != nil {
		description.WriteString(" htCtl=")
		description.WriteString(strconv.FormatUint(uint64(*f.HTControlField), 10))
	}

	if len(f.Payload) > 0 {
		description.WriteRune(':')
	}

	for _, b := range f.Payload {
		description.WriteRune(' ')
		description.WriteString(byteToHex(b))
	}

	return description.String()
}

// decodeHeaderFields decodes all of the header fields after the frame control
// field and the duration ID field.
// The supplied data should start at the first header field and end before
// the checksum.
// This returns the number of bytes consumed by the header, and a possible
// buffer underflow error.
func (f *Frame) decodeHeaderFields(data []byte) (int, error) {
	var addressCount int
	var hasSequenceControl bool
	var hasCarriedFrameControl bool
	var hasQoSControl bool
	var hasHTControl bool

	switch f.Type.Type() {
	case FrameMajorTypeData:
		hasSequenceControl = true
		if f.ToDS && f.FromDS {
			addressCount = 4
		} else {
			addressCount = 3
		}
		if f.Type.Subtype() >= 8 {
			hasQoSControl = true
			hasHTControl = f.Order
		}
	case FrameMajorTypeManagement:
		hasSequenceControl = true
		addressCount = 3
		hasHTControl = f.Order
	case FrameMajorTypeControl:
		switch f.Type {
		case FrameTypeControlWrapper:
			hasHTControl = true
			hasCarriedFrameControl = true
			fallthrough
		case FrameTypeCTS, FrameTypeACK:
			addressCount = 1
		case FrameTypeRTS, FrameTypePSPoll, FrameTypeCFEnd, FrameTypeCFEndCFAck,
			FrameTypeBlockAck, FrameTypeBlockAckRequest:
			addressCount = 2
		}
	}

	offset := 0

	f.Addresses = make([]MAC, addressCount)
	for i := 0; i < addressCount && i < 3; i++ {
		if offset+6 >= len(data) {
			return 0, ErrBufferOverflow
		}
		copy(f.Addresses[i][:], data[offset:])
		offset += 6
	}

	if hasSequenceControl {
		if offset+2 > len(data) {
			return 0, ErrBufferUnderflow
		}
		num := binary.LittleEndian.Uint16(data[offset:])
		f.SequenceControl = &num
		offset += 2
	}

	if addressCount == 4 {
		if offset+6 >= len(data) {
			return 0, ErrBufferUnderflow
		}
		copy(f.Addresses[3][:], data[offset:])
		offset += 6
	}

	if hasCarriedFrameControl {
		if offset+2 >= len(data) {
			return 0, ErrBufferUnderflow
		}
		num := binary.LittleEndian.Uint16(data[offset:])
		f.CarriedFrameControl = &num
		offset += 2
	}

	if hasQoSControl {
		if offset+2 >= len(data) {
			return 0, ErrBufferUnderflow
		}
		num := binary.LittleEndian.Uint16(data[offset:])
		f.QoSControl = &num
		offset += 2
	}

	if hasHTControl {
		if offset+4 >= len(data) {
			return 0, ErrBufferUnderflow
		}
		num := binary.LittleEndian.Uint32(data[offset:])
		f.HTControlField = &num
		offset += 4
	}

	return offset, nil
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
