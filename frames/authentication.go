package frames

import (
	"bytes"
	"encoding/binary"
)

// Authentication frames are used at the beginning of a new client-router connection.
type Authentication struct {
	MAC1 [6]byte
	MAC2 [6]byte
	MAC3 [6]byte

	Algorithm      uint16
	SequenceNumber uint16
	StatusCode     uint16

	Elements ManagementElements
}

// NewAuthenticationOpen generates an initial authentication frame for an open network.
// This is useful for every kind of network besides WEP networks.
func NewAuthenticationOpen(router, client [6]byte) *Authentication {
	return &Authentication{
		MAC1:           router,
		MAC2:           client,
		MAC3:           router,
		SequenceNumber: 1,
		Elements:       ManagementElements{},
	}
}

// DecodeAuthentication decodes an authentication frame.
func DecodeAuthentication(f *Frame) (auth *Authentication, err error) {
	if len(f.Payload) < 6 {
		return nil, ErrBufferUnderflow
	}

	var res Authentication

	res.MAC1 = f.MAC1
	res.MAC2 = f.MAC2
	res.MAC3 = f.MAC3

	res.Algorithm = binary.LittleEndian.Uint16(f.Payload)
	res.SequenceNumber = binary.LittleEndian.Uint16(f.Payload[2:])
	res.StatusCode = binary.LittleEndian.Uint16(f.Payload[4:])

	res.Elements, err = DecodeManagementElements(f.Payload[6:])
	if err != nil {
		return
	}

	return &res, nil
}

// Encode encodes an authentication frame.
func (a *Authentication) EncodeToFrame() *Frame {
	var buf bytes.Buffer

	header := make([]byte, 6)
	binary.LittleEndian.PutUint16(header, a.Algorithm)
	binary.LittleEndian.PutUint16(header[2:], a.SequenceNumber)
	binary.LittleEndian.PutUint16(header[4:], a.StatusCode)

	buf.Write(header)
	buf.Write(a.Elements.Encode())

	return &Frame{
		Version: 0,
		Type:    FrameTypeAuthentication,
		MAC1:    a.MAC1,
		MAC2:    a.MAC2,
		MAC3:    a.MAC3,
		Payload: buf.Bytes(),
	}
}
