package frames

import (
	"bytes"
	"encoding/binary"
)

// Authentication frames are used at the beginning of a new client-router connection.
type Authentication struct {
	Addresses []MAC

	Algorithm      uint16
	SequenceNumber uint16
	StatusCode     uint16

	Elements ManagementElements
}

// NewAuthenticationOpen generates an initial authentication frame for an open network.
// This is useful for every kind of network besides WEP networks.
func NewAuthenticationOpen(bssid, client MAC) *Authentication {
	return &Authentication{
		Addresses:      []MAC{bssid, client, bssid},
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

	res.Addresses = f.Addresses

	res.Algorithm = binary.LittleEndian.Uint16(f.Payload)
	res.SequenceNumber = binary.LittleEndian.Uint16(f.Payload[2:])
	res.StatusCode = binary.LittleEndian.Uint16(f.Payload[4:])

	res.Elements, err = DecodeManagementElements(f.Payload[6:])
	if err != nil {
		return
	}

	return &res, nil
}

// EncodeToFrame generates a Frame which represents this authentication frame.
func (a *Authentication) EncodeToFrame() *Frame {
	var buf bytes.Buffer

	header := make([]byte, 6)
	binary.LittleEndian.PutUint16(header, a.Algorithm)
	binary.LittleEndian.PutUint16(header[2:], a.SequenceNumber)
	binary.LittleEndian.PutUint16(header[4:], a.StatusCode)

	buf.Write(header)
	buf.Write(a.Elements.Encode())

	var seqControl uint16
	return &Frame{
		Version:         0,
		Type:            FrameTypeAuthentication,
		SequenceControl: &seqControl,
		Addresses:       a.Addresses,
		Payload:         buf.Bytes(),
	}
}

// Success returns true if the status code of the authentication frame
// indicates a success.
func (a *Authentication) Success() bool {
	return a.StatusCode == 0
}
