package frames

import (
	"bytes"
	"encoding/binary"
)

// An AssocRequest stores holds information about an association request frame.
type AssocRequest struct {
	BSSID  MAC
	Client MAC

	Capabilities uint16
	Interval     uint16

	Elements Elements
}

// DecodeAssocRequest extracts association request information from a Frame.
func DecodeAssocRequest(f *Frame) (assocRequest *AssocRequest, err error) {
	if len(f.Payload) < 4 {
		return nil, ErrBufferUnderflow
	}

	var res AssocRequest

	res.BSSID = f.Addresses[0]
	res.Client = f.Addresses[1]

	res.Capabilities = binary.LittleEndian.Uint16(f.Payload)
	res.Interval = binary.LittleEndian.Uint16(f.Payload[2:])

	res.Elements, err = DecodeElements(f.Payload[4:])
	if err != nil {
		return
	}

	return &res, nil
}

// EncodeToFrame generates an 802.11 frame which represents this association request.
func (a *AssocRequest) EncodeToFrame() *Frame {
	var buf bytes.Buffer

	header := make([]byte, 4)
	binary.LittleEndian.PutUint16(header, a.Capabilities)
	binary.LittleEndian.PutUint16(header[2:], a.Interval)

	buf.Write(header)
	buf.Write(a.Elements.Encode())

	var seqControl uint16
	return &Frame{
		Version:         0,
		Type:            FrameTypeAssocRequest,
		SequenceControl: &seqControl,
		Addresses:       []MAC{a.BSSID, a.Client, a.BSSID},
		Payload:         buf.Bytes(),
	}
}

// An AssocResponse holds information about an association response frame.
type AssocResponse struct {
	BSSID  MAC
	Client MAC

	Capabilities  uint16
	StatusCode    uint16
	AssociationID uint16

	Elements Elements
}

// DecodeAssocResponse extracts association request information from a Frame.
func DecodeAssocResponse(f *Frame) (assocResponse *AssocResponse, err error) {
	if len(f.Payload) < 6 {
		return nil, ErrBufferUnderflow
	}

	var res AssocResponse

	res.Client = f.Addresses[0]
	res.BSSID = f.Addresses[1]

	res.Capabilities = binary.LittleEndian.Uint16(f.Payload)
	res.StatusCode = binary.LittleEndian.Uint16(f.Payload[2:])
	res.AssociationID = binary.LittleEndian.Uint16(f.Payload[4:])

	res.Elements, err = DecodeElements(f.Payload[6:])
	if err != nil {
		return
	}

	return &res, nil
}

// EncodeToFrame generates an 802.11 frame which represents this association response.
func (a *AssocResponse) EncodeToFrame() *Frame {
	var buf bytes.Buffer

	header := make([]byte, 6)
	binary.LittleEndian.PutUint16(header, a.Capabilities)
	binary.LittleEndian.PutUint16(header[2:], a.StatusCode)
	binary.LittleEndian.PutUint16(header[4:], a.AssociationID)

	buf.Write(header)
	buf.Write(a.Elements.Encode())

	var seqControl uint16
	return &Frame{
		Version:         0,
		Type:            FrameTypeAssocResponse,
		SequenceControl: &seqControl,
		Addresses:       []MAC{a.Client, a.BSSID, a.BSSID},
		Payload:         buf.Bytes(),
	}
}

// Success returns true if the association response indicates success.
func (a *AssocResponse) Success() bool {
	return a.StatusCode == 0
}
