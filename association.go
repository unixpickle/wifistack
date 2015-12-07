package wifistack

import "encoding/binary"

// An AssocRequest stores information about an association request.
type AssocRequest struct {
	BSSID  [6]byte
	Client [6]byte

	Capabilities uint16
	Interval     uint16

	Elements ManagementElements
}

// DecodeAssocRequest extracts association request information from a Frame.
func DecodeAssocRequest(f *Frame) (assocRequest *AssocRequest, err error) {
	if len(f.Payload) < 4 {
		return nil, ErrBufferUnderflow
	}

	var res AssocRequest

	res.BSSID = f.MAC1
	res.Client = f.MAC2

	// TODO: figure out if these are really supposed to be little endian.
	res.Capabilities = binary.LittleEndian.Uint16(f.Payload)
	res.Interval = binary.LittleEndian.Uint16(f.Payload[2:])

	res.Elements, err = DecodeManagementElements(f.Payload[4:])
	if err != nil {
		return
	}

	return &res, nil
}
