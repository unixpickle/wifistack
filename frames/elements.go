package frames

import "bytes"

// An Element represents an informational element from a management frame.
type Element struct {
	ID    ElementID
	Value []byte
}

// Elements is an ordered list of Element values.
type Elements []Element

// DecodeElements decodes an array of informational elements from a management frame's body.
func DecodeElements(buf []byte) (Elements, error) {
	res := Elements{}
	i := 0
	for i+2 < len(buf) {
		id := ElementID(buf[i])
		length := int(buf[i+1])
		if length+i+2 > len(buf) {
			return nil, ErrBufferUnderflow
		}
		value := buf[i+2 : i+2+length]
		res = append(res, Element{id, value})
		i += 2 + length
	}
	if i < len(buf) {
		return nil, ErrBufferOverflow
	}
	return res, nil
}

// Encode generates a binary representation of the informational elements.
func (m Elements) Encode() []byte {
	var buf bytes.Buffer
	for _, pair := range m {
		buf.WriteByte(byte(pair.ID))
		buf.WriteByte(byte(len(pair.Value)))
		buf.Write(pair.Value)
	}
	return buf.Bytes()
}

// Get looks up the value for an element, returning nil if the element was absent.
func (m Elements) Get(t ElementID) []byte {
	for _, pair := range m {
		if pair.ID == t {
			return pair.Value
		}
	}
	return nil
}
