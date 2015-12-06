package wifistack

import (
	"bytes"
	"sort"
)

func decodeManagementTags(buf []byte) (map[int][]byte, error) {
	res := map[int][]byte{}
	i := 0
	for i+2 < len(buf) {
		tagType := int(buf[i])
		length := int(buf[i+1])
		if length+i+2 > len(buf) {
			return nil, ErrBufferUnderflow
		}
		res[tagType] = buf[i+2 : i+2+length]
		i += 2 + length
	}
	if i < len(buf) {
		return nil, ErrBufferOverflow
	}
	return res, nil
}

func encodeManagementTags(tags map[int][]byte) []byte {
	var buf bytes.Buffer

	// NOTE: the specification says that these should be encoded in order.
	tagIds := make([]int, 0, len(tags))
	for tag := range tags {
		tagIds = append(tagIds, tag)
	}
	sort.Ints(tagIds)

	for _, tag := range tagIds {
		value := tags[tag]
		buf.WriteByte(byte(tag))
		buf.WriteByte(byte(len(value)))
		buf.Write(value)
	}

	return buf.Bytes()
}
