package wifistack

import "errors"

var ErrBufferUnderflow = errors.New("buffer underflow")
var ErrBadChecksum = errors.New("bad checksum")
