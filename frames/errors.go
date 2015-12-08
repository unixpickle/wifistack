package frames

import "errors"

var ErrBufferUnderflow = errors.New("buffer underflow")
var ErrBufferOverflow = errors.New("buffer overflow")
var ErrBadChecksum = errors.New("bad checksum")
