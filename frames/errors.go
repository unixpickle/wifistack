package frames

import "errors"

var (
	ErrBufferUnderflow     = errors.New("buffer underflow")
	ErrBufferOverflow      = errors.New("buffer overflow")
	ErrBadChecksum         = errors.New("bad checksum")
	ErrInvalidMAC          = errors.New("invalid MAC")
	ErrUnknownFrameType    = errors.New("unknown frame type")
	ErrUnknownFrameVersion = errors.New("unknown frame version")
)
