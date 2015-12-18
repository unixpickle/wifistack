package wifistack

import "github.com/unixpickle/wifistack/frames"

type MSDU struct {
	Remote  frames.MAC
	Payload []byte
}

// An MSDUStream sends and receives MAC service data units.
type MSDUStream interface {
	// Incoming returns the channel to which incoming MSDUs are delivered.
	// When the stream is closed, this channel will be closed as well.
	//
	// If the stream encounters an error, this channel will be closed.
	// In this case, you still have to close the outgoing channel in order
	// to signify that you are done with the stream.
	Incoming() <-chan MSDU

	// Outgoing returns the channel to which outgoing MSDUs should be sent.
	// You should close() this channel once you are done with the stream.
	Outgoing() chan<- MSDU

	// ForceClose forces the stream to close, even if there are pending outgoing MSDUs.
	// You should close the outgoing channel before using it.
	// If you do not use this, there is no guarantee that the stream will ever close,
	// since sending an outgoing frame may take forever if the AP goes out of range.
	ForceClose()
}
