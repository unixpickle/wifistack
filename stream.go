package wifistack

import "github.com/unixpickle/gofi"

// A Stream is an abstract interface which can transfer 802.11 frames.
type Stream interface {
	// Incoming returns the channel to which incoming packets are delivered.
	// When the stream is closed, this channel will be closed as well.
	Incoming() <-chan gofi.RadioPacket

	// Outgoing returns the channel to which outgoing packets should be sent.
	// You can close() this channel to close the stream.
	Outgoing() chan<- gofi.Frame

	// Channel returns the wireless channel to which the stream is tuned.
	Channel() int

	// SetChannel modifies the wireless channel to which the stream is tuned.
	// Some types of Stream may not support channel hopping, in which case
	// this will return an error.
	SetChannel(i int) error
}
