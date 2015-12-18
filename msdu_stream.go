package wifistack

// An MSDUStream sends and receives MAC service data units.
type MSDUStream interface {
	// Incoming returns the channel to which incoming MSDUs are delivered.
	// When the stream is closed, this channel will be closed as well.
	Incoming() <-chan []byte

	// Outgoing returns the channel to which outgoing MSDUs should be sent.
	// You should close() this channel once you are done with the stream.
	Outgoing() chan<- []byte
}
