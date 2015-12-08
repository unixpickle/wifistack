package wifistack

import (
	"sync"

	"github.com/unixpickle/gofi"
)

// A RawStream provides a channel-based API for reading and writing
// to and from a gofi.Handle.
type RawStream struct {
	handle gofi.Handle

	incoming <-chan gofi.RadioPacket
	outgoing chan<- gofi.Frame

	receiveFailed chan struct{}

	firstErrLock sync.Mutex
	firstErr     error
}

// NewRawStream creates a raw stream which wraps a gofi.Handle.
// After you call this, you should not manually access the
// handle anymore, even to close it.
func NewRawStream(h gofi.Handle) *RawStream {
	incoming := make(chan gofi.RadioPacket, 16)
	outgoing := make(chan gofi.Frame)
	res := &RawStream{
		handle:        h,
		incoming:      incoming,
		outgoing:      outgoing,
		receiveFailed: make(chan struct{}),
	}
	go res.incomingLoop(incoming)
	go res.outgoingLoop(outgoing)
	return res
}

// FirstError returns the first error encountered when reading or writing
// to the underlying handle.
// This can be used to figure out why a stream closed early.
func (s *RawStream) FirstError() error {
	s.firstErrLock.Lock()
	defer s.firstErrLock.Unlock()
	return s.firstErr
}

// Incoming returns the channel of incoming radio packets.
// This channel will be closed when the stream is closed.
func (s *RawStream) Incoming() <-chan gofi.RadioPacket {
	return s.incoming
}

// Outgoing returns the channel of outgoing frames.
// To write to the stream, write to this channel.
// To close the stream, simply close this channel.
func (s *RawStream) Outgoing() chan<- gofi.Frame {
	return s.outgoing
}

// SetChannel sets the wireless channel of the underlying handle.
func (s *RawStream) SetChannel(i int) error {
	return s.handle.SetChannel(i)
}

// Channel returns the wireless channel of the underlying handle.
func (s *RawStream) Channel() int {
	return s.handle.Channel()
}

func (s *RawStream) incomingLoop(ch chan<- gofi.RadioPacket) {
	defer func() {
		close(ch)
		close(s.receiveFailed)
	}()
	for {
		frame, radio, err := s.handle.Receive()
		if err != nil {
			s.setFirstErr(err)
			return
		}
		ch <- gofi.RadioPacket{frame, radio}
	}
}

func (s *RawStream) outgoingLoop(ch <-chan gofi.Frame) {
	defer s.handle.Close()
	for {
		select {
		case f, ok := <-ch:
			if !ok {
				return
			} else if err := s.handle.Send(f); err != nil {
				s.setFirstErr(err)
				return
			}
		case <-s.receiveFailed:
			return
		}
	}
}

func (s *RawStream) setFirstErr(err error) {
	s.firstErrLock.Lock()
	if s.firstErr == nil {
		s.firstErr = err
	}
	s.firstErrLock.Unlock()
}
