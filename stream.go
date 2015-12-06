package wifistack

import (
	"sync"

	"github.com/unixpickle/gofi"
)

// A Stream provides a channel-based API for reading and writing
// to and from a gofi.Handle.
type Stream struct {
	handle gofi.Handle

	incoming <-chan gofi.RadioPacket
	outgoing chan<- gofi.Frame

	closeChan chan struct{}
	wg        sync.WaitGroup

	firstErrLock sync.Mutex
	firstErr     error
}

// NewStream creates a stream which wraps a gofi.Handle.
// After you call this, you should not manually access the
// handle anymore, even to close it.
func NewStream(h gofi.Handle) *Stream {
	incoming := make(chan gofi.RadioPacket, 16)
	outgoing := make(chan gofi.Frame)
	res := &Stream{
		handle:    h,
		incoming:  incoming,
		outgoing:  outgoing,
		closeChan: make(chan struct{}),
	}
	res.wg.Add(2)
	go res.incomingLoop(incoming)
	go res.outgoingLoop(outgoing)
	return res
}

// Close closes the stream.
// By the time this returns, both the incoming and outgoing
// channels will be closed.
func (s *Stream) Close() {
	close(s.closeChan)
	s.handle.Close()
	s.wg.Wait()
}

// FirstError returns the first error encountered when reading or writing
// to the underlying handle.
// This can be used to figure out why a stream closed early.
func (s *Stream) FirstError() error {
	s.firstErrLock.Lock()
	defer s.firstErrLock.Unlock()
	return s.firstErr
}

// Incoming returns the channel of incoming radio packets.
// This channel will be closed when the stream is closed.
func (s *Stream) Incoming() <-chan gofi.RadioPacket {
	return s.incoming
}

// Outgoing returns the channel of outgoing frames.
// To close the stream, simply close this channel.
func (s *Stream) Outgoing() chan<- gofi.Frame {
	return s.outgoing
}

// SetChannel sets the channel of the underlying handle.
func (s *Stream) SetChannel(i int) error {
	return s.handle.SetChannel(i)
}

// Channel returns the channel of the underlying handle.
func (s *Stream) Channel() int {
	return s.handle.Channel()
}

func (s *Stream) incomingLoop(ch chan<- gofi.RadioPacket) {
	defer func() {
		s.handle.Close()
		close(ch)
		s.wg.Done()
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

func (s *Stream) outgoingLoop(ch <-chan gofi.Frame) {
	defer func() {
		s.wg.Done()
	}()
	for {
		select {
		case f, ok := <-ch:
			if !ok {
				s.handle.Close()
				return
			}
			if err := s.handle.Send(f); err != nil {
				s.setFirstErr(err)
				s.handle.Close()
				return
			}
		case <-s.closeChan:
			return
		}
	}
}

func (s *Stream) setFirstErr(err error) {
	s.firstErrLock.Lock()
	if s.firstErr == nil {
		s.firstErr = err
	}
	s.firstErrLock.Unlock()
}
