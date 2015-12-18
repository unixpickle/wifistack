package wifistack

import (
	"sync"
	"sync/atomic"
	"time"

	"github.com/unixpickle/wifistack/frames"
)

const dataResendTimeout = time.Millisecond * 10

// OpenMSDUStreamConfig stores the configuration for an OpenMSDUStream.
type OpenMSDUStreamConfig struct {
	// FragmentThreshold is the size, in bytes, at which MSDUs should be
	// fragmented into multiple MPDUs.
	FragmentThreshold int

	// DataRate is the data rate at which packets will be sent, in
	// units of 500Kb/s.
	DataRate int

	// BSSID is the BSS identifier for the access point.
	BSSID frames.MAC

	// Client is the MAC address of this client.
	Client frames.MAC

	// Stream is used to transfer raw 802.11 frames.
	Stream Stream
}

// OpenMSDUStream is an MSDUStream which sends and receives MSDUs from an open network.
// Currently, this does not support QoS, HCF, or PCF.
type OpenMSDUStream struct {
	// hasClosed is used to atomically ensure that closeChan is closed only once.
	hasClosed uint32

	// closeChan is closed by the first thing that causes the stream to close.
	closeChan chan struct{}

	config   OpenMSDUStreamConfig
	incoming chan MSDU
	outgoing chan MSDU

	// acks is used by the incoming loop to pass ack frames to the outgoing loop.
	acks chan *frames.Frame

	// wg waits for the incoming and outgoing loops to return.
	wg sync.WaitGroup

	// outgoingSequenceNum is the outgoing sequence number.
	// This is used by the outgoing loop.
	outgoingSequenceNum int
}

// NewOpenMSDUStream creates an OpenMSDUStream using a configuration.
// You must close the stream's outgoing channel once you are done with it.
func NewOpenMSDUStream(c OpenMSDUStreamConfig) *OpenMSDUStream {
	res := &OpenMSDUStream{
		closeChan: make(chan struct{}),
		config:    c,
		incoming:  make(chan MSDU, 16),
		outgoing:  make(chan MSDU),
		acks:      make(chan *frames.Frame, 16),
	}
	res.wg.Add(2)
	go res.incomingLoop()
	go res.outgoingLoop()
	go func() {
		res.wg.Wait()
		close(res.config.Stream.Outgoing())
	}()
	return res
}

// Incoming returns the incoming channel, which will be closed
// if the underlying stream is closed or encounters an error.
func (o *OpenMSDUStream) Incoming() <-chan MSDU {
	return o.incoming
}

// Outgoing returns the outgoing channel.
// You should close this once you are done with the MSDU stream.
// Closing this will close the underlying stream.
func (o *OpenMSDUStream) Outgoing() chan<- MSDU {
	return o.outgoing
}

// ForceClose will terminate any pending outgoing or incoming MSDUs.
// You should close the outgoing channel before using this.
func (o *OpenMSDUStream) ForceClose() {
	if atomic.SwapUint32(&o.hasClosed, 1) == 0 {
		close(o.closeChan)
	}
}

func (o *OpenMSDUStream) incomingLoop() {
	defer func() {
		o.ForceClose()
		close(o.incoming)
		o.wg.Done()
	}()
	for {
		select {
		case <-o.closeChan:
			return
		default:
		}

		select {
		case <-o.closeChan:
			return
		case packet, ok := <-o.config.Stream.Incoming():
			if !ok {
				return
			}
			frame, err := frames.DecodeFrame(packet.Frame)
			if err != nil {
				continue
			}

			if frame.Type == frames.FrameTypeData {
				if frame.FromDS && frame.Addresses[0] == o.config.Client &&
					frame.Addresses[1] == o.config.BSSID {
					if !o.handleIncomingData(frame) {
						return
					}
				}
			} else if frame.Type == frames.FrameTypeACK {
				if frame.Addresses[0] == o.config.Client {
					// NOTE: this select{} will prevent malicious clients from hanging the
					// loop by flooding us with fake ACKs.
					select {
					case o.acks <- frame:
					default:
					}
				}
			}
		}
	}
}

func (o *OpenMSDUStream) outgoingLoop() {
	defer func() {
		for {
			if _, ok := <-o.outgoing; !ok {
				break
			}
		}
		o.ForceClose()
		o.wg.Done()
	}()
	for {
		select {
		case <-o.closeChan:
			return
		default:
		}

		select {
		case msdu, ok := <-o.outgoing:
			if !ok {
				return
			}
			if !o.sendOutgoingData(msdu) {
				return
			}
		case <-o.closeChan:
			return
		}
	}
}

func (o *OpenMSDUStream) handleIncomingData(f *frames.Frame) bool {
	// TODO: this.
	return false
}

func (o *OpenMSDUStream) sendOutgoingData(msdu MSDU) bool {
	numFragments := len(msdu.Payload) / o.config.FragmentThreshold
	if len(msdu.Payload)%o.config.FragmentThreshold > 0 {
		numFragments++
	}

	sequenceNum := o.outgoingSequenceNum
	o.outgoingSequenceNum = (o.outgoingSequenceNum + 1) & 0xfff

	for i := 0; i < numFragments; i++ {
		startIndex := i * o.config.FragmentThreshold
		endIndex := (i + 1) * o.config.FragmentThreshold
		if endIndex > len(msdu.Payload) {
			endIndex = len(msdu.Payload)
		}
		piece := msdu.Payload[startIndex:endIndex]

		seqControl := uint16(i | (sequenceNum << 4))
		frame := &frames.Frame{
			Type:     frames.FrameTypeData,
			ToDS:     true,
			MoreData: i+1 < numFragments,
			Addresses: []frames.MAC{
				o.config.BSSID,
				o.config.Client,
				msdu.Remote,
			},
			Payload:         piece,
			SequenceControl: &seqControl,
		}
		// TODO: compute the DurationID here; for now we just use 2ms.
		frame.DurationID = 2000

	SendLoop:
		for {
			select {
			case o.config.Stream.Outgoing() <- frame.Encode():
			case <-o.closeChan:
				return false
			}

			ackTimeout := time.After(dataResendTimeout)
			for {
				select {
				case <-o.closeChan:
					return false
				case <-ackTimeout:
					frame.Retry = true
					continue SendLoop
				case <-o.acks:
					break SendLoop
				}
			}
		}
	}
	return true
}
