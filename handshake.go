package wifistack

import (
	"errors"
	"strconv"
	"time"

	"github.com/unixpickle/gofi"
	"github.com/unixpickle/wifistack/frames"
)

// HandshakeDurationID is used as the 802.11 frame DurationID for all the association
// and authentication frames.
// I got this value by analyzing traffic from my phone.
const HandshakeDurationID = 60

var ErrHandshakeTimeout = errors.New("handshake timed out")

type Handshaker struct {
	Stream Stream
	Client frames.MAC
	BSS    frames.BSSDescription
}

// HandshakeOpen performs the handshake for an open network.
func (h *Handshaker) HandshakeOpen(timeout time.Duration) error {
	timeoutChan := time.After(timeout)

	bssChannel := gofi.Channel{Number: h.BSS.Channel}
	if err := h.Stream.SetChannel(bssChannel); err != nil {
		return err
	}

	if err := h.authenticateOpen(timeoutChan); err != nil {
		return err
	}

	return h.associate(timeoutChan)
}

// authenticateOpen performs the authentication handshake for an open (or WPA) network.
func (h *Handshaker) authenticateOpen(timeout <-chan time.Time) error {
	authPacket := frames.NewAuthenticationOpen(h.BSS.BSSID, h.Client)
	authFrame := authPacket.EncodeToFrame()
	authFrame.DurationID = HandshakeDurationID

	h.Stream.Outgoing() <- OutgoingFrame{Frame: authFrame.Encode()}

	for {
		// NOTE: this guarantees that we will never read more than one packet
		// after the timeout expires.
		select {
		case <-timeout:
			return ErrHandshakeTimeout
		default:
		}

		select {
		case <-timeout:
			return ErrHandshakeTimeout
		case packet, ok := <-h.Stream.Incoming():
			if !ok {
				return h.Stream.FirstError()
			}
			frame, err := frames.DecodeFrame(packet.Frame)
			if err != nil {
				continue
			}
			if frame.Version != 0 || frame.Type != frames.FrameTypeAuthentication {
				continue
			}

			auth, err := frames.DecodeAuthentication(frame)
			if err != nil {
				continue
			}
			if auth.Addresses[0] != h.Client || auth.Addresses[1] != h.BSS.BSSID ||
				auth.Addresses[2] != h.BSS.BSSID {
				continue
			}

			ack := &frames.Frame{
				Type:      frames.FrameTypeACK,
				Addresses: []frames.MAC{auth.Addresses[2]},
			}
			h.Stream.Outgoing() <- OutgoingFrame{Frame: ack.Encode()}

			if auth.Success() {
				return nil
			} else {
				codeStr := strconv.Itoa(int(auth.StatusCode))
				return errors.New("authentication error: " + codeStr)
			}
		}
	}
}

// associate performs the association handshake for a network.
func (h *Handshaker) associate(timeout <-chan time.Time) error {
	assocReq := &frames.AssocRequest{
		BSSID:  h.BSS.BSSID,
		Client: h.Client,

		// NOTE: this is the interval my phone used.
		Interval: 3,

		Elements: frames.Elements{
			{frames.ElementIDSSID, []byte(h.BSS.SSID)},
			{frames.ElementIDSupportedRates, h.BSS.BasicRates},
		},
	}

	assocReqFrame := assocReq.EncodeToFrame()
	assocReqFrame.DurationID = HandshakeDurationID

	// The fragment number from the last packet was 0, so this one should be 1.
	seqControl := uint16(1 << 12)
	assocReqFrame.SequenceControl = &seqControl

	h.Stream.Outgoing() <- OutgoingFrame{Frame: assocReqFrame.Encode()}

	for {
		// NOTE: see the comment in authenticateOpen() to see why we need an extra select{}.
		select {
		case <-timeout:
			return ErrHandshakeTimeout
		default:
		}

		select {
		case <-timeout:
			return ErrHandshakeTimeout
		case packet, ok := <-h.Stream.Incoming():
			if !ok {
				return h.Stream.FirstError()
			}
			frame, err := frames.DecodeFrame(packet.Frame)
			if err != nil {
				continue
			}
			if frame.Version != 0 || frame.Type != frames.FrameTypeAssocResponse {
				continue
			}
			resp, err := frames.DecodeAssocResponse(frame)
			if err != nil {
				continue
			}
			if resp.BSSID != h.BSS.BSSID || resp.Client != h.Client {
				continue
			}

			ack := &frames.Frame{
				Type:      frames.FrameTypeACK,
				Addresses: []frames.MAC{resp.BSSID},
			}
			h.Stream.Outgoing() <- OutgoingFrame{Frame: ack.Encode()}

			if resp.Success() {
				return nil
			} else {
				codeStr := strconv.Itoa(int(resp.StatusCode))
				return errors.New("association error " + codeStr)
			}
		}
	}
}
