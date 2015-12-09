package wifistack

import (
	"errors"
	"strconv"
	"time"

	"github.com/unixpickle/wifistack/frames"
)

// HandshakeDurationID is used as the 802.11 frame DurationID for all the association
// and authentication frames.
// I got this value by analyzing traffic from my phone.
const HandshakeDurationID = 15360

// AuthenticateOpen performs the authentication handshake for an open network.
func AuthenticateOpen(s Stream, bssid, client [6]byte, timeout time.Duration) error {
	timeoutChan := time.After(timeout)

	authPacket := frames.NewAuthenticationOpen(bssid, client)
	authFrame := authPacket.EncodeToFrame()
	authFrame.DurationID = HandshakeDurationID
	authFrame.SequenceControl = 57422

	s.Outgoing() <- authFrame.Encode()

	for {
		select {
		case packet, ok := <-s.Incoming():
			s.Outgoing() <- authFrame.Encode()
			if !ok {
				return s.FirstError()
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
			if auth.MAC1 != client || auth.MAC2 != bssid || auth.MAC3 != bssid {
				continue
			}
			if auth.Success() {
				return nil
			} else {
				codeStr := strconv.Itoa(int(auth.StatusCode))
				return errors.New("authentication error: " + codeStr)
			}
		case <-timeoutChan:
			return errors.New("authentication timed out")
		}
	}
}

// Associate performs the association handshake for a network.
// You may only associate with a network once you are authenticated with it.
func Associate(s Stream, bssid, client [6]byte, ssid string, timeout time.Duration) error {
	timeoutChan := time.After(timeout)

	assocReq := &frames.AssocRequest{
		BSSID:  bssid,
		Client: client,

		// NOTE: this is the interval my phone used.
		Interval: 3,

		Elements: frames.ManagementElements{
			{frames.ManagementTagSSID, []byte(ssid)},
		},
	}

	assocReqFrame := assocReq.EncodeToFrame()
	assocReqFrame.DurationID = HandshakeDurationID

	// The fragment number from the last packet was 0, so this one should be 1.
	assocReqFrame.SequenceControl = (1 << 12)

	s.Outgoing() <- assocReqFrame.Encode()

	for {
		select {
		case packet, ok := <-s.Incoming():
			if !ok {
				return s.FirstError()
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
			if resp.BSSID != bssid || resp.Client != client {
				continue
			}
			if resp.Success() {
				return nil
			} else {
				codeStr := strconv.Itoa(int(resp.StatusCode))
				return errors.New("association error " + codeStr)
			}
		case <-timeoutChan:
			return errors.New("association timed out")
		}
	}
}
