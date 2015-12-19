package wifistack

import (
	"time"

	"github.com/unixpickle/wifistack/frames"
)

const scanChannelTime = time.Second / 5

// ScanNetworks asynchronously scans for wireless networks.
//
// When the scan is complete, the output channel will be closed.
// To complete the scan early, you may close the cancel channel.
//
// While the scan is running, this will continually read from and (possibly)
// write to the stream.
func ScanNetworks(s Stream) (descs <-chan frames.BSSDescription, cancel chan<- struct{}) {
	descChan := make(chan frames.BSSDescription)
	cancelChan := make(chan struct{})

	go func() {
		defer close(descChan)

		bssMap := map[frames.MAC]bool{}

		// TODO: remove channels with duplicate channel numbers but different widths.
		for _, ch := range s.SupportedChannels() {
			select {
			case <-cancelChan:
				return
			default:
			}

			if s.SetChannel(ch) != nil {
				return
			}

			timeout := time.After(scanChannelTime)

		PacketLoop:
			for {
				select {
				case packet, ok := <-s.Incoming():
					if !ok {
						return
					}
					frame, err := frames.DecodeFrame(packet.Frame)
					if err != nil || frame.Version != 0 ||
						frame.Type != frames.FrameTypeBeacon {
						continue
					}
					beacon, err := frames.DecodeBeacon(frame)
					if err != nil {
						continue
					}
					description := beacon.BSSDescription()
					if !bssMap[description.BSSID] {
						bssMap[description.BSSID] = true
						descChan <- description
					}
				case <-cancelChan:
					return
				case <-timeout:
					break PacketLoop
				}
			}
		}
	}()

	return descChan, cancelChan
}
