package wifistack

import (
	"time"

	"github.com/unixpickle/gofi"
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

		for _, ch := range scanChannels(s) {
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

func scanChannels(s Stream) []gofi.Channel {
	res := []gofi.Channel{}
	usedNumbers := map[int]bool{}
	for _, ch := range s.SupportedChannels() {
		if !usedNumbers[ch.Number] {
			usedNumbers[ch.Number] = true
			res = append(res, ch)
		}
	}
	return res
}
