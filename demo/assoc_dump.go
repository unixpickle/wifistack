package main

import (
	"log"
	"os"
	"strconv"

	"github.com/unixpickle/gofi"
	"github.com/unixpickle/wifistack/frames"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatalln("Usage: assoc_dump <channel>")
	}

	channel, err := strconv.Atoi(os.Args[1])
	if err != nil {
		log.Fatalln("invalid channel:", os.Args[1])
	}

	name, err := gofi.DefaultInterfaceName()
	if err != nil {
		log.Fatalln("no default interface:", err)
	}
	handle, err := gofi.NewHandle(name)
	if err != nil {
		log.Fatalln("could not open handle:", err)
	}

	if err := handle.SetChannel(gofi.Channel{Number: channel}); err != nil {
		log.Fatalln("could not set channel:", err)
	}

	packetTypes := []frames.FrameType{
		frames.FrameTypeAssocRequest,
		frames.FrameTypeAssocResponse,
		frames.FrameTypeAuthentication,
	}
	for {
		rawFrame, _, err := handle.Receive()
		if err != nil {
			log.Fatalln("failed to receive:", err)
		}
		frame, err := frames.DecodeFrame(rawFrame)
		if err != nil {
			continue
		}

		// NOTE: on my WLAN, I occasionally receive almost completely 0'd packets
		// with a *correct* checksum. It is baffling.
		if frame.MAC1 == (frames.MAC{}) {
			continue
		}

		shouldDrop := true
		for _, t := range packetTypes {
			if t == frame.Type {
				shouldDrop = false
				break
			}
		}
		if shouldDrop {
			continue
		}
		switch frame.Type {
		case frames.FrameTypeAssocRequest:
			assoc, err := frames.DecodeAssocRequest(frame)
			if err != nil {
				log.Println("Invalid Association Request:", frame)
			} else {
				log.Println("Association Request:", assoc)
			}
		case frames.FrameTypeAssocResponse:
			assoc, err := frames.DecodeAssocResponse(frame)
			if err != nil {
				log.Println("Invalid Association Response:", frame)
			} else {
				log.Println("Association Response:", assoc)
			}
		default:
			log.Println(frame)
		}
		if frame.Type == frames.FrameTypeAssocRequest {
		} else {

		}
	}
}
