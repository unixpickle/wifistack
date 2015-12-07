package main

import (
	"log"
	"os"
	"strconv"

	"github.com/unixpickle/gofi"
	"github.com/unixpickle/wifistack"
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

	if err := handle.SetChannel(channel); err != nil {
		log.Fatalln("could not set channel:", err)
	}

	packetTypes := []wifistack.FrameType{
		wifistack.FrameTypeAssocRequest,
		wifistack.FrameTypeAssocResponse,
		wifistack.FrameTypeAuth,
	}
	for {
		rawFrame, _, err := handle.Receive()
		if err != nil {
			log.Fatalln("failed to receive:", err)
		}
		frame, err := wifistack.DecodeFrame(rawFrame)
		if err != nil {
			continue
		}

		// NOTE: on my WLAN, I occasionally receive almost completely 0'd packets
		// with a *correct* checksum. It is baffling.
		if frame.MAC1 == [6]byte{} {
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
		if frame.Type == wifistack.FrameTypeAssocRequest {
			assoc, err := wifistack.DecodeAssocRequest(frame)
			if err != nil {
				log.Println("Invalid assoc request:", frame)
			} else {
				log.Println("AssocReq:", assoc)
			}
		} else {
			log.Println(frame)
		}
	}
}
