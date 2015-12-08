package main

import (
	"log"
	"time"

	"github.com/unixpickle/gofi"
	"github.com/unixpickle/wifistack/frames"
)

func main() {
	interfaceName, err := gofi.DefaultInterfaceName()
	if err != nil {
		log.Fatalln("no default interface:", err)
	}
	handle, err := gofi.NewHandle(interfaceName)
	if err != nil {
		log.Fatalln("could not open handle to "+interfaceName+":", err)
	}
	defer handle.Close()

	// Constantly hop between channels.
	go func() {
		for {
			for i := 1; i < 14; i++ {
				handle.SetChannel(i)
				time.Sleep(time.Second / 10)
			}
		}
	}()

	for {
		frameData, _, err := handle.Receive()
		if err != nil {
			log.Fatalln("receive error:", err)
		}
		frame, err := frames.DecodeFrame(frameData)
		if err != nil {
			continue
		}
		if frame.Beacon() {
			beacon, err := frames.DecodeBeacon(frame)
			if err != nil {
				log.Println("got invalid beacon:", err)
			} else {
				log.Println("got beacon:", beacon.SSID())
			}
		}
	}
}
