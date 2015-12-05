package main

import (
	"log"
	"time"

	"github.com/unixpickle/gofi"
	"github.com/unixpickle/wifistack"
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
		frame, err := wifistack.DecodeFrame(frameData)
		if err != nil {
			continue
		}
		if frame.Beacon() {
			beacon, err := wifistack.DecodeBeacon(frame)
			if err != nil {
				log.Println("got invalid beacon:", err)
			} else {
				log.Println("got beacon:", beacon.SSID())
			}
		} else {
			log.Println("got frame with payload of", len(frame.Payload), "bytes")
		}
	}
}
