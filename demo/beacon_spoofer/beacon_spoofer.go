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

	handle.SetChannel(gofi.Channel{Number: 11})

	var beacon frames.Beacon
	beacon.Capabilities = 1057
	beacon.Interval = 25

	copy(beacon.BSSID[1:], []byte("HELLO"))
	beacon.Elements = frames.Elements{
		{frames.ElementIDSSID, []byte("Spoofed Network")},
		{frames.ElementIDDSSSParameterSet, []byte{11}},
	}
	frameData := beacon.EncodeToFrame().Encode()
	for {
		if err := handle.Send(frameData); err != nil {
			log.Fatalln("failed to send beacon:", err)
		}
		time.Sleep(time.Second / 40)
	}
}
