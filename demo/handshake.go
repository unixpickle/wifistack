package main

import (
	"log"
	"os"
	"strconv"
	"time"

	"github.com/unixpickle/gofi"
	"github.com/unixpickle/wifistack"
	"github.com/unixpickle/wifistack/frames"
)

const Timeout = time.Second*5

func main() {
	if len(os.Args) != 5 {
		log.Fatalln("Usage: <client MAC> <BSSID MAC> <SSID> <channel>")
	}

	clientMAC, err := frames.ParseMAC(os.Args[1])
	if err != nil {
		log.Fatalln("invalid client MAC:", err)
	}
	bssidMAC, err := frames.ParseMAC(os.Args[2])
	if err != nil {
		log.Fatalln("invalid client MAC:", err)
	}
	ssid := os.Args[3]
	channel, err := strconv.Atoi(os.Args[4])
	if err != nil {
		log.Fatalln("invalid channel:", err)
	}

	interfaceName, err := gofi.DefaultInterfaceName()
	if err != nil {
		log.Fatalln("no default interface:", err)
	}
	handle, err := gofi.NewHandle(interfaceName)
	if err != nil {
		log.Fatalln("could not open handle to "+interfaceName+":", err)
	}
	defer handle.Close()

	handle.SetChannel(channel)

	stream := wifistack.NewRawStream(handle)
	if err := wifistack.AuthenticateOpen(stream, bssidMAC, clientMAC, Timeout); err != nil {
		log.Fatalln("could not authenticate:", err)
	}
	log.Println("authenticated!")
	if err := wifistack.Associate(stream, bssidMAC, clientMAC, ssid, Timeout); err != nil {
		log.Fatalln("could not associate:", err)
	}
	log.Println("associated!")
}
