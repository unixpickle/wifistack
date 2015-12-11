package main

import (
	"fmt"
	"log"

	"github.com/unixpickle/gofi"
	"github.com/unixpickle/wifistack"
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

	fmt.Println("BSS Descriptions:")

	stream := wifistack.NewRawStream(handle)
	scanRes, _ := wifistack.ScanNetworks(stream)
	descriptions := []frames.BSSDescription{}
	for desc := range scanRes {
		fmt.Println(len(descriptions), "-", desc.BSSID, desc.SSID)
		descriptions = append(descriptions, desc)
	}
}
