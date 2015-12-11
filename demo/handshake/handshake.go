package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/unixpickle/gofi"
	"github.com/unixpickle/wifistack"
	"github.com/unixpickle/wifistack/frames"
)

const Timeout = time.Second * 5

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

	fmt.Print("Pick a number from the list: ")
	choice := readChoice()
	if choice < 0 || choice >= len(descriptions) {
		log.Fatalln("choice out of bounds.")
	}

	handshaker := wifistack.Handshaker{
		Stream: stream,
		Client: frames.MAC{0, 1, 2, 3, 4, 5},
		BSS:    descriptions[choice],
	}
	if err := handshaker.HandshakeOpen(time.Second * 5); err != nil {
		log.Fatalln("handshake failed:", err)
	} else {
		log.Println("handshake successful!")
	}
}

func readChoice() int {
	s := ""
	for {
		b := make([]byte, 1)
		if _, err := os.Stdin.Read(b); err != nil {
			log.Fatalln(err)
		}
		if b[0] == '\n' {
			break
		} else if b[0] == '\r' {
			continue
		} else {
			s += string(b)
		}
	}

	num, err := strconv.Atoi(s)
	if err != nil {
		log.Fatalln("invalid number:", s)
	}
	return num
}
