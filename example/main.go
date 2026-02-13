package main

import (
	"flag"
	"fmt"
	"log"
	"math/rand"
	"strings"
	"time"

	"dotpad"
)

var (
	clearData = strings.Repeat("00", dotpad.GraphicLen)
)

func main() {
	text := flag.Bool("text", false, "display as text (vs. graphic")
	hex := flag.Bool("hex", false, "the input is already an hexadecimal string")
	uni := flag.Bool("unicode", false, "print Braille unicode")
	cclear := flag.Bool("clear", false, "clear before display")
	flag.Parse()

	var hexData string

	if flag.NArg() == 0 {
		if *text {
			hexData = strings.Repeat("BB", dotpad.TextLen)
		} else {
			var sb strings.Builder

			for i := 0; i < dotpad.GraphicLen; i++ {
				sb.WriteString(fmt.Sprintf("%02x", i%0xFF))
			}

			hexData = sb.String()
		}
	} else if *hex {
		hexData = strings.Join(flag.Args(), "")
	} else {
		textData := strings.Join(flag.Args(), " ")
		hexData = dotpad.ToBrailleHex(textData, ! *text)

		if *uni {
			fmt.Println(dotpad.ToBrailleUnicode(textData))
			fmt.Println(dotpad.ToBrailleHex(textData, false))
		}
	}

	sdk := dotpad.NewDotPadSDK()

	log.Println("connecting...")
	device, err := sdk.Request(10 * time.Second)
	if err != nil {
		log.Fatalf("connect to device: %v", err)
	}

	log.Println("connected to", sdk.DotPadName)
	defer func() {
		if err := sdk.Disconnect(device); err != nil {
			log.Printf("disconnect: %v", err)
		}
	}()

	if err := sdk.AddListenerKeyEvent(device, func(code string) {
		log.Printf("key event: %s", code)

		switch code {
		case dotpad.LP:
			if err := sdk.ResetTextData(device); err != nil {
				log.Println("Error clearing text")
			}
			if err := sdk.ResetGraphicData(device); err != nil {
				log.Println("Error clearing graphic")
			}
		case dotpad.F1:
			if err := sdk.DisplayTextData(device, hexData); err != nil {
				log.Println("display text:", err)
			}
		case dotpad.F2:
			if err := sdk.DisplayGraphicData(device, hexData); err != nil {
				log.Println("display graphic:", err)
			}
		case dotpad.F3:
			var sb strings.Builder

			for i := 0; i < dotpad.TextLen; i++ {
				c := rand.Intn(256)
				sb.WriteString(fmt.Sprintf("%02x", c))
			}
			if err := sdk.DisplayTextData(device, sb.String()); err != nil {
				log.Println("display text:", err)
			}
		case dotpad.F4:
			var sb strings.Builder

			for i := 0; i < dotpad.GraphicLen; i++ {
				c := rand.Intn(256)
				sb.WriteString(fmt.Sprintf("%02x", c))
			}
			if err := sdk.DisplayGraphicData(device, sb.String()); err != nil {
				log.Println("display graphic:", err)
			}
		case dotpad.RP:
			buffer := "FF" + clearData[2:]
			ll := len(clearData[2:])

			for i := 0; i < dotpad.GraphicLen; i++ {
				//fmt.Println(i, buffer)

				if err := sdk.DisplayGraphicData(device, buffer); err != nil {
					log.Println("display graphic:", err)
					break
				}

				buffer = buffer[ll:] + buffer[:ll]
				time.Sleep(400 * time.Millisecond)
			}
		}
	}); err != nil {
		log.Fatalf("add listener: %v", err)
	}

	if *cclear {
		if err := sdk.ResetTextData(device); err != nil {
			log.Println("Error clearing text")
		}
		if err := sdk.ResetGraphicData(device); err != nil {
			log.Println("Error clearing graphic")
		}
	}

	if *text {
		if err := sdk.DisplayTextData(device, hexData); err != nil {
			log.Println("display text:", err)
		}
	} else {
		if err := sdk.DisplayGraphicData(device, hexData); err != nil {
			log.Println("display graphic:", err)
		}
	}

	select {}
}
