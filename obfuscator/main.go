package main

import (
	"fmt"
	"flag"
	"strings"

	// Own modules
	"obfuscator/internal/helpers"
	"obfuscator/internal/ipv4"
)

func main() {
	// Defining available flags
	payloadPtr := flag.String("payload", "", "payload which should be executed")
	payloadFilePtr := flag.String("payloadFile", "", "Path to file with payload")
	obfuscateToIPv4Ptr := flag.Bool("toIPv4", false, "Obfuscate payload to IPv4 list")
	restoreFromIPv4Ptr := flag.Bool("fromIPv4", false, "Restore from payload")

	// Parse all falgs
	flag.Parse()

	// If no payload given, we have nothing to do
	if len(*payloadPtr) == 0 && len(*payloadFilePtr) == 0 {
		fmt.Println("[X] No payload given... nothing to do...")
		return
	}
	payload := *payloadPtr

	// Obfuscate payload to IPv4 comma separated list
	// Prints to stdout
	if *obfuscateToIPv4Ptr {
		chunk := ipv4.ObfuscateToIPv4(payload)
		fmt.Println(strings.Join(chunk, ","))
		return
	}

	if len(*payloadFilePtr) != 0 {
		payload = helpers.GetContentFromFileWithChecks(payloadFilePtr)
		if *restoreFromIPv4Ptr && len(payload) > 0{
			payload = ipv4.DeobfuscateFromIPv4(strings.Split(payload, ","))
		}
	}

	fmt.Println("[i] Done with obfuscating.")	
}
