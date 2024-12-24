package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/KennyZ69/portslibK/privileges"
	"github.com/KennyZ69/portslibK/scanner"
)

func main() {
	start := time.Now()

	if len(os.Args) != 4 {
		fmt.Printf("Usage: %s <target IP> <target Port> <scan type>\n", os.Args[0])
		return
	}
	// get the privileges
	privileges.Init()

	targetIP := net.ParseIP(os.Args[1])
	targetPort, err := strconv.Atoi(os.Args[2])
	if err != nil {
		log.Fatalf("Invalid port provided: %v\n", err)
	}
	var portArr []int
	portArr = append(portArr, targetPort)
	sType := os.Args[3]

	s, err := scanner.CreateScanner(sType, targetIP, portArr, time.Second*2)
	if err != nil {
		log.Fatalf("Couldn't create new scanner: %v\n", err)
	}

	if err = s.Start(); err != nil {
		log.Fatalf("Scan failed: %v\n", err)
	}

	s.Stop()

	elapsed := time.Since(start)
	log.Printf("Scan took %s\n", elapsed)
}
