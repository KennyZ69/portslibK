package scanner

import (
	"fmt"
	"io"
	"log"
	"net"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func TCPScan(targetIP net.IP, port int, semaphore chan struct{}) (string, error) {
	semaphore <- struct{}{}
	defer func() { <-semaphore }()

	target := fmt.Sprintf("%s:%d", targetIP.String(), port)
	c, err := net.DialTimeout("tcp", target, time.Second*2)
	if err != nil {
		if strings.Contains(err.Error(), "too many open files") {
			time.Sleep(time.Second * 2)
			TCPScan(targetIP, port, semaphore)
		} else {
			fmt.Println("TCP - Port", port, "closed on", targetIP.String())
			return "", fmt.Errorf("Error dialing to port %d: %v\n", port, err)
		}
	}

	defer c.Close()

	fmt.Printf("TCP - Port %d is open on %s\n", port, targetIP.String())

	h, err := getPortHeader(c)
	if err != nil || h == "" {
		// return fmt.Errorf("Error getinng port header: %v\n", err)
		fmt.Printf("\nCouldn't get the header for port %d on %s: %v\n", port, targetIP.String(), err)
	} else {
		fmt.Printf("\nHeader for port %d on %s: %s\n", port, targetIP.String(), h)
	}
	return fmt.Sprintf("TCP scan went succesfully\n"), nil

}

func getPortHeader(c net.Conn) (string, error) {
	buf := make([]byte, 2048)
	c.SetReadDeadline(time.Now().Add(time.Second * 3))

	n, err := c.Read(buf)
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("Error reading to buffer")
	}

	h := strings.TrimSpace(string(buf[:n]))

	return h, nil
}

func getProtocol(c net.Conn, ip net.IP, port int) (string, error) {
	if port == 80 || port == 8080 {
		fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s \r\n\r\n", ip.String())
	}

	return "", nil
}

func ulimit() int {
	out, err := exec.Command("sh", "-c", "ulimit -n").Output()
	if err != nil {
		log.Fatalf("Error getting routines limit: %v\n", err) // end point for the program
	}

	s := strings.TrimSpace(string(out))
	ulimit, err := strconv.Atoi(s)
	// if err != nil || s == "unlimited" {
	// 	// log.Fatal(err)
	// 	return 100
	// }
	if err != nil {
		log.Fatal(err)
	}

	return ulimit
}
