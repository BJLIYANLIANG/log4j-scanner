package main

import (
	"log"

	"github.com/name/log4j-scanner/scanner"
)

func main() {
	log.Println("[+] CVE-2021-45105 - Apache Log4j RCE Scanning Tool.")
	var detections = scanner.Scan()
	log.Println("Found vulnerabilities:")
	for _, detection := range detections {
		log.Println(detection)
	}
}
