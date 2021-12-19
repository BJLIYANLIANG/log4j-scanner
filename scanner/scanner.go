package scanner

import (
	"archive/zip"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/shirou/gopsutil/disk"
)

// Scan :
func Scan() []string {
	log.Println("[+] Scanning for CVE-2021-45105.")
	var detections []string
	partitions, _ := disk.Partitions(true)
	for _, partition := range partitions {
		log.Println("[%] Scanning '" + partition.Mountpoint + "' for CVE-2021-45105 vulnerability.")
		e := filepath.Walk(partition.Mountpoint+"/", func(path string, f os.FileInfo, err error) error {
			if strings.Contains(path, "log4j") {
				if strings.HasSuffix(path, ".jar") {
					r, err := zip.OpenReader(path)
					if err != nil {
						panic(err)
					}
					for _, f := range r.File {
						if strings.Contains(f.Name, "JndiLookup.class") {
							log.Println("[*] Found CVE-2021-45105: " + path)
							detections = append(detections, path)
						}
					}
				}
			}
			return nil
		})

		if e != nil {
			log.Println(e)
		}
	}
	return detections
}
