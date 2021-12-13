package main

import (
	"archive/zip"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/shirou/gopsutil/disk"
)

var (
	detectionCount = 0
	className      = ""
)

func main() {
	run()
	fmt.Printf("\nFound %v vulnerable files", detectionCount)
}

func run() ([]string, error) {

	fileList := make([]string, 0)

	partitions, _ := disk.Partitions(false)
	for _, partition := range partitions {
		fmt.Println("Scanning '" + partition.Mountpoint + "' for CVE-2021-44228 vulnerability")
		e := filepath.Walk(partition.Mountpoint, func(path string, f os.FileInfo, err error) error {
			if strings.Contains(path, "log4j-core") {
				if strings.HasSuffix(path, ".jar") {
					r, err := zip.OpenReader(path)
					if err != nil {
						panic(err)
					}

					for _, f := range r.File {
						className = f.Name
						if strings.Contains(className, "JndiLookup.class") {
							fileList = append(fileList, "[*] Found CVE-2021-44228 vulnerability in "+path)
							detectionCount = detectionCount + 1
						}
					}
				}
			}
			return nil
		})

		if e != nil {
			panic(e)
		}
	}

	for _, file := range fileList {
		fmt.Println(file)
	}

	return fileList, nil
}
