# log4j-scanner
Log4j 2 (CVE-2021-44228) vulnerability scanner for Windows OS.

## Example Usage

![Terminal output from running .\log4j-scanner.exe in a terminal](https://i.imgur.com/VmlD9y8.png)

## Usage
```
.\log4j-scanner.exe

Terminal is used to output results, deploy this to machines via RMM and Start/Report from PowerShell or CMD Prompt.
```

## Build from source
```
git clone https://github.com/name/log4j-scanner.git
cd log4j-scanner/
go get github.com/shirou/gopsutil/disk
go build .
```

## How does it work?

After finding each avialable drive on the system this will find all .jar files that belong to 'log4j-core' and expand the jar archive to check if the vulnerable file 'JndiLookup.class' exists, if the file is present the path to the .jar file is reported back to the terminal.

## Changes?

I'm still in the early stages of learning GO so feel free to create a pull request with any changes!

## Compatibility
Compatible with Windows Server 2012+, Windows 7-10 and Windows Core.
