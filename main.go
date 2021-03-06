// IP Address Parser
// Created by Don Franke
// This takes a list of domains/URLs/URIs and formats them into a Splunk proxy log search.

package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"strings"
)

// Read a whole file into the memory and store it as array of lines
func readLines(path string) (lines []string, err error) {
	var (
		file   *os.File
		part   []byte
		prefix bool
	)
	if file, err = os.Open(path); err != nil {
		return
	}
	defer file.Close()

	reader := bufio.NewReader(file)
	buffer := bytes.NewBuffer(make([]byte, 0))
	for {
		if part, prefix, err = reader.ReadLine(); err != nil {
			break
		}
		buffer.Write(part)
		if !prefix {
			lines = append(lines, buffer.String())
			buffer.Reset()
		}
	}
	if err == io.EOF {
		err = nil
	}
	return
}

func main() {
	// get filename from comamnd line
	filename := flag.String("u", "", "Name of URLs File")
	includewww := flag.String("www", "", "Indicate (Y/N) whether or not to include a www. version of the domain in the results")
	flag.Parse()

	if *filename == "" || *includewww == "" {
		log.Fatal("EXECUTION HALTED: Not enough arguments supplied. Usage:\n" + showUsage())
	}

	// read file
	lines, err := readLines(*filename)
	if err != nil {
		log.Fatal("ERROR: %s\n", err)
	}
	// display contents
	var spl string
	var url string
	spl = "index=proxy ("
	var i = 0
	for _, line := range lines {
		line = strings.Trim(line, " ")
		if line == "" {
			continue
		}
		url = line

		// de-sanitize value
		r := regexp.MustCompile(`\[[\.\,]\]`)
		url = r.ReplaceAllString(url, ".")

		// remove quotes and double quotes
		r = regexp.MustCompile(`[\"\'"]`)
		url = r.ReplaceAllString(url, "")

		// remove string preceeding ://
		r = regexp.MustCompile(`\w*:\/\/`)
		url = r.ReplaceAllString(url, "")

		// remove [dot]
		r = regexp.MustCompile(`\[dot\]`)
		url = r.ReplaceAllString(url, ".")

		// remove leading arrows
		r = regexp.MustCompile(`-->`)
		url = r.ReplaceAllString(url, "")

		// remove uri stuff
		r = regexp.MustCompile(`\/.+`)
		url = r.ReplaceAllString(url, "")

		// remove domain:
		r = regexp.MustCompile(`domain:\s`)
		url = r.ReplaceAllString(url, "")

		// trim whitespace
		url = strings.Trim(url, " ")

		if i == 0 {
			spl += "dest_host=\"" + url + "\""
		} else {
			spl += " OR dest_host=\"" + url + "\""
		}
		if *includewww == "Y" {
			spl += " OR dest_host=\"www." + url + "\""
		}
		i++
	}
	spl += ")"
	fmt.Println(strings.Repeat("=", 30) + " SNIP " + strings.Repeat("=", 30))
	fmt.Println(spl)
	fmt.Println(strings.Repeat("=", 30) + " /SNIP " + strings.Repeat("=", 30))
}

func showUsage() string {
	var message string
	message = strings.Repeat("-", 75) + "\n"
	message += "\t-u = path/file of URL file\n"
	message += "\t-www = whether or not to include a www.[url] in results [Y/N]\n"
	message += strings.Repeat("-", 75) + "\n"
	return message
}
