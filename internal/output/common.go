package output

import (
	"fmt"
	"os"
	"strings"
	"time"
)

func GetCommand() string {
	return "nmap" + strings.Join(os.Args[1:], " ")
}

func ConvertTime(unixTime time.Time, format string) string {
	if format == "nmap-file" {
		parts := strings.Split(strings.Replace(unixTime.Format(time.RFC1123), ",", "", 1), " ")
		return fmt.Sprintf("%s %s %s %s %s", parts[0], parts[2], parts[1], parts[4], parts[3])
	} else if format == "nmap-stdout" {
		rawDate := strings.Split(unixTime.Format(time.RFC3339), "T")[0]
		formattedDate := strings.Replace(rawDate, ":", "-", -1)
		parts := strings.Split(unixTime.Format(time.RFC822), " ")
		return fmt.Sprintf("%s %s %s", formattedDate, parts[3], parts[4])
	}
	return fmt.Sprintf("%d", unixTime.Unix())
}

func Write(str string, dest string) {
	if dest == "-" {
		fmt.Print(str)
		return
	}
	f, err := os.OpenFile(dest, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fmt.Fprint(os.Stderr, "Failed to open output file %s for writing\n", dest)
		fmt.Fprint(os.Stderr, "QUITTING!\n")
		os.Exit(1)
	}
	f.WriteString(str)
	defer f.Close()
}
