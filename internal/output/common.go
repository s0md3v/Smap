package output

import (
	"fmt"
	"os"
	"strings"
	"time"

	g "github.com/dylan1501/smap/internal/global"
)

func GetCommand() string {
	args := make([]string, 0, len(os.Args)-1)
	skipNext := false
	for _, token := range os.Args[1:] {
		if skipNext {
			skipNext = false
			continue
		}
		switch {
		case token == "--active":
			continue
		case token == "--append-output":
			continue
		case token == "--concurrency":
			skipNext = true
			continue
		case strings.HasPrefix(token, "--concurrency="):
			continue
		default:
			args = append(args, token)
		}
	}
	return "nmap " + strings.Join(args, " ")
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

func OpenFile(filepath string) *os.File {
	flags := os.O_CREATE | os.O_WRONLY | os.O_TRUNC
	if _, ok := g.Args["append-output"]; ok {
		flags = os.O_CREATE | os.O_WRONLY | os.O_APPEND
	}
	f, err := os.OpenFile(filepath, flags, 0644)
	if err != nil {
		fmt.Fprint(os.Stderr, fmt.Sprintf("Failed to open output file %s for writing\n", filepath))
		fmt.Fprint(os.Stderr, "QUITTING!\n")
		os.Exit(1)
	}
	return f
}

func Write(str string, dest string, openedFile *os.File) {
	if dest == "-" {
		fmt.Print(str)
		return
	}
	openedFile.WriteString(str)
}

func CloseFile(openedFile *os.File) {
	if openedFile != nil {
		openedFile.Close()
	}
}
