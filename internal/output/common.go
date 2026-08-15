package output

import (
	"fmt"
	"os"
	"strings"
	"time"

	g "github.com/s0md3v/smap/internal/global"
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
		case token == "--nmap":
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
		return unixTime.Format("Mon Jan _2 15:04:05 2006")
	} else if format == "nmap-stdout" {
		return unixTime.Format("2006-01-02 15:04 -0700")
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
