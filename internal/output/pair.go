package output

import (
	"fmt"
	"os"

	g "github.com/s0md3v/smap/internal/global"
)

var openedPairFile *os.File

func StartPair() {
	if g.PairFilename != "-" {
		openedPairFile = OpenFile(g.PairFilename)
	}
}

func ContinuePair(result g.Output) {
	thisString := ""
	for _, port := range result.Ports {
		thisString += fmt.Sprintf("%s:%d\n", result.IP, port.Port)
	}
	Write(thisString, g.PairFilename, openedPairFile)
}

func EndPair() {
}
