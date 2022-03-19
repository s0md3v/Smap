package output

import (
	"os"
	"encoding/json"

	g "github.com/s0md3v/smap/internal/global"
)

var firstDone = false
var openedJsonFile *os.File

func StartJson() {
	if g.JsonFilename != "-" {
		openedGrepFile = OpenFile(g.JsonFilename)
	}
	Write("[", g.JsonFilename, openedJsonFile)
}

func ContinueJson(output g.Output) {
	prefix := ""
	if firstDone {
		prefix = ","
	}
	firstDone = true
	jsoned , _ := json.Marshal(&output)
	Write(prefix + string(jsoned), g.JsonFilename, openedJsonFile)
}

func EndJson() {
	Write("]", g.JsonFilename, openedJsonFile)
	defer openedJsonFile.Close()
}