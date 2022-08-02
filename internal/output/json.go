package output

import (
	"encoding/json"
	"os"

	g "github.com/s0md3v/smap/internal/global"
)

var firstDone = false
var openedJsonFile *os.File

func StartJson() {
	if g.JsonFilename != "-" {
		openedJsonFile = OpenFile(g.JsonFilename)
	}
	Write("[", g.JsonFilename, openedJsonFile)
}

func ContinueJson(result g.Output) {
	prefix := ""
	if firstDone {
		prefix = ","
	}
	firstDone = true
	jsoned, _ := json.Marshal(&result)
	Write(prefix+string(jsoned), g.JsonFilename, openedJsonFile)
}

func EndJson() {
	Write("]", g.JsonFilename, openedJsonFile)
	defer openedJsonFile.Close()
}
