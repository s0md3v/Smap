package output

import (
	"encoding/json"
	"os"

	g "github.com/dylan1501/smap/internal/global"
)

var firstDone = false
var openedJsonFile *os.File

func StartJson() {
	firstDone = false
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
	CloseFile(openedJsonFile)
}
