package output

import (
	"strings"

	g "github.com/dylan1501/smap/internal/global"
)

func scriptText(script g.Script) string {
	if script.Output != "" {
		return script.Output
	}
	lines := scriptElementLines(script.Elements, 0)
	return strings.Join(lines, "\n")
}

func scriptElementLines(elements []g.ScriptElement, depth int) []string {
	lines := make([]string, 0)
	indent := strings.Repeat("  ", depth)
	for _, element := range elements {
		label := element.Key
		if label == "" {
			label = element.Kind
		}
		switch {
		case len(element.Elements) == 0 && element.Value == "":
			lines = append(lines, indent+label)
		case len(element.Elements) == 0 && label == "":
			lines = append(lines, indent+element.Value)
		case len(element.Elements) == 0:
			lines = append(lines, indent+label+": "+element.Value)
		default:
			header := indent + label + ":"
			if element.Value != "" {
				header += " " + element.Value
			}
			lines = append(lines, header)
			lines = append(lines, scriptElementLines(element.Elements, depth+1)...)
		}
	}
	return lines
}
