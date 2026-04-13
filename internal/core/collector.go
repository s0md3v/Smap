package core

import g "github.com/s0md3v/smap/internal/global"

func collectOutput(done chan<- []g.Output) {
	results := []g.Output{}
	for output := range outputChannel {
		results = append(results, output)
		activeOutputs.Done()
	}
	done <- results
}
