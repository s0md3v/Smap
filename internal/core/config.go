package core

import (
	"fmt"
	"strconv"

	g "github.com/dylan1501/smap/internal/global"
)

const defaultConcurrency = 3

func parsePositiveInt(raw string, name string) (int, error) {
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 {
		return 0, fmt.Errorf("%s must be a positive integer", name)
	}
	return value, nil
}

func getConcurrency() (int, error) {
	if value, ok := g.Args["concurrency"]; ok {
		return parsePositiveInt(value, "--concurrency")
	}
	return defaultConcurrency, nil
}
