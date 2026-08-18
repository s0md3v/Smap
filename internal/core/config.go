package core

import (
	"fmt"
	"strconv"

	g "github.com/s0md3v/smap/internal/global"
)

const defaultConcurrency = 3
const defaultShodanRPS = 1.0

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

func getShodanRPS() (float64, error) {
	if value, ok := g.Args["shodan-rate"]; ok {
		parsed, err := strconv.ParseFloat(value, 64)
		if err != nil || parsed <= 0 {
			return 0, fmt.Errorf("--shodan-rate must be a positive number")
		}
		return parsed, nil
	}
	return defaultShodanRPS, nil
}
