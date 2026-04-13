package core

import (
	"fmt"
	"strconv"
	"strings"
)

func expandAddressRange(str string) ([]string, error) {
	if !isAddressRange(str) {
		return nil, fmt.Errorf("%q is not a valid IPv4 range", str)
	}

	octets := strings.Split(str, ".")
	ranges := make([][]int, 0, len(octets))
	total := 1

	for _, octet := range octets {
		parts := strings.Split(octet, "-")
		start, _ := strconv.Atoi(parts[0])
		end := start
		if len(parts) == 2 {
			end, _ = strconv.Atoi(parts[1])
			if start > end {
				return nil, fmt.Errorf("%q is not a valid IPv4 range", str)
			}
		}

		values := make([]int, 0, end-start+1)
		for value := start; value <= end; value++ {
			values = append(values, value)
		}
		total *= len(values)
		ranges = append(ranges, values)
	}

	results := make([]string, 0, total)
	var current [4]int

	var build func(int)
	build = func(index int) {
		if index == len(ranges) {
			results = append(results, fmt.Sprintf("%d.%d.%d.%d", current[0], current[1], current[2], current[3]))
			return
		}
		for _, value := range ranges[index] {
			current[index] = value
			build(index + 1)
		}
	}

	build(0)
	return results, nil
}
