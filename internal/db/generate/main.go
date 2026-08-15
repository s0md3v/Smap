package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

type capability struct {
	Cpe     string `json:"cpe"`
	Service string `json:"service"`
	Product string `json:"product,omitempty"`
	TLS     bool   `json:"tls"`
}

type evidenceKey struct {
	cpe     string
	service string
	tls     bool
}

type evidence struct {
	products map[string]map[string]int
	dynamic  bool
}

func escaped(value string, index int) bool {
	backslashes := 0
	for index--; index >= 0 && value[index] == '\\'; index-- {
		backslashes++
	}
	return backslashes%2 == 1
}

func fieldValue(value string, index int) (string, int, bool) {
	if index >= len(value) {
		return "", index, false
	}
	delimiter := value[index]
	start := index + 1
	for index = start; index < len(value); index++ {
		if value[index] == delimiter && !escaped(value, index) {
			result := value[start:index]
			result = strings.ReplaceAll(result, "\\"+string(delimiter), string(delimiter))
			return result, index + 1, true
		}
	}
	return "", index, false
}

func parseMatch(line string) (string, bool, string, []string, bool) {
	if !strings.HasPrefix(line, "match ") {
		return "", false, "", nil, false
	}
	rest := strings.TrimPrefix(line, "match ")
	serviceEnd := strings.IndexAny(rest, " \t")
	if serviceEnd < 1 {
		return "", false, "", nil, false
	}
	service := strings.ToLower(rest[:serviceEnd])
	tls := strings.HasPrefix(service, "ssl/")
	service = strings.TrimPrefix(service, "ssl/")
	rest = strings.TrimSpace(rest[serviceEnd:])
	if len(rest) < 3 || rest[0] != 'm' {
		return "", false, "", nil, false
	}
	_, index, ok := fieldValue(rest, 1)
	if !ok {
		return "", false, "", nil, false
	}
	for index < len(rest) && (rest[index] == 'i' || rest[index] == 's') {
		index++
	}

	product := ""
	cpes := []string{}
	for index < len(rest) {
		for index < len(rest) && (rest[index] == ' ' || rest[index] == '\t') {
			index++
		}
		if index >= len(rest) {
			break
		}
		if strings.HasPrefix(rest[index:], "cpe:") {
			index += 4
			value, next, valid := fieldValue(rest, index)
			if !valid {
				break
			}
			cpes = append(cpes, value)
			index = next
			if index < len(rest) && rest[index] == 'a' {
				index++
			}
			continue
		}
		field := rest[index]
		if !strings.ContainsRune("pvihod", rune(field)) || index+1 >= len(rest) {
			for index < len(rest) && rest[index] != ' ' && rest[index] != '\t' {
				index++
			}
			continue
		}
		value, next, valid := fieldValue(rest, index+1)
		if !valid {
			break
		}
		if field == 'p' {
			product = value
		}
		index = next
	}
	return service, tls, product, cpes, true
}

func cpeKey(value string) string {
	parts := strings.Split(value, ":")
	if len(parts) < 3 || parts[0] != "a" || strings.Contains(parts[1], "$") || strings.Contains(parts[2], "$") {
		return ""
	}
	return strings.Join(parts[:3], ":")
}

func normalizeProduct(value string) string {
	var builder strings.Builder
	space := false
	for _, character := range strings.ToLower(value) {
		if (character >= 'a' && character <= 'z') || (character >= '0' && character <= '9') {
			if space && builder.Len() != 0 {
				builder.WriteByte(' ')
			}
			builder.WriteRune(character)
			space = false
		} else {
			space = true
		}
	}
	return builder.String()
}

func consensusProduct(item evidence) string {
	if item.dynamic || len(item.products) != 1 {
		return ""
	}
	for _, displays := range item.products {
		values := make([]string, 0, len(displays))
		for display := range displays {
			values = append(values, display)
		}
		sort.Slice(values, func(i, j int) bool {
			if displays[values[i]] == displays[values[j]] {
				return values[i] < values[j]
			}
			return displays[values[i]] > displays[values[j]]
		})
		return values[0]
	}
	return ""
}

func main() {
	if len(os.Args) != 4 {
		panic("usage: generate nmap-service-probes ports.json capabilities.json")
	}
	tableData, err := os.ReadFile(os.Args[2])
	if err != nil {
		panic(err)
	}
	var table map[string]string
	if err := json.Unmarshal(tableData, &table); err != nil {
		panic(err)
	}
	services := map[string]bool{}
	for _, service := range table {
		services[strings.ToLower(service)] = true
	}

	source, err := os.Open(os.Args[1])
	if err != nil {
		panic(err)
	}
	defer source.Close()
	allEvidence := map[evidenceKey]evidence{}
	scanner := bufio.NewScanner(source)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for scanner.Scan() {
		service, tls, product, cpes, ok := parseMatch(scanner.Text())
		if !ok || !services[service] {
			continue
		}
		seen := map[string]bool{}
		for _, rawCPE := range cpes {
			keyCPE := cpeKey(rawCPE)
			if keyCPE == "" || seen[keyCPE] {
				continue
			}
			seen[keyCPE] = true
			key := evidenceKey{cpe: keyCPE, service: service, tls: tls}
			item := allEvidence[key]
			if item.products == nil {
				item.products = map[string]map[string]int{}
			}
			if strings.Contains(product, "$") {
				item.dynamic = true
			} else if product != "" {
				normalized := normalizeProduct(product)
				if item.products[normalized] == nil {
					item.products[normalized] = map[string]int{}
				}
				item.products[normalized][product]++
			}
			allEvidence[key] = item
		}
	}
	if err := scanner.Err(); err != nil {
		panic(err)
	}

	capabilities := make([]capability, 0, len(allEvidence))
	products := 0
	for key, item := range allEvidence {
		product := consensusProduct(item)
		if product != "" {
			products++
		}
		capabilities = append(capabilities, capability{Cpe: key.cpe, Service: key.service, Product: product, TLS: key.tls})
	}
	sort.Slice(capabilities, func(i, j int) bool {
		if capabilities[i].Service != capabilities[j].Service {
			return capabilities[i].Service < capabilities[j].Service
		}
		if capabilities[i].Cpe != capabilities[j].Cpe {
			return capabilities[i].Cpe < capabilities[j].Cpe
		}
		return !capabilities[i].TLS && capabilities[j].TLS
	})
	output, err := json.Marshal(capabilities)
	if err != nil {
		panic(err)
	}
	output = append(output, '\n')
	if err := os.WriteFile(os.Args[3], output, 0644); err != nil {
		panic(err)
	}
	fmt.Fprintf(os.Stderr, "Generated %d capabilities with %d consensus products.\n", len(capabilities), products)
}
