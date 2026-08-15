package core

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strconv"
	"strings"

	g "github.com/s0md3v/smap/internal/global"
)

func validateNmapMode() error {
	if _, err := exec.LookPath("nmap"); err != nil {
		return fmt.Errorf("nmap is required for --nmap")
	}
	return nil
}

func candidatePortUnion(results []g.Output) []int {
	seen := map[int]bool{}
	ports := make([]int, 0)
	for _, result := range results {
		for _, port := range result.Ports {
			if seen[port.Port] {
				continue
			}
			seen[port.Port] = true
			ports = append(ports, port.Port)
		}
	}
	sort.Ints(ports)
	return ports
}

func nmapPortList(ports []int) string {
	parts := make([]string, 0, len(ports))
	for _, port := range ports {
		parts = append(parts, strconv.Itoa(port))
	}
	return strings.Join(parts, ",")
}

func shouldPrefilterNmap(args map[string]string, targets []string) bool {
	if len(targets) == 0 {
		if _, ok := args["iL"]; !ok {
			return false
		}
	}
	if _, ok := args["sL"]; ok {
		return false
	}
	if _, ok := args["sn"]; ok {
		return false
	}
	return true
}

func isAttachedPortArgument(arg string) bool {
	if len(arg) < 3 || !strings.HasPrefix(arg, "-p") {
		return false
	}
	if arg[2] == '-' || arg[2] == '=' || arg[2] >= '0' && arg[2] <= '9' {
		return true
	}
	return len(arg) > 3 && strings.ContainsRune("TUSP", rune(arg[2])) && arg[3] == ':'
}

func buildNmapArgs(ports []int, stdinTargets string, narrow bool) []string {
	raw := os.Args[1:]
	args := make([]string, 0, len(raw)+2)
	for index := 0; index < len(raw); index++ {
		arg := raw[index]
		switch {
		case arg == "--nmap":
			continue
		case arg == "--concurrency":
			index++
			continue
		case strings.HasPrefix(arg, "--concurrency="):
			continue
		case narrow && arg == "-p":
			index++
			continue
		case narrow && isAttachedPortArgument(arg):
			continue
		case narrow && arg == "-F":
			args = append(args, "--top-ports", "100")
			continue
		case stdinTargets != "" && arg == "-iL" && index+1 < len(raw) && raw[index+1] == "-":
			args = append(args, "-iL", stdinTargets)
			index++
			continue
		case stdinTargets != "" && arg == "-iL=-":
			args = append(args, "-iL", stdinTargets)
			continue
		default:
			args = append(args, arg)
		}
	}
	if narrow {
		args = append(args, "-p", nmapPortList(ports))
	}
	return args
}

func runNmap(ports []int, stdinTargets string, narrow bool) int {
	cmd := exec.Command("nmap", buildNmapArgs(ports, stdinTargets, narrow)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		var exitError *exec.ExitError
		if errors.As(err, &exitError) {
			return exitError.ExitCode()
		}
		fmt.Fprintf(os.Stderr, "Failed to run Nmap: %v\n", err)
		return 1
	}
	return 0
}
