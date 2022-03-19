package util

import (
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

func RemoveByIndex(array []string, index int) []string {
	array[index] = array[len(array)-1]
	return array[:len(array)-1]
}

func Contains(array []string, item string) bool {
	for _, thisItem := range array {
		if thisItem == item {
			return true
		}
	}
	return false
}
