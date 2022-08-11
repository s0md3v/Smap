package global

import (
	"sync/atomic"
	"time"
)

type count32 int32

func (c *count32) inc() int32 {
	return atomic.AddInt32((*int32)(c), 1)
}

func Increment(counterType int) {
	if counterType == 0 {
		TotalHosts.inc()
	} else {
		AliveHosts.inc()
	}
}

var (
	PortList      []int
	ScanStartTime time.Time
	ScanEndTime   time.Time
	XmlFilename   string
	GrepFilename  string
	NmapFilename  string
	JsonFilename  string
	SmapFilename  string
	PairFilename  string
	Args          map[string]string
	TotalHosts    count32
	AliveHosts    count32
	Version       = "0.1.2"
)
