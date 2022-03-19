package global

import (
	"time"
	"sync/atomic"
)

type count32 int32

func (c *count32) inc() int32 {
    return atomic.AddInt32((*int32)(c), 1)
}

func Increment(counter count32) {
	counter.inc()
}

var (
	PortList      []int
	ScanStartTime time.Time
	ScanEndTime   time.Time
	XmlFilename   string
	GrepFilename  string
	NmapFilename  string
	Args          map[string]string
	TotalHosts    count32
	AliveHosts    count32
)
