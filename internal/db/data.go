package db

import _ "embed"

//go:embed capabilities.json
var Capabilities []byte

//go:embed ports.json
var Ports []byte
