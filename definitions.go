package main

const CHRequestId = "ch-request-id"
const AssetType = "BINARY"
const FilePerm = 0755
const MaskedValue = "**********"

var SeverityMap = map[string]int{
	"":          0,
	"LOW":       1,
	"MEDIUM":    2,
	"HIGH":      3,
	"VERY_HIGH": 4,
}
