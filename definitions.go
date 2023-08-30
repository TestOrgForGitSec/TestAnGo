package main

const CHRequestId = "ch-request-id"
const AssetType = "BINARY"
const Summary = "SUMMARY"
const Detail = "DETAIL"
const String = "string"

var SeverityMap = map[string]int{
	"":          0,
	"LOW":       1,
	"MEDIUM":    2,
	"HIGH":      3,
	"VERY_HIGH": 4,
}
