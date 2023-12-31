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

var NexusPorts = []string{
	":5002",
	":5003",
	":5004",
}

type ImageDetails struct {
	ImageDigest string `json:"imageDigest,omitempty"`
	ImageTag    string `json:"imageTag,omitempty"`
}
