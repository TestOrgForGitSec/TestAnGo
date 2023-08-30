package utilities

import (
	"context"
	"strings"

	"github.com/cloudbees-compliance/chlog-go/log"
	scan "github.com/cloudbees-compliance/compliance-hub-plugin-anchore/scan"
)

func GetRequestId(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	requestId, ok := ctx.Value("requestId").(string)
	if !ok {
		log.Error().Msg("Unable to get request id. Using main logger.")
		requestId = ""
	}
	return requestId
}

func GetValidURL(url string) string {
	url = strings.TrimSpace(url)
	url = strings.TrimRight(url, "/")
	if len(url) > 0 {
		if !strings.HasPrefix(url, scan.HttpProtocol) && !strings.HasPrefix(url, scan.HttpsProtocol) {
			url = scan.HttpsProtocol + url
		}
	}
	return url
}
