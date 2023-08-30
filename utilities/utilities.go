package utilities

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/cloudbees-compliance/chlog-go/log"
	domain "github.com/cloudbees-compliance/chplugin-go/v0.4.0/domainv0_4_0"
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

func GroupResourcesByVulnerability(vulnList *[]scan.VulnerabilityDetail) map[string][]*domain.DetailRow {

	resourceMap := map[string][]*domain.DetailRow{}

	for _, v := range *vulnList {
		detail, ok := resourceMap[v.CveId]
		nvdDataStr := fmt.Sprintf("%+v", v.NvdData)
		data := []string{v.Package, strings.Join(v.VendorData, ","), v.FeedGroup, v.PackageCpe, v.Url, nvdDataStr, strconv.FormatBool(v.WillNotFix)}
		if !ok {
			resourceMap[v.CveId] = append([]*domain.DetailRow{}, &domain.DetailRow{Data: data})
		} else {
			resourceMap[v.CveId] = append(detail, &domain.DetailRow{Data: data})
		}
	}

	return resourceMap
}

func MapToEvaluation(ctx context.Context, vulnList *[]scan.VulnerabilityDetail, asset *domain.Asset, ap *domain.AssetProfile, evalMap map[string]*domain.Evaluation) map[string]*domain.Evaluation {
	resourceMap := GroupResourcesByVulnerability(vulnList)
	reqId := GetRequestId(ctx)
	var eval *domain.Evaluation
	var ok bool
	vulnCategory := "VULNERABILITY"
	for _, v := range *vulnList {

		if eval, ok = evalMap[v.CveId]; !ok {
			ar := &domain.AssetResult{
				Asset:          asset.MasterAsset,
				AssetUuid:      asset.Uuid,
				AttributesUuid: ap.AttributesUuid,
				ProfileUuid:    ap.Uuid,
				Details:        resourceMap[v.CveId],
			}
			eval = &domain.Evaluation{
				Standard:      "STANDARD",
				Code:          v.CveId,
				Name:          v.CveId,
				Importance:    mapSeverity(reqId, v.Severity),
				Description:   "",
				Cvssv3:        "",
				DetailHeaders: []string{"Package", "Vendor Data", "Feed Group", "Package CPE", "URL", "NVD Data", "Will Not Fix"},
				DetailTypes:   []string{"string", "json", "string", "string", "csv[link]", "json", "string"},
				Category:      &vulnCategory,
				Failures:      []*domain.AssetResult{ar},
			}
			setBaseData(v, eval)
		} else {
			updateExistingEval(v, reqId, eval)
		}
		evalMap[v.CveId] = eval
	}
	return evalMap
}

func mapSeverity(reqId string, severity string) string {
	lower := strings.ToLower(severity)
	switch lower {
	case "high":
		return "HIGH"
	case "very_high", "critical", "error":
		return "VERY_HIGH"
	case "medium", "moderate":
		return "MEDIUM"
	case "low", "info":
		return "LOW"
	default:
		log.Warn(reqId).Msgf("Severity value : %s is defaulting to LOW", lower)
		return "LOW"
	}
}

func setBaseData(v scan.VulnerabilityDetail, eval *domain.Evaluation) {
	baseDataBytes, err := json.Marshal(v)
	if err == nil {
		eval.BaseData = baseDataBytes
		eval.Remediation = &v.Fix
	}
}

func updateExistingEval(v scan.VulnerabilityDetail, reqId string, eval *domain.Evaluation) {
	newSev := mapSeverity(reqId, v.Severity)
	if isNewSevVulnerable(eval.Importance, newSev) {
		eval.Importance = newSev
		setBaseData(v, eval)
		eval.Remediation = &v.Fix
	}
}

func isNewSevVulnerable(oldSev string, newSev string) bool {
	return scan.SeverityMap[oldSev] < scan.SeverityMap[newSev]
}
