package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/cloudbees-compliance/chlog-go/log"
	domain "github.com/cloudbees-compliance/chplugin-go/v0.4.0/domainv0_4_0"
	scan "github.com/cloudbees-compliance/compliance-hub-plugin-anchore/scan"
	utilities "github.com/cloudbees-compliance/compliance-hub-plugin-anchore/utilities"
)

func groupResourcesByVulnerability(vulnList *[]scan.VulnerabilityDetail) (map[string][]*domain.DetailRow, map[string][]scan.VulnerabilityDetail) {

	resourceMap := map[string][]*domain.DetailRow{}
	baseDataMap := map[string][]scan.VulnerabilityDetail{}

	for _, v := range *vulnList {
		detail, ok := resourceMap[v.CveId]
		nvdDataStr := fmt.Sprintf("%+v", v.NvdData)
		vendorStr := fmt.Sprintf("%+v", v.VendorData)
		data := []string{v.Package, vendorStr, v.FeedGroup, v.PackageCpe, v.Url, nvdDataStr, strconv.FormatBool(v.WillNotFix)}
		if !ok {
			resourceMap[v.CveId] = append([]*domain.DetailRow{}, &domain.DetailRow{Data: data})
		} else {
			resourceMap[v.CveId] = append(detail, &domain.DetailRow{Data: data})
		}
		baseDataList, ok := baseDataMap[v.CveId]
		if !ok {
			baseDataMap[v.CveId] = append([]scan.VulnerabilityDetail{}, v)
		} else {
			baseDataMap[v.CveId] = append(baseDataList, v)
		}
	}

	return resourceMap, baseDataMap
}

func mapToEvaluation(ctx context.Context, vulnList *[]scan.VulnerabilityDetail, asset *domain.Asset, ap *domain.AssetProfile, evalMap map[string]*domain.Evaluation) map[string]*domain.Evaluation {
	resourceMap, baseDataMap := groupResourcesByVulnerability(vulnList)
	reqId := utilities.GetRequestId(ctx)
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
				Standard:       "STANDARD",
				Code:           v.CveId,
				Name:           v.CveId,
				Importance:     mapSeverity(reqId, v.Severity),
				DetailHeaders:  []string{"Package", "Vendor Data", "Feed Group", "Package CPE", "URL", "NVD Data", "Will Not Fix"},
				DetailTypes:    []string{String, "json", String, String, "csv[link]", "json", String},
				DetailContexts: []string{Summary, Detail, Summary, Summary, Detail, Detail, Detail},
				Category:       &vulnCategory,
				Failures:       []*domain.AssetResult{ar},
				BaseData:       getBaseData(baseDataMap[v.CveId]),
				Remediation:    &v.Fix,
			}
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

func getBaseData(v []scan.VulnerabilityDetail) []byte {
	baseDataBytes, err := json.Marshal(v)
	if err == nil {
		return baseDataBytes
	} else {
		return nil
	}
}

func updateExistingEval(v scan.VulnerabilityDetail, reqId string, eval *domain.Evaluation) {
	newSev := mapSeverity(reqId, v.Severity)
	if isNewSevVulnerable(eval.Importance, newSev) {
		eval.Importance = newSev
	}
}

func isNewSevVulnerable(oldSev string, newSev string) bool {
	return SeverityMap[oldSev] < SeverityMap[newSev]
}
