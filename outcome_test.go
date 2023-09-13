package main

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	log "github.com/cloudbees-compliance/chlog-go/log"
	domain "github.com/cloudbees-compliance/chplugin-go/v0.4.0/domainv0_4_0"
	scan "github.com/cloudbees-compliance/compliance-hub-plugin-anchore/scan"
	"github.com/stretchr/testify/assert"
)

func TestMapToEvaluation(t *testing.T) {
	log.Debug().Msg("Inside TestMapToEvaluation - Enter")
	var vulnerabilityList []scan.VulnerabilityDetail
	vulnerabilitiesByte, _ := os.ReadFile("testdata/getVulnerabilities.json")
	json.Unmarshal(vulnerabilitiesByte, &vulnerabilityList)
	var assetProfiles []*domain.AssetProfile
	assetProfile := &domain.AssetProfile{Uuid: "testProfileuuid", Identifier: "v1.0.1", Type: "BINARY", AttributesUuid: "testattriuuid"}
	assetProfiles = append(assetProfiles, assetProfile)
	asset := &domain.Asset{Uuid: "1", MasterAsset: &domain.MasterAsset{Type: "BINARY", SubType: "subtype", Identifier: "localhost"}, Profiles: assetProfiles}
	evaluationMap := mapToEvaluation(context.Background(), &vulnerabilityList, asset, assetProfile, map[string]*domain.Evaluation{})
	assert.Equal(t, 93, len(evaluationMap))
	assert.NotEmpty(t, evaluationMap)
	log.Debug().Msg("Inside TestMapToEvaluation - Exit")
}
