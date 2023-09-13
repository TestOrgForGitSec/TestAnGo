package main

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	"github.com/cloudbees-compliance/chlog-go/log"
	domain "github.com/cloudbees-compliance/chplugin-go/v0.4.0/domainv0_4_0"
	service "github.com/cloudbees-compliance/chplugin-go/v0.4.0/servicev0_4_0"
	plugin "github.com/cloudbees-compliance/chplugin-service-go/plugin"
	scan "github.com/cloudbees-compliance/compliance-hub-plugin-anchore/scan"
	"github.com/cloudbees-compliance/compliance-hub-plugin-anchore/testdata"
	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

type PluginFetcher struct {
	plugin.AssetFetcher
}

func (f *PluginFetcher) FetchAssets(req plugin.AssetFetchRequest) ([]*domain.Asset, error) {
	var assets []*domain.Asset
	var assetProfiles []*domain.AssetProfile
	binaryAttribute := &domain.BinaryAttribute{Name: "imageName", Type: "PRIMARY", Version: "1.0", SourceType: domain.SourceType_STREAM, Data: []byte("{sampledata}")}
	assetProfile := &domain.AssetProfile{Uuid: "testProfileuuid", Identifier: "v1.0.1", Type: "BINARY", AttributesUuid: "testattriuuid"}

	assetProfile.BinAttributes = append(assetProfile.BinAttributes, binaryAttribute)
	assetProfiles = append(assetProfiles, assetProfile)
	asset := &domain.Asset{Uuid: "1", MasterAsset: &domain.MasterAsset{Type: "BINARY", SubType: "aws_ecr_repo", Identifier: "aws_ecr_repoarn:aws:ecr:us-east-1:1234567:repository/test/plugin-test"}, Profiles: assetProfiles}
	assets = append(assets, asset)

	//asset 2
	var assetProfiles2 []*domain.AssetProfile
	binaryAttribute2 := &domain.BinaryAttribute{Name: "imageName", Type: "PRIMARY", Version: "1.0", SourceType: domain.SourceType_STREAM, Data: []byte("{sampledata}")}
	assetProfile2 := &domain.AssetProfile{Uuid: "testProfileuuid", Identifier: "v1.0.1", Type: "BINARY", AttributesUuid: "testattriuuid"}

	assetProfile2.BinAttributes = append(assetProfile2.BinAttributes, binaryAttribute2)
	assetProfiles2 = append(assetProfiles2, assetProfile2)
	asset2 := &domain.Asset{Uuid: "1", MasterAsset: &domain.MasterAsset{Type: "BINARY", SubType: "dockerhub_repo", Identifier: "library/test"}, Profiles: assetProfiles2}
	assets = append(assets, asset2)

	//asset 3
	var assetProfiles3 []*domain.AssetProfile
	binaryAttribute3 := &domain.BinaryAttribute{Name: "imageName", Type: "PRIMARY", Version: "1.0", SourceType: domain.SourceType_STREAM, Data: []byte("{sampledata}")}
	assetProfile3 := &domain.AssetProfile{Uuid: "testProfileuuid", Identifier: "v1.0.1", Type: "BINARY", AttributesUuid: "testattriuuid"}

	assetProfile3.BinAttributes = append(assetProfile3.BinAttributes, binaryAttribute3)
	assetProfiles3 = append(assetProfiles3, assetProfile3)
	asset3 := &domain.Asset{Uuid: "1", MasterAsset: &domain.MasterAsset{Type: "BINARY", SubType: "artifactory_repo", Identifier: "https://jfrog.test.com/artifactory/test/plugin"}, Profiles: assetProfiles3}
	assets = append(assets, asset3)

	//asset 4
	var assetProfiles4 []*domain.AssetProfile
	binaryAttribute4 := &domain.BinaryAttribute{Name: "imageName", Type: "PRIMARY", Version: "1.0", SourceType: domain.SourceType_STREAM, Data: []byte("{sampledata}")}
	assetProfile4 := &domain.AssetProfile{Uuid: "testProfileuuid", Identifier: "v1.0.1", Type: "BINARY", AttributesUuid: "testattriuuid"}

	assetProfile4.BinAttributes = append(assetProfile4.BinAttributes, binaryAttribute4)
	assetProfiles4 = append(assetProfiles4, assetProfile4)
	asset4 := &domain.Asset{Uuid: "1", MasterAsset: &domain.MasterAsset{Type: "BINARY", SubType: "nexus_repo_binary", Identifier: "https://nexus.com/#browse/browse:docker-hosted-repo:v2/test"}, Profiles: assetProfiles4}
	assets = append(assets, asset4)

	return assets, nil
}

func (f *PluginFetcher) SendMessage(messageType service.MessageType, message proto.Message) error {
	return nil
}

func TestGetManifest(t *testing.T) {
	log.Debug().Msg("Inside TestGetManifest - Enter")
	anchore := NewAnchoreScanner()
	gmr := &service.GetManifestRequest{}
	res, err := anchore.GetManifest(context.Background(), gmr)
	assert.Nil(t, err)
	assert.Equal(t, 1, len(res.Manifest.AssetRoles))
	log.Debug().Msg("Inside TestGetManifest - Exit")
}

func TestGetAssetDescriptors(t *testing.T) {
	log.Debug().Msg("Inside TestGetAssetDescriptors - Enter")
	anchore := NewAnchoreScanner()
	gadr := &service.GetAssetDescriptorsRequest{}
	res, err := anchore.GetAssetDescriptors(context.Background(), gadr)
	assert.Nil(t, err)
	assert.Equal(t, 0, len(res.AssetDescriptors.GetAttributesDescriptors()))
	log.Debug().Msg("Inside TestGetAssetDescriptors - Exit")
}

func mockEcrExecuteRequest() *service.ExecuteRequest {
	acct := &domain.Account{Uuid: "12245"}
	str := []string{"aws_ecr_repo"}
	metadataStr := []byte(`{"url":"testurl","userName":"test","password":"test","accountName":"test"}`)
	assetIds := []string{"arn:aws:ecr:us-east-1:1234567:repository/test/plugin-test"}
	profileIds := []string{""}
	req := &service.ExecuteRequest{Account: acct, AssetType: "BINARY", AssetSubTypes: str, Metadata: metadataStr,
		AssetIdentifiers: assetIds, ProfileIdentifiers: profileIds}
	return req
}

func mockExecuteRequestErr() *service.ExecuteRequest {
	acct := &domain.Account{Uuid: "12245"}
	str := []string{"aws_ecr_repo"}
	metadataStr := []byte(`{"url""testurl","username":"test","password":"test","accountName":"test"}`)
	assetIds := []string{"arn:aws:ecr:us-east-1:1234567:repository/test/plugin-test"}
	profileIds := []string{""}
	req := &service.ExecuteRequest{Account: acct, AssetType: "BINARY", AssetSubTypes: str, Metadata: metadataStr,
		AssetIdentifiers: assetIds, ProfileIdentifiers: profileIds}
	return req
}

func TestExecuteAnalyserCredMapErr(t *testing.T) {
	log.Debug().Msg("TestExecuteAnalyserCredMapErr - Enter")
	anchore := NewAnchoreScanner()
	req := mockExecuteRequestErr()
	fetcher := &PluginFetcher{}
	res, err := anchore.ExecuteAnalyser(context.Background(), req, fetcher, nil)
	assert.Nil(t, res)
	assert.Equal(t, "invalid character '\"' after object key", err.Error())
	log.Debug().Msg("TestExecuteAnalyserCredMapErr - Exit")
}

func TestBuildEvaluations(t *testing.T) {
	log.Debug().Msg("TestBuildEvaluations - Enter")

	var vulnerabilityList []scan.VulnerabilityDetail
	vulnerabilitiesByte, _ := os.ReadFile("testdata/getVulnerabilities.json")
	json.Unmarshal(vulnerabilitiesByte, &vulnerabilityList)
	assetProfile := &domain.AssetProfile{Uuid: "testProfileuuid", Identifier: "v1.0.1", Type: "BINARY", AttributesUuid: "testattriuuid"}
	asset := &domain.Asset{Uuid: "1", MasterAsset: &domain.MasterAsset{Type: "BINARY", SubType: "subtype", Identifier: "localhost"}}

	evaluationList, err := buildEvaluations(context.Background(), &vulnerabilityList, asset, assetProfile)
	assert.Nil(t, err)
	assert.NotNil(t, evaluationList)
	log.Debug().Msg("TestBuildEvaluations - Exit")
}

func TestGetNetListener(t *testing.T) {
	log.Debug().Msg("TestGetNetListener - Enter")
	GetNetListener("127.0.0.1", 5001)
	getGrpcServer(1024*1024*1024, 3, 5)
	InitConfig()
	log.Debug().Msg("TestGetNetListener - Exit")
}

func TestExecuteAnalysersuccessecrrepo(t *testing.T) {
	log.Debug().Msg("TestExecuteAnalysersuccess - Enter")
	anchore := NewAnchoreScanner()
	req := mockEcrExecuteRequest()
	fetcher := &PluginFetcher{}

	testdata.MockGetSystemStatus("testdata/getimage.json")
	testdata.MockGetRegistries("testdata/getregistries.json")
	testdata.MockGetImage("testdata/getimage.json")
	testdata.MockGetVulnerabilities("testdata/getVulnerabilities.json")
	mockVar := testdata.HttpMock1{}

	scan.IAnchore = mockVar
	res, err := anchore.ExecuteAnalyser(context.Background(), req, fetcher, nil)
	assert.Nil(t, err)
	assert.NotNil(t, res)
	log.Debug().Msg("TestExecuteAnalysersuccess - Exit")

}
