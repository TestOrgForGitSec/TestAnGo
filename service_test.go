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
	//Aws Ecr Asset
	var assets []*domain.Asset
	var ecrAssetProfiles []*domain.AssetProfile
	ecrBinaryAttribute := &domain.BinaryAttribute{Name: "imageName", Type: "PRIMARY", Version: "1.0", SourceType: domain.SourceType_STREAM, Data: []byte("{sampledata}")}
	ecrAssetProfile := &domain.AssetProfile{Uuid: "testProfileuuid", Identifier: "v1.0.1", Type: "BINARY", AttributesUuid: "testattriuuid"}

	ecrAssetProfile.BinAttributes = append(ecrAssetProfile.BinAttributes, ecrBinaryAttribute)
	ecrAssetProfiles = append(ecrAssetProfiles, ecrAssetProfile)
	ecrAsset := &domain.Asset{Uuid: "1", MasterAsset: &domain.MasterAsset{Type: "BINARY", SubType: "aws_ecr_repo", Identifier: "arn:aws:ecr:us-east-1:1234567:repository/test/plugin-test"}, Profiles: ecrAssetProfiles}
	assets = append(assets, ecrAsset)

	//Docker asset
	var dockerAssetProfiles []*domain.AssetProfile
	dockerBinaryAttribute := &domain.BinaryAttribute{Name: "imageName", Type: "PRIMARY", Version: "1.0", SourceType: domain.SourceType_STREAM, Data: []byte("{sampledata}")}
	dockerAssetProfile := &domain.AssetProfile{Uuid: "testProfileuuid", Identifier: "v1.0.1", Type: "BINARY", AttributesUuid: "testattriuuid"}

	dockerAssetProfile.BinAttributes = append(dockerAssetProfile.BinAttributes, dockerBinaryAttribute)
	dockerAssetProfiles = append(dockerAssetProfiles, dockerAssetProfile)
	dockerAsset := &domain.Asset{Uuid: "1", MasterAsset: &domain.MasterAsset{Type: "BINARY", SubType: "dockerhub_repo", Identifier: "library/test"}, Profiles: dockerAssetProfiles}
	assets = append(assets, dockerAsset)

	//Jfrog asset
	var jfrogAssetProfiles []*domain.AssetProfile
	jfrogBinaryAttribute := &domain.BinaryAttribute{Name: "imageName", Type: "PRIMARY", Version: "1.0", SourceType: domain.SourceType_STREAM, Data: []byte("{sampledata}")}
	jfrogAssetProfile := &domain.AssetProfile{Uuid: "testProfileuuid", Identifier: "v1.0.1", Type: "BINARY", AttributesUuid: "testattriuuid"}

	jfrogAssetProfile.BinAttributes = append(jfrogAssetProfile.BinAttributes, jfrogBinaryAttribute)
	jfrogAssetProfiles = append(jfrogAssetProfiles, jfrogAssetProfile)
	jfrogAsset := &domain.Asset{Uuid: "1", MasterAsset: &domain.MasterAsset{Type: "BINARY", SubType: "artifactory_repo", Identifier: "https://jfrog.test.com/artifactory/test/plugin"}, Profiles: jfrogAssetProfiles}
	assets = append(assets, jfrogAsset)

	//Nexus asset
	var nexusAssetProfiles []*domain.AssetProfile
	nexusBinaryAttribute := &domain.BinaryAttribute{Name: "imageName", Type: "PRIMARY", Version: "1.0", SourceType: domain.SourceType_STREAM, Data: []byte("{sampledata}")}
	nexusAssetProfile := &domain.AssetProfile{Uuid: "testProfileuuid", Identifier: "v1.0.1", Type: "BINARY", AttributesUuid: "testattriuuid"}

	nexusAssetProfile.BinAttributes = append(nexusAssetProfile.BinAttributes, nexusBinaryAttribute)
	nexusAssetProfiles = append(nexusAssetProfiles, nexusAssetProfile)
	nexusAsset := &domain.Asset{Uuid: "1", MasterAsset: &domain.MasterAsset{Type: "BINARY", SubType: "nexus_repo_binary", Identifier: "https://nexus.com/#browse/browse:docker-hosted-repo:v2/test"}, Profiles: nexusAssetProfiles}
	assets = append(assets, nexusAsset)

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

	evaluationList, err := buildEvaluations("123", &vulnerabilityList, asset, assetProfile)
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

func TestExecuteAnalyserSuccess(t *testing.T) {
	log.Debug().Msg("TestExecuteAnalyserSuccess - Enter")
	anchore := NewAnchoreScanner()
	req := mockEcrExecuteRequest()
	fetcher := &PluginFetcher{}

	testdata.MockGetSystemStatus("testdata/getsystemstatus.json")
	testdata.MockGetRegistries("testdata/getregistries.json")
	testdata.MockGetImage("testdata/getimage.json")
	testdata.MockGetVulnerabilities("testdata/getVulnerabilities.json")
	mockVar := testdata.HttpMock1{}

	scan.IAnchore = mockVar
	res, err := anchore.ExecuteAnalyser(context.Background(), req, fetcher, nil)
	assert.Nil(t, err)
	assert.NotNil(t, res)
	log.Debug().Msg("TestExecuteAnalyserSuccess - Exit")
}

func TestExecuteAnalyserCredErr(t *testing.T) {
	log.Debug().Msg("TestExecuteAnalyserCredErr - Enter")
	anchore := NewAnchoreScanner()
	req := mockEcrExecuteRequest()
	fetcher := &PluginFetcher{}

	testdata.MockGetSystemStatusError()
	mockVar := testdata.HttpMock1{}

	scan.IAnchore = mockVar
	res, err := anchore.ExecuteAnalyser(context.Background(), req, fetcher, nil)
	assert.Nil(t, res)
	assert.NotNil(t, err)
	log.Debug().Msg("TestExecuteAnalyserCredErr - Exit")
}

func TestExecuteAnalyserGetStatusErr(t *testing.T) {
	log.Debug().Msg("TestExecuteAnalyserGetStatusErr - Enter")
	anchore := NewAnchoreScanner()
	req := mockEcrExecuteRequest()
	fetcher := &PluginFetcher{}

	testdata.MockGetSystemStatus("testdata/getsystemstatus.json")
	testdata.MockGetImageError()
	testdata.MockGetRegistriesError()

	mockVar := testdata.HttpMock1{}

	scan.IAnchore = mockVar
	res, err := anchore.ExecuteAnalyser(context.Background(), req, fetcher, nil)
	assert.Nil(t, res)
	assert.NotNil(t, err)
	log.Debug().Msg("TestExecuteAnalyserGetStatusErr - Exit")
}

func TestExecuteAnalyserGetVulnErr(t *testing.T) {
	log.Debug().Msg("TestExecuteAnalyserGetVulnErr - Enter")
	anchore := NewAnchoreScanner()
	req := mockEcrExecuteRequest()
	fetcher := &PluginFetcher{}

	testdata.MockGetSystemStatus("testdata/getsystemstatus.json")
	testdata.MockGetRegistries("testdata/getregistries.json")
	testdata.MockGetImage("testdata/getimage.json")
	testdata.MockGetVulnerabilitiesError()
	mockVar := testdata.HttpMock1{}

	scan.IAnchore = mockVar
	res, err := anchore.ExecuteAnalyser(context.Background(), req, fetcher, nil)
	assert.Nil(t, res)
	assert.NotNil(t, err)
	log.Debug().Msg("TestExecuteAnalyserGetVulnErr - Exit")
}

func TestExecuteAnalyserEmptyVuln(t *testing.T) {
	log.Debug().Msg("TestExecuteAnalyserEmptyVuln - Enter")
	anchore := NewAnchoreScanner()
	req := mockEcrExecuteRequest()
	fetcher := &PluginFetcher{}

	testdata.MockGetSystemStatus("testdata/getsystemstatus.json")
	testdata.MockGetRegistries("testdata/getregistries.json")
	testdata.MockGetImage("testdata/getimage.json")
	testdata.MockGetEmptyVulnerabilities()
	mockVar := testdata.HttpMock1{}

	scan.IAnchore = mockVar
	res, err := anchore.ExecuteAnalyser(context.Background(), req, fetcher, nil)
	assert.Nil(t, err)
	assert.Equal(t, 0, len(res.Checks))
	log.Debug().Msg("TestExecuteAnalyserEmptyVuln - Exit")
}

func TestExecuteAnalyserInactiveImage(t *testing.T) {
	log.Debug().Msg("TestExecuteAnalyserInactiveImage - Enter")
	anchore := NewAnchoreScanner()
	req := mockEcrExecuteRequest()
	fetcher := &PluginFetcher{}

	testdata.MockGetSystemStatus("testdata/getsystemstatus.json")
	testdata.MockGetRegistries("testdata/getregistries.json")
	testdata.MockGetImage("testdata/getinactiveimage.json")
	testdata.MockGetVulnerabilities("testdata/getVulnerabilities.json")
	mockVar := testdata.HttpMock1{}

	scan.IAnchore = mockVar
	res, err := anchore.ExecuteAnalyser(context.Background(), req, fetcher, nil)
	assert.Nil(t, res)
	assert.NotNil(t, err)
	log.Debug().Msg("TestExecuteAnalyserInactiveImage - Exit")
}

func TestExecuteAnalyserGetRegistryErr(t *testing.T) {
	log.Debug().Msg("TestExecuteAnalyserGetRegistryErr - Enter")
	anchore := NewAnchoreScanner()
	req := mockEcrExecuteRequest()
	fetcher := &PluginFetcher{}

	testdata.MockGetSystemStatus("testdata/getsystemstatus.json")
	testdata.MockGetRegistriesError()
	testdata.MockGetImage("testdata/getimage.json")
	testdata.MockGetVulnerabilities("testdata/getVulnerabilities.json")
	mockVar := testdata.HttpMock1{}

	scan.IAnchore = mockVar
	res, err := anchore.ExecuteAnalyser(context.Background(), req, fetcher, nil)
	assert.Nil(t, err)
	assert.NotNil(t, res)
	log.Debug().Msg("TestExecuteAnalyserGetRegistryErr - Exit")
}
