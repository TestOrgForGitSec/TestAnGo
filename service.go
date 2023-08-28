package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"

	log "github.com/cloudbees-compliance/chlog-go/log"
	domain "github.com/cloudbees-compliance/chplugin-go/v0.4.0/domainv0_4_0"
	service "github.com/cloudbees-compliance/chplugin-go/v0.4.0/servicev0_4_0"
	"github.com/cloudbees-compliance/chplugin-service-go/plugin"
	"github.com/cloudbees-compliance/compliance-hub-plugin-anchore/scan"
	"github.com/cloudbees-compliance/compliance-hub-plugin-anchore/utilities"
	"github.com/google/uuid"
)

type anchoreScanner struct {
	plugin.CHPluginService
}

func NewAnchoreScanner() plugin.CHPluginService {
	return &anchoreScanner{}
}

func (as *anchoreScanner) GetManifest(context.Context, *service.GetManifestRequest) (*service.GetManifestResponse, error) {

	log.Debug().Msg("Request for manifest")

	return &service.GetManifestResponse{
		Manifest: &domain.Manifest{
			Uuid:    "8a300061-30f0-4cf6-ba79-33ee2f1c6151",
			Name:    "AnchorePlugin",
			Version: "0.0.1",
			AssetRoles: []*domain.AssetRole{
				{
					AssetType:                AssetType,
					Role:                     domain.Role_ANALYSER,
					RequiresAssets:           true,
					RequiresAttributes:       true,
					RequiresBinaryAttributes: true,
				},
			},
		},
		Error: nil,
	}, nil
}

func (as *anchoreScanner) GetAssetDescriptors(context.Context, *service.GetAssetDescriptorsRequest) (*service.GetAssetDescriptorsResponse, error) {
	return &service.GetAssetDescriptorsResponse{}, nil
}

func (as *anchoreScanner) ExecuteAnalyser(ctx context.Context, req *service.ExecuteRequest, assetFetcher plugin.AssetFetcher, stream service.CHPluginService_AnalyserServer) (*service.ExecuteAnalyserResponse, error) {
	log.Info().Msgf("Analyser Request received")
	ctx = makeSubLogger(req, ctx)
	requestId := utilities.GetRequestId(ctx)
	defer log.DestroySubLogger(requestId)

	receivedAssets, err := assetFetcher.FetchAssets(plugin.AssetFetchRequest{
		AccountID:          req.Account.Uuid,
		AssetType:          req.AssetType,
		AssetSubTypes:      req.AssetSubTypes,
		Identifiers:        req.AssetIdentifiers,
		ProfileIdentifiers: req.ProfileIdentifiers,
	})
	if err != nil {
		log.Error(requestId).Err(err).Msgf("Asset Fetch Failed")
		return nil, err
	}

	log.Debug(requestId).Msgf("Total Asset Fetched : %d", len(receivedAssets))
	var checks []*domain.Evaluation
	log.Info(requestId).Msgf("Anchore analyser under development")
	//if received asset list is present ,
	if len(receivedAssets) > 0 {
		//check if valid creds
		for _, asset := range receivedAssets {
			assetIdentifier := asset.MasterAsset.Identifier
			for _, profile := range asset.Profiles {
				log.Debug(requestId).Msgf("Binary Attributes Count : %v", len(profile.BinAttributes))
				tagName := profile.Identifier
				var imageName string
				var isAnalysed bool
				//https://jfrog.demo.ceebe.com/artifactory/fodler.
				//compare with registry list
				imageName, isAnalysed, err = getAnalysisStatus(asset, imageName, assetIdentifier, tagName, isAnalysed, err, requestId)
				if err != nil {
					//error when getting status
					return nil, err
				}
				if isAnalysed {
					//Get Vulnerabilities
					vulnerabilityList, err := scan.GetVulnerabilities(requestId, imageName)
					if err != nil {
						return nil, err
					}
					if len(*vulnerabilityList) > 0 {
						log.Debug(requestId).Msgf("Vulnerabilities got %d", len(*vulnerabilityList))

					} else {
						log.Debug(requestId).Msgf("No Vulns")
					}

				} else {
					log.Error(requestId).Msgf("Could not get vulnerabilities %s", assetIdentifier)
					return nil, errors.New("could not get vulnerabilities")
				}

			}

		}

	}
	return &service.ExecuteAnalyserResponse{
		Checks: checks,
	}, nil
}

func getAnalysisStatus(asset *domain.Asset, imageName string, assetIdentifier string, tagName string, isAnalysed bool, err error, requestId string) (string, bool, error) {
	if strings.Compare(scan.DockerRepo, asset.MasterAsset.SubType) == 0 {
		imageName = assetIdentifier + ":" + tagName
		_, isAnalysed, err = scan.GetScanStatus(requestId, imageName)
	} else if strings.Compare(scan.JfrogRepo, asset.MasterAsset.SubType) == 0 {
		assetIdArr := strings.SplitAfter(assetIdentifier, "://")
		imageNameStr := assetIdArr[1]
		hostName := imageNameStr[0:strings.Index(imageNameStr, "/")]
		assetName := imageNameStr[strings.Index(imageNameStr, "/artifactory")+len("/artifactory"):]
		imageName = hostName + assetName + ":" + tagName
		_, isAnalysed, err = scan.GetScanStatus(requestId, imageName)

	} else if strings.Compare(scan.NexusRepo, asset.MasterAsset.SubType) == 0 {
		assetIdArr := strings.SplitAfter(assetIdentifier, "://")
		imageNameStr := assetIdArr[1]
		hostName := imageNameStr[0:strings.Index(imageNameStr, "/")]
		registryList, err := scan.GetRegistries(requestId)
		if err != nil {
			log.Debug(requestId).Msgf("Could not get registry ... using default")
			hostName = hostName + ":5002"
		} else {
			for _, registry := range *registryList {
				if strings.HasPrefix(registry.RegistryName, hostName) {
					hostName = registry.RegistryName
					break
				}

			}
		}
		assetName := imageNameStr[strings.Index(imageNameStr, ":v2")+len(":v2"):]
		imageName = hostName + assetName + ":" + tagName
		_, isAnalysed, err = scan.GetScanStatus(requestId, imageName)
		if err != nil {
			log.Error(requestId).Msgf("Could not get analysis status for %s", imageName)
			return "", false, err
		}
	}
	return imageName, isAnalysed, err
}

func makeSubLogger(req *service.ExecuteRequest, ctx context.Context) context.Context {
	trackingInfo := make(map[string]string)
	err := json.Unmarshal(req.TrackingInfo, &trackingInfo)
	if err != nil {
		log.Warn().Msg("AnchorePlugin: Unable to unmarshal trackingInfo.")
	}

	requestId := trackingInfo[CHRequestId]
	if requestId == "" {
		requestId = uuid.New().String()
		trackingInfo[CHRequestId] = requestId
	}
	log.CreateSubLogger(requestId, "", trackingInfo)
	ctx = context.WithValue(ctx, "requestId", requestId)
	ctx = context.WithValue(ctx, "trackingInfo", trackingInfo)
	return ctx
}
