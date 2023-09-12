package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
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
	if len(receivedAssets) > 0 {
		credMap, credError := makeCredentialMap(req, requestId)
		if credError != nil {
			return nil, credError
		}
		err := validateCredMap(credMap, requestId)
		if err != nil {
			return nil, err
		}
		log.Debug(requestId).Msgf("Anchore Auth Validate Success")
		for _, asset := range receivedAssets {
			assetIdentifier := asset.MasterAsset.Identifier
			for _, profile := range asset.Profiles {
				log.Debug(requestId).Msgf("Binary Attributes Count : %v", len(profile.BinAttributes))
				tagName := profile.Identifier
				var imageName string
				var isAnalysed bool
				imageName, isAnalysed, err = getAnalysisStatus(asset, imageName, assetIdentifier, tagName, isAnalysed, err, requestId)
				if err != nil {
					return nil, err
				}
				if isAnalysed {
					vulnerabilityList, err := scan.GetVulnerabilities(requestId, imageName)
					if err != nil {
						return nil, err
					}
					if len(vulnerabilityList) > 0 {
						log.Debug(requestId).Msgf("Vulnerabilities got %d", len(vulnerabilityList))
						checks, err = buildEvaluations(ctx, &vulnerabilityList, asset, profile)
						if err != nil {
							log.Error(requestId).Err(err).Msgf("Error occurred while building evaluations %s", asset.MasterAsset.Identifier)
							return nil, err
						}
						log.Info(requestId).Msgf("Total number of evaluations returned %d", len(checks))

					} else {
						log.Debug(requestId).Msgf("No Vulnerabilities")
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
		assetIdentifier = strings.Replace(assetIdentifier, "library/", scan.EmptyString, -1)
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
		var hostNameList []string
		assetIdArr := strings.SplitAfter(assetIdentifier, "://")
		imageNameStr := assetIdArr[1]
		hostName := imageNameStr[0:strings.Index(imageNameStr, "/")]
		assetName := imageNameStr[strings.Index(imageNameStr, ":v2")+len(":v2"):]
		registryList, err := scan.GetRegistries(requestId)
		if err != nil {
			log.Debug(requestId).Msgf("Could not get registry ... using default values")
			for _, portNumber := range NexusPorts {
				hostNameList = append(hostNameList, hostName+portNumber)
			}
		} else {
			for _, registry := range *registryList {
				if strings.HasPrefix(registry.Registry, hostName) {
					hostNameList = append(hostNameList, registry.Registry)
				}
			}
		}
		if len(hostNameList) == 0 {
			log.Error(requestId).Msgf("No Nexus registry found for asset %s", assetIdentifier)
			return "", false, errors.New("no nexus registry found in anchore dashboard")
		}
		for _, hostNameValue := range hostNameList {
			imageName = hostNameValue + assetName + ":" + tagName
			_, isAnalysed, err = scan.GetScanStatus(requestId, imageName)
			if err == nil {
				break
			}
			log.Debug(requestId).Msgf("Checking Nexus image status for next registry")
		}
		if err != nil {
			log.Error(requestId).Msgf("Could not get analysis status for Nexus asset %s", assetIdentifier)
			return "", false, err
		}
	} else if strings.Compare(scan.AwsEcrRepo, asset.MasterAsset.SubType) == 0 {
		splitedAssetIdentifer := strings.Split(assetIdentifier, ":")
		assetName := strings.Replace(splitedAssetIdentifer[5], "repository", scan.EmptyString, -1)
		registryList, err := scan.GetRegistries(requestId)
		registryName := scan.EmptyString
		if err != nil {
			log.Debug(requestId).Msgf("Could not get registry ... using default format")
			registryName = splitedAssetIdentifer[4] + ".dkr." + splitedAssetIdentifer[2] + "." + splitedAssetIdentifer[3] + ".amazonaws.com"
		} else {
			for _, registryData := range *registryList {
				if strings.EqualFold(registryData.RegistryType, "awsecr") && strings.HasPrefix(registryData.Registry, splitedAssetIdentifer[4]) {
					registryName = registryData.Registry
					break
				}
			}
			if len(registryName) == 0 {
				log.Error(requestId).Msgf("No Aws ECR registry found for asset %s", assetIdentifier)
				return "", false, errors.New("no Aws Ecr registry found in anchore dashboard")
			}
		}
		imageName = registryName + assetName + ":" + tagName
		_, isAnalysed, err = scan.GetScanStatus(requestId, imageName)
		if err != nil {
			log.Error(requestId).Msgf("Could not get analysis status for AWS ECR asset %s", assetIdentifier)
			return "", false, err
		}
	}
	return imageName, isAnalysed, err
}

func makeCredentialMap(req *service.ExecuteRequest, requestId string) (scan.AccountCred, error) {
	var credMap scan.AccountCred
	if err := json.Unmarshal(req.Metadata, &credMap); err != nil {
		log.Error(requestId).Err(err).Msgf("Error Parsing Credentials")
		return scan.AccountCred{}, err
	}
	credMap.URL = utilities.GetValidURL(credMap.URL)
	return credMap, nil
}

func validateCredMap(credMap scan.AccountCred, requestId string) error {
	os.Setenv("ANCHORECTL_ACCOUNT", credMap.AccountName)
	os.Setenv("ANCHORECTL_PASSWORD", credMap.Password)
	os.Setenv("ANCHORECTL_URL", credMap.URL)
	os.Setenv("ANCHORECTL_USERNAME", credMap.UserName)
	os.Setenv("ANCHORECTL_UPDATE_CHECK", "false")
	return scan.GetSystemStatus(requestId)
}

func buildEvaluations(ctx context.Context, vulnList *[]scan.VulnerabilityDetail, asset *domain.Asset, ap *domain.AssetProfile) ([]*domain.Evaluation, error) {

	evalList := []*domain.Evaluation{}
	evaluationMap := mapToEvaluation(ctx, vulnList, asset, ap, map[string]*domain.Evaluation{})

	if len(evaluationMap) > 0 {
		for _, evaluation := range evaluationMap {
			evalList = append(evalList, evaluation)
		}
	}
	return evalList, nil
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
