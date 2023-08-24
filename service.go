package main

import (
	"context"
	"encoding/json"

	log "github.com/cloudbees-compliance/chlog-go/log"
	domain "github.com/cloudbees-compliance/chplugin-go/v0.4.0/domainv0_4_0"
	service "github.com/cloudbees-compliance/chplugin-go/v0.4.0/servicev0_4_0"
	"github.com/cloudbees-compliance/chplugin-service-go/plugin"
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
	return &service.ExecuteAnalyserResponse{
		Checks: checks,
	}, nil
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
