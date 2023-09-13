package scan

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/cloudbees-compliance/chlog-go/log"
)

type AnchoreScanInterface interface {
	GetImage(requestId string, imageName string) ([]byte, error)
	GetVulnerabilities(requestId string, imageName string) ([]byte, error)
	GetRegistries(requestId string) ([]byte, error)
	GetSystemStatus(requestId string) ([]byte, error)
}

type AnchoreWrapper struct {
}

// create a package level variable of type interface
var IAnchore AnchoreScanInterface

func init() {
	IAnchore = AnchoreWrapper{}
}

func GetImage(requestId string, imageName string) ([]byte, error) {
	log.Debug(requestId).Msgf("Getting scanned image...")

	out, err := IAnchore.GetImage(requestId, imageName)

	if err != nil {
		// only output stdout/err if there was a problem
		if out != nil {
			log.Error(requestId).Msg("stdout/err:" + string(out))
		}
		return nil, err
	}
	return out, nil
}

func GetScanStatus(requestId string, imageName string, retryCount int) (*GetAnalysisStatus, bool, error) {
	status, err := GetImage(requestId, imageName)
	if err != nil {
		return nil, false, err
	}
	var analysisStatus GetAnalysisStatus
	jsonerr := json.Unmarshal(status, &analysisStatus)
	if jsonerr != nil {
		log.Error().Msgf("AnchorePlugin: Error when marshaling response %s - %s", analysisStatus.AnalysisStatus, analysisStatus.ImageStatus)
		return nil, false, jsonerr
	}
	log.Debug(requestId).Msgf("AnchorePlugin: Get image status %s - %s", analysisStatus.AnalysisStatus, analysisStatus.ImageStatus)
	if strings.Compare("active", analysisStatus.ImageStatus) == 0 &&
		strings.Compare("analyzed", analysisStatus.AnalysisStatus) == 0 {
		return &analysisStatus, true, nil
	} else if strings.Compare("active", analysisStatus.ImageStatus) == 0 &&
		strings.Compare("analyzed", analysisStatus.AnalysisStatus) != 0 {
		var attempts = retryCount
		sleep := time.Second * SleepDuration
		log.Debug(requestId).Msgf("Starting Retry for %d times ...", attempts)
		for i := 0; i < attempts; i++ {
			status, err = GetImage(requestId, imageName)
			if err != nil {
				return nil, false, err
			}
			jsonerr := json.Unmarshal(status, &analysisStatus)
			if jsonerr != nil {
				log.Error().Msgf("AnchorePlugin: Error when marshaling response %s - %s", analysisStatus.AnalysisStatus, analysisStatus.ImageStatus)
				return nil, false, jsonerr
			}
			if strings.Compare("active", analysisStatus.ImageStatus) == 0 &&
				strings.Compare("analyzed", analysisStatus.AnalysisStatus) != 0 {
				log.Debug(requestId).Msgf("status of analysis for attempt %d is - %s", i+1, analysisStatus.AnalysisStatus)
				log.Debug(requestId).Msgf("sleeping for : %s ", sleep.String())
				time.Sleep(sleep)
				continue
			}
			break
		}

	} else {
		return nil, false, nil
	}
	return &analysisStatus, true, nil
}

func GetVulnerabilities(requestId string, imageName string) ([]VulnerabilityDetail, error) {
	log.Debug(requestId).Msgf("Getting vulnerabilities...")
	var vulnerabilityList []VulnerabilityDetail
	vulnerabilities, err := IAnchore.GetVulnerabilities(requestId, imageName)
	if err != nil {
		// only output stdout/err if there was a problem
		if vulnerabilities != nil {
			log.Error(requestId).Msg("stdout/err:" + string(vulnerabilities))
		}
		return nil, err
	}

	jsonerr := json.Unmarshal(vulnerabilities, &vulnerabilityList)
	if jsonerr != nil {
		log.Error().Msgf("AnchorePlugin: Error when marshaling response for vulnerabilities")
		return nil, jsonerr
	}

	return vulnerabilityList, nil

}

func GetRegistries(requestId string) (*[]Registry, error) {
	log.Debug(requestId).Msgf("Getting registries...")
	var registryList []Registry
	registries, err := IAnchore.GetRegistries(requestId)
	if err != nil {
		// only output stdout/err if there was a problem
		if registries != nil {
			log.Error(requestId).Msg("stdout/err:" + string(registries))
		}
		return nil, err
	}

	jsonerr := json.Unmarshal(registries, &registryList)
	if jsonerr != nil {
		log.Error().Msgf("AnchorePlugin: Error when marshaling response for registries")
		return nil, jsonerr
	}

	return &registryList, nil

}

func GetSystemStatus(requestId string) error {
	log.Debug(requestId).Msgf("Getting system status...")

	sysStatus, err := IAnchore.GetSystemStatus(requestId)
	if err != nil {
		if sysStatus != nil {
			log.Error(requestId).Err(err).Msg("stdout/err:" + string(sysStatus))
		}
		return err
	}
	return nil
}
