package testdata

import (
	"errors"
	"os"

	"github.com/cloudbees-compliance/chlog-go/log"
)

const ErrorResponse = "Error occured"

var GetImageMock func(requestId string, imageName string) ([]byte, error)
var GetRegistriesMock func(requestId string) ([]byte, error)
var GetSystemStatusMock func(requestId string) ([]byte, error)
var GetVulnerabilitiesMock func(requestId string, imageName string) ([]byte, error)

type HttpMock1 struct{}

func (u HttpMock1) GetImage(requestId string, imageName string) ([]byte, error) {
	return GetImageMock(requestId, imageName)
}

func (u HttpMock1) GetRegistries(requestId string) ([]byte, error) {
	return GetRegistriesMock(requestId)
}

func (u HttpMock1) GetSystemStatus(requestId string) ([]byte, error) {
	return GetSystemStatusMock(requestId)
}

func (u HttpMock1) GetVulnerabilities(requestId string, imageName string) ([]byte, error) {
	return GetVulnerabilitiesMock(requestId, imageName)
}

func MockGetImage(jsonpath string) {
	GetImageMock = func(requestId string, imageName string) ([]byte, error) {
		file, err := os.ReadFile(jsonpath)
		if err != nil {
			log.Error().Err(err).Msg("Error reading test data")
		}
		return file, nil
	}
}

func MockGetImageError() {
	GetImageMock = func(requestId string, imageName string) ([]byte, error) {
		return []byte(ErrorResponse), errors.New("error when getting image")
	}
}

func MockGetRegistries(jsonpath string) {
	GetRegistriesMock = func(requestId string) ([]byte, error) {
		file, err := os.ReadFile(jsonpath)
		if err != nil {
			log.Error().Err(err).Msg("Error reading test data")
		}
		return file, nil
	}
}

func MockGetRegistriesError() {
	GetRegistriesMock = func(requestId string) ([]byte, error) {
		return []byte(ErrorResponse), errors.New("error when getting registries")
	}
}

func MockGetRegistriesJsonError() {
	GetRegistriesMock = func(requestId string) ([]byte, error) {
		return []byte(ErrorResponse), nil
	}
}

func MockGetVulnerabilities(jsonPath string) {
	GetVulnerabilitiesMock = func(requestId string, imageName string) ([]byte, error) {
		file, err := os.ReadFile(jsonPath)
		if err != nil {
			log.Error().Err(err).Msg("Error reading test data")
		}
		return file, nil
	}
}

func MockGetEmptyVulnerabilities() {
	GetVulnerabilitiesMock = func(requestId string, imageName string) ([]byte, error) {
		return []byte("[]"), nil
	}
}

func MockGetVulnerabilitiesError() {
	GetVulnerabilitiesMock = func(requestId string, imageName string) ([]byte, error) {
		return []byte(ErrorResponse), errors.New("error when getting vulnerabilities")
	}
}

func MockGetVulnerabilitiesJsonError() {
	GetVulnerabilitiesMock = func(requestId string, imageName string) ([]byte, error) {
		return []byte(ErrorResponse), nil
	}
}

func MockGetSystemStatus(jsonPath string) {
	GetSystemStatusMock = func(requestId string) ([]byte, error) {
		file, err := os.ReadFile(jsonPath)
		if err != nil {
			log.Error().Err(err).Msg("Error reading test data")
		}
		return file, nil

	}
}

func MockGetSystemStatusError() {
	GetSystemStatusMock = func(requestId string) ([]byte, error) {
		return []byte(ErrorResponse), errors.New("error when getting system status")
	}
}
