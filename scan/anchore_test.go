package scan

import (
	"path/filepath"
	"testing"

	"github.com/cloudbees-compliance/chlog-go/log"
	"github.com/cloudbees-compliance/compliance-hub-plugin-anchore/testdata"
	"github.com/stretchr/testify/assert"
)

func TestGetImage(t *testing.T) {
	log.Debug().Msg("Inside TestGetImage - Enter")
	path, _ := filepath.Abs("../testdata/getimage.json")
	testdata.MockGetImage(path)
	mockVar := testdata.HttpMock1{}
	IAnchore = mockVar
	data, err := GetImage("1234", "alpine")
	assert.Nil(t, err)
	assert.NotNil(t, data)
	log.Debug().Msg(" TestGetImage - Exit")
}

func TestGetImageErr(t *testing.T) {
	log.Debug().Msg("Inside TestGetImageErr - Enter")
	testdata.MockGetImageError()
	mockVar := testdata.HttpMock1{}
	IAnchore = mockVar
	data, err := GetImage("1234", "alpine")
	assert.NotNil(t, err)
	assert.Nil(t, data)
	log.Debug().Msg(" TestGetImageErr - Exit")
}

func TestGetRegistries(t *testing.T) {
	log.Debug().Msg("Inside TestGetRegistries - Enter")
	path, _ := filepath.Abs("../testdata/getregistries.json")
	testdata.MockGetRegistries(path)
	mockVar := testdata.HttpMock1{}
	IAnchore = mockVar
	data, err := GetRegistries("1234")
	assert.Nil(t, err)
	assert.NotNil(t, data)
	log.Debug().Msg("TestGetRegistries - Exit")
}

func TestGetRegistriesErr(t *testing.T) {
	log.Debug().Msg("Inside TestGetRegistriesErr - Enter")
	testdata.MockGetRegistriesError()
	mockVar := testdata.HttpMock1{}
	IAnchore = mockVar
	registryList, err := GetRegistries("1234")
	assert.NotNil(t, err)
	assert.Nil(t, registryList)
	log.Debug().Msg("TestGetRegistriesErr - Exit")
}

func TestGetRegistriesJsonErr(t *testing.T) {
	log.Debug().Msg("Inside TestGetRegistriesJsonErr - Enter")
	testdata.MockGetRegistriesJsonError()
	mockVar := testdata.HttpMock1{}
	IAnchore = mockVar
	registryList, err := GetRegistries("1234")
	assert.NotNil(t, err)
	assert.Nil(t, registryList)
	log.Debug().Msg("TestGetRegistriesJsonErr - Exit")
}

func TestGetVulnerabilities(t *testing.T) {
	log.Debug().Msg("Inside TestGetVulnerabilities - Enter")
	path, _ := filepath.Abs("../testdata/getVulnerabilities.json")
	testdata.MockGetVulnerabilities(path)
	mockVar := testdata.HttpMock1{}
	IAnchore = mockVar

	data, err := GetVulnerabilities("1234", "alpine")
	assert.Nil(t, err)
	assert.NotNil(t, data)
	log.Debug().Msg(" TestGetVulnerabilities - Exit")
}

func TestGetVulnerabilitiesErr(t *testing.T) {
	log.Debug().Msg("Inside TestGetVulnerabilitiesErr - Enter")
	testdata.MockGetVulnerabilitiesError()
	mockVar := testdata.HttpMock1{}
	IAnchore = mockVar

	data, err := GetVulnerabilities("1234", "alpine")
	assert.Nil(t, data)
	assert.NotNil(t, err)
	log.Debug().Msg(" TestGetVulnerabilitiesErr - Exit")
}

func TestGetVulnerabilitiesJsonErr(t *testing.T) {
	log.Debug().Msg("Inside TestGetVulnerabilitiesJsonErr - Enter")
	testdata.MockGetVulnerabilitiesJsonError()
	mockVar := testdata.HttpMock1{}
	IAnchore = mockVar

	data, err := GetVulnerabilities("1234", "alpine")
	assert.Nil(t, data)
	assert.NotNil(t, err)
	log.Debug().Msg(" TestGetVulnerabilitiesJsonErr - Exit")
}

func TestGetScanStatus(t *testing.T) {
	log.Debug().Msg("Inside TestGetScanStatus - Enter")
	path, _ := filepath.Abs("../testdata/getimage.json")
	testdata.MockGetImage(path)
	mockVar := testdata.HttpMock1{}
	IAnchore = mockVar
	status, _, err := GetScanStatus("123", "alpine", 1)
	assert.Nil(t, err)
	assert.Equal(t, status.ImageStatus, "active")
	log.Debug().Msg("Inside TestGetScanStatus - Exit")
}

func TestGetScanStatusErr(t *testing.T) {
	log.Debug().Msg("Inside TestGetScanStatusErr - Enter")
	path, _ := filepath.Abs("../testdata/getanalyzingimage.json")
	testdata.MockGetImage(path)

	mockVar := testdata.HttpMock1{}
	IAnchore = mockVar
	status, _, err := GetScanStatus("123", "unittest", 1)

	assert.Nil(t, err)
	assert.Equal(t, status.AnalysisStatus, "analyzing")
	log.Debug().Msg("Inside TestGetScanStatusErr - Exit")
}

func TestGetScanStatusResErr(t *testing.T) {
	log.Debug().Msg("Inside TestGetScanStatusResErr - Enter")
	testdata.MockGetImageError()
	mockVar := testdata.HttpMock1{}
	IAnchore = mockVar
	status, _, err := GetScanStatus("123", "test", 1)
	assert.NotNil(t, err)
	assert.Nil(t, status)
	log.Debug().Msg("Inside TestGetScanStatusResErr - Exit")

}

func TestGetScanStatusJsonErr(t *testing.T) {
	log.Debug().Msg("Inside TestGetScanStatusJsonErr - Enter")
	path, _ := filepath.Abs("{{test:test1}}")
	testdata.MockGetImage(path)

	mockVar := testdata.HttpMock1{}
	IAnchore = mockVar
	status, _, err := GetScanStatus("123", "test", 1)
	assert.NotNil(t, err)
	assert.Nil(t, status)

	log.Debug().Msg("Inside TestGetScanStatusJsonErr - Exit")

}

func TestGetScanStatusInactiveErr(t *testing.T) {
	log.Debug().Msg("Inside TestGetScanStatusInactiveErr - Enter")
	path, _ := filepath.Abs("../testdata/getinactiveimage.json")
	testdata.MockGetImage(path)

	mockVar := testdata.HttpMock1{}
	IAnchore = mockVar
	status, isAnalysed, err := GetScanStatus("123", "test", 1)
	assert.Nil(t, err)
	assert.Nil(t, status)
	assert.Equal(t, false, isAnalysed)

	log.Debug().Msg("Inside TestGetScanStatusInactiveErr - Exit")

}

func TestGetSystemStatus(t *testing.T) {
	log.Debug().Msg("Inside TestGetSystemStatus - Enter")
	path, _ := filepath.Abs("../testdata/getsystemstatus.json")
	testdata.MockGetSystemStatus(path)

	mockVar := testdata.HttpMock1{}
	IAnchore = mockVar
	err := GetSystemStatus("123")
	assert.Nil(t, err)
	log.Debug().Msg("Inside TestGetSystemStatus - Exit")
}

func TestGetSystemStatusErr(t *testing.T) {
	log.Debug().Msg("Inside TestGetSystemStatusErr - Enter")
	testdata.MockGetSystemStatusError()

	mockVar := testdata.HttpMock1{}
	IAnchore = mockVar
	err := GetSystemStatus("123")
	assert.NotNil(t, err)
	log.Debug().Msg("Inside TestGetSystemStatusErr - Exit")
}
