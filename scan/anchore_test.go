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
	path, _ := filepath.Abs("../testdata/getimage.json")
	testdata.MockGetImageError(path)
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
	path, _ := filepath.Abs("../testdata/getimagena.json")
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
	path, _ := filepath.Abs("../testdata/getimagena.json")
	testdata.MockGetImageError(path)

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

func TestGetScanStatusOtherStatus(t *testing.T) {
	log.Debug().Msg("Inside TestGetScanStatusOtherStatus - Enter")
	path, _ := filepath.Abs("../testdata/getimageother.json")
	testdata.MockGetSystemStatus(path)

	mockVar := testdata.HttpMock1{}
	IAnchore = mockVar
	err := GetSystemStatus("123")
	assert.Nil(t, err)
	log.Debug().Msg("Inside TestGetScanStatusOtherStatus - Exit")
}
