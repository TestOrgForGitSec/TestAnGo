package scan

import (
	"os/exec"

	"github.com/cloudbees-compliance/chlog-go/log"
	"github.com/cloudbees-compliance/compliance-hub-plugin-anchore/config"
)

func (a AnchoreWrapper) GetImage(requestId string, imageName string) ([]byte, error) {

	app := config.Config.GetString("anchore.exe")

	cmd := exec.Command(app, "image", "get", imageName, "-o", "json")
	cmdString := cmd.String()

	log.Debug(requestId).Msgf("Running command: %s", cmdString)

	return cmd.CombinedOutput()
}

func (a AnchoreWrapper) GetVulnerabilities(requestId string, imageName string) ([]byte, error) {

	app := config.Config.GetString("anchore.exe")

	cmd := exec.Command(app, "image", "vulnerabilities", imageName, "-t", "all", "-o", "json")
	cmdString := cmd.String()

	log.Debug(requestId).Msgf("Running command: %s", cmdString)

	return cmd.CombinedOutput()

}

func (a AnchoreWrapper) GetRegistries(requestId string) ([]byte, error) {

	app := config.Config.GetString("anchore.exe")

	cmd := exec.Command(app, "registry", "list", "-o", "json")
	cmdString := cmd.String()

	log.Debug(requestId).Msgf("Running command: %s", cmdString)

	return cmd.CombinedOutput()

}
