package scan

import (
	"os/exec"
	"time"

	"github.com/cloudbees-compliance/chlog-go/log"
	"github.com/cloudbees-compliance/compliance-hub-plugin-anchore/config"
)

func (a AnchoreWrapper) GetImage(requestId string, imageName string) ([]byte, error) {
	defer timeTrack(time.Now(), "Anchore get image", requestId)
	app := config.Config.GetString("anchorectl.exe")

	cmd := exec.Command(app, "image", "get", imageName, "-o", "json")
	cmdString := cmd.String()

	log.Debug(requestId).Msgf(RunningCommand, cmdString)

	return cmd.CombinedOutput()
}

func (a AnchoreWrapper) GetVulnerabilities(requestId string, imageName string) ([]byte, error) {
	defer timeTrack(time.Now(), "Anchore get vulnerabilities", requestId)
	app := config.Config.GetString("anchorectl.exe")

	cmd := exec.Command(app, "image", "vulnerabilities", imageName, "-t", "all", "-o", "json")
	cmdString := cmd.String()

	log.Debug(requestId).Msgf(RunningCommand, cmdString)

	return cmd.CombinedOutput()

}

func (a AnchoreWrapper) GetRegistries(requestId string) ([]byte, error) {
	defer timeTrack(time.Now(), "Anchore get registries", requestId)
	app := config.Config.GetString("anchorectl.exe")

	cmd := exec.Command(app, "registry", "list", "-o", "json")
	cmdString := cmd.String()

	log.Debug(requestId).Msgf(RunningCommand, cmdString)

	return cmd.CombinedOutput()

}

func (a AnchoreWrapper) GetSystemStatus(requestId string) ([]byte, error) {
	defer timeTrack(time.Now(), "Anchore status check", requestId)
	app := config.Config.GetString("anchorectl.exe")

	cmd := exec.Command(app, "system", "status")
	cmdString := cmd.String()

	log.Debug(requestId).Msgf(RunningCommand, cmdString)

	return cmd.CombinedOutput()
}

func timeTrack(start time.Time, name string, requestId string) {
	elapsed := time.Since(start)
	log.Debug(requestId).Msgf("%s took %s", name, elapsed)
}
