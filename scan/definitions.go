package scan

const EmptyString = ""
const Slash = "/"
const Url = "url"
const Username = "username"
const Password = "password"
const HttpsProtocol = "https://"
const HttpProtocol = "http://"
const CreateTokenEndPoint = "/api/v1/login"
const PostMethodType = "POST"
const ContentType = "application/json"
const RetryCount = 8
const SleepDuration = 30
const DockerRepo = "dockerhub_repo"
const JfrogRepo = "jfrog_server"
const NexusRepo = "nexus_repo_binary"

type GetAnalysisStatus struct {
	AnalysisStatus string `json:"analysisStatus,omitempty"`
	ImageStatus    string `json:"imageStatus,omitempty"`
}

type VulnerabilityDetail struct {
	CveId   string `json:"vulns,omitempty"`
	Url     string `json:"url,omitempty"`
	Package string `json:"package,omitempty"`
}

type Registry struct {
	RegistryName string `json:"registryName,omitempty"`
}
