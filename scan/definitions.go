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
const JfrogRepo = "artifactory_repo"
const NexusRepo = "nexus_repo_binary"

type GetAnalysisStatus struct {
	AnalysisStatus string `json:"analysisStatus,omitempty"`
	ImageStatus    string `json:"imageStatus,omitempty"`
}

type VulnerabilityDetail struct {
	DetectedAt     string    `json:"detectedAt,omitempty"`
	Feed           string    `json:"feed,omitempty"`
	FeedGroup      string    `json:"feedGroup,omitempty"`
	Fix            string    `json:"fix,omitempty"`
	Package        string    `json:"package,omitempty"`
	PackageCpe     string    `json:"packageCpe,omitempty"`
	PackageName    string    `json:"packageName,omitempty"`
	PackagePath    string    `json:"packagePath,omitempty"`
	PackageType    string    `json:"packageType,omitempty"`
	PackageVersion string    `json:"packageVersion,omitempty"`
	Severity       string    `json:"severity,omitempty"`
	Url            string    `json:"url,omitempty"`
	CveId          string    `json:"vuln,omitempty"`
	WillNotFix     bool      `json:"willNotFix,omitempty"`
	VendorData     []string  `json:"vendorData,omitempty"`
	NvdData        []NvdData `json:"nvdData,omitempty"`
}

type NvdData struct {
	Id     string   `json:"id,omitempty"`
	CvssV2 CvsScore `json:"cvssV2,omitempty"`
	CvssV3 CvsScore `json:"cvssV3,omitempty"`
}

type CvsScore struct {
	BaseScore           float64 `json:"baseScore,omitempty"`
	ExploitabilityScore float64 `json:"exploitabilityScore,omitempty"`
	ImpactScore         float64 `json:"impactScore,omitempty"`
}

type Registry struct {
	RegistryName string `json:"registryName,omitempty"`
}

type AccountCred struct {
	URL         string `json:"url"`
	UserName    string `json:"userName"`
	Password    string `json:"password"`
	AccountName string `json:"accountName"`
}

var SeverityMap = map[string]int{
	"":          0,
	"LOW":       1,
	"MEDIUM":    2,
	"HIGH":      3,
	"VERY_HIGH": 4,
}
