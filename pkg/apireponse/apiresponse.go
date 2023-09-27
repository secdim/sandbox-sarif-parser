package apiresponse

type Vulnerability struct {
	VulnerabilityID string    `json:"vulnerability_id"`
	Title           string    `json:"title"`
	Description     string    `json:"description"`
	Tags            []Tag     `json:"tags"`
	Severity        string    `json:"severity"`
	Sandboxes       []Sandbox `json:"sandboxes"`
	CWES            []CWE     `json:"cwes"`
	OWASPS          []OWASP   `json:"owasps"`
	Slug            string    `json:"slug"`
	CreatedAt       string    `json:"created_at"`
}

type Tag struct {
	Name       string `json:"name"`
	Category   string `json:"category"`
	Searchable bool   `json:"search_able"`
	Slug       string `json:"slug"`
}

type Sandbox struct {
	ID          int          `json:"id"`
	SandboxTags []SandboxTag `json:"tags"`
	Language    string       `json:"language"`
}

type SandboxTag struct {
	Name string `json:"name"`
	Slug string `json:"slug"`
}

type CWE struct {
	CWEID int    `json:"cwe_id"`
	Title string `json:"title"`
	Slug  string `json:"slug"`
}

type OWASP struct {
	OWASPId string `json:"owasp_id"`
	Title   string `json:"title"`
	Slug    string `json:"slug"`
}
