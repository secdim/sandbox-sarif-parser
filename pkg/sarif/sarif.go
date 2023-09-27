package sarif

type Sarif struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Runs `json:"runs"`
}

type Runs struct {
	Tool           Tool           `json:"tool"`
	Artifacts      []Artifact     `json:"artifacts"`
	Results        []Result       `json:"results"`
	ColumnKind     string         `json:"columnKind"`
	RunsProperties RunsProperties `json:"properties"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type Driver struct {
	Name  string  `json:"name"`
	Rules []Rules `json:"rules"`
}

type Rules struct {
	DefaultConfiguration DefaultConfiguration `json:"defaultConfiguration"`
	FullDescription      FullDescription      `json:"fullDescription"`
	Help                 Help                 `json:"help"`
	HelpUri              string               `json:"helpUri"`
	ID                   string               `json:"id"`
	Name                 string               `json:"name"`
	Properties           Properties           `json:"properties"`
	ShortDescription     ShortDescription     `json:"shortDescription"`
}

type DefaultConfiguration struct {
	Level string `json:"level"`
}

type FullDescription struct {
	Text string `json:"text"`
}

type Help struct {
	Markdown string `json:"markdown"`
	Text     string `json:"text"`
}

type Properties struct {
	Precision string   `json:"precision"`
	Tags      []string `json:"tags"`
}

type ShortDescription struct {
	Text string `json:"text"`
}

type Artifact struct {
	Location Location `json:"location"`
}

type Location struct {
	Uri       string `json:"uri"`
	UriBaseId string `json:"uriBaseId"`
	Index     int    `json:"index"`
}

type Result struct {
	RuleId    string      `json:"ruleId"`
	RuleIndex int         `json:"ruleIndex"`
	Message   Message     `json:"message"`
	Locations []Locations `json:"locations"`
}

type Message struct {
	Text string `json:"text"`
}

type Locations struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
}

type ArtifactLocation struct {
	Uri       string `json:"uri"`
	UriBaseId string `json:"uriBaseId"`
	Index     int    `json:"index"`
}

type RunsProperties struct {
	SemmleFormatSpecific string `json:"semmle.formatSpecifier"`
}
