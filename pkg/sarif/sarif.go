package sarif

import (
	"fmt"
	"reflect"
	"strings"
)

type Sarif struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []Runs `json:"runs"`
}

type Runs struct {
	Tool           Tool           `json:"tool"`
	Artifacts      []Artifact     `json:"artifacts"`
	Results        []Result       `json:"results"`
	RunsProperties RunsProperties `json:"properties,omitempty"`
	Invocations    []Invocation   `json:"invocations,omitempty"`
}

type Invocation struct {
	CommandLine string `json:"commandLine,omitempty"`
	StartTimeUtc string `json:"startTimeUtc,omitempty"`
	EndTimeUtc   string `json:"endTimeUtc,omitempty"`
	ExecutionSuccessful bool `json:"executionSuccessful,omitempty"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type Driver struct {
	Name           string  `json:"name"`
	Version        string  `json:"version,omitempty"`
	InformationUri string  `json:"informationUri,omitempty"`
	Rules          []Rules `json:"rules"`
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
	Region           Region           `json:"region,omitempty"`
	ContextRegion    Region           `json:"contextRegion,omitempty"`
}

type ArtifactLocation struct {
	Uri         string `json:"uri"`
	UriBaseId   string `json:"uriBaseId,omitempty"`
	Index       int    `json:"index,omitempty"`
	Description Message `json:"description,omitempty"`
}

type Region struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
	ByteOffset  int `json:"byteOffset,omitempty"`
	ByteLength  int `json:"byteLength,omitempty"`
}

type RunsProperties struct {
	SemmleFormatSpecific string `json:"semmle.formatSpecifier"`
}

func RemoveNullFields(v reflect.Value) {
	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() {
			return
		}
		RemoveNullFields(v.Elem())
	case reflect.Interface:
		if v.IsNil() {
			return
		}
		RemoveNullFields(v.Elem())
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			field := v.Field(i)
			if field.Kind() == reflect.Ptr && field.IsNil() {
				// Replace nil pointer with zero value of its type
				field.Set(reflect.New(field.Type().Elem()))
			} else if field.Kind() == reflect.Slice && field.IsNil() {
				// Replace nil slice with empty slice of its type
				field.Set(reflect.MakeSlice(field.Type(), 0, 0))
			} else {
				RemoveNullFields(field)
			}
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			RemoveNullFields(v.Index(i))
		}
	case reflect.Map:
		for _, key := range v.MapKeys() {
			RemoveNullFields(v.MapIndex(key))
		}
	}
}

func RemoveEmptyResults(sarifData Sarif) Sarif {
	fmt.Printf("Cleaning up output SARIF file\n")
	var updatedSarif Sarif
	updatedSarif.Schema = sarifData.Schema
	updatedSarif.Version = sarifData.Version
	for _, run := range sarifData.Runs {
		for i := 0; i < len(run.Results); i++ {
			result := run.Results[i]
			foundResult := false
			for j := 0; j < len(run.Tool.Driver.Rules); j++ {
				rule := run.Tool.Driver.Rules[j]
				if result.RuleId == rule.ID && strings.HasPrefix(rule.ShortDescription.Text, "SecDim") {
					foundResult = true
					break
				}
			}
			if !foundResult {
				// Remove result if rule ID matches and short description does not start with "SecDim"
				run.Results = append(run.Results[:i], run.Results[i+1:]...)
				i-- // Decrement i to account for the removed element
			}
		}
		RemoveNullFields(reflect.ValueOf(&run))
		updatedSarif.Runs = append(updatedSarif.Runs, run)
	}
	return updatedSarif
}