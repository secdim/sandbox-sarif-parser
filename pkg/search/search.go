package search

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sandbox/pkg/apiresponse"
	"sandbox/pkg/globals"
	"sandbox/pkg/sarif"
	"strings"
)

type SearchTerm struct {
	ID               string
	Description      string
	CWECode          []string
	CWEDescription   []string
	OWASPCode        []string
	OWASPDescription []string
}

type SearchResult struct {
	RuleID     string
	Title      string
	ResultJson []apiresponse.Vulnerability
}

func ParseSarifStruct(sarif sarif.Sarif) []SearchTerm {
	fmt.Printf("Parsing SARIF file for search terms\n")
	var searchTerms []SearchTerm
	for _, result := range sarif.Runs[0].Results {
		for _, rule := range sarif.Runs[0].Tool.Driver.Rules {
			if result.RuleId == rule.ID {
				var searchTerm = SearchTerm{
					ID:          rule.ID,
					Description: rule.FullDescription.Text,
				}

				for _, tag := range rule.Properties.Tags {
					if strings.HasPrefix(tag, "CWE") {
						substrings := strings.Split(tag, ":")
						searchTerm.CWECode = append(searchTerm.CWECode, substrings[0][4:])
						if len(substrings) >= 2 {
							searchTerm.CWEDescription = append(searchTerm.CWEDescription, substrings[1][1:])
						} else {
							searchTerm.CWEDescription = append(searchTerm.CWEDescription, "")
						}
					} else if strings.HasPrefix(tag, "OWASP") {
						substrings := strings.Split(tag, " ")
						searchTerm.OWASPCode = append(searchTerm.OWASPCode, substrings[0][6:])
						if len(substrings) >= 3 {
							searchTerm.OWASPDescription = append(searchTerm.OWASPDescription, strings.Join(substrings[2:], " "))
						} else {
							searchTerm.OWASPDescription = append(searchTerm.OWASPDescription, "")
						}
					}
				}
				searchTerms = append(searchTerms, searchTerm)
			}
		}
	}

	return searchTerms
}

func SearchAPI(searchTerm string) ([]byte, error) {
	response, err := http.Get(globals.API_URL + searchTerm)
	if err != nil {
		fmt.Printf("Error sending GET request: %v\n", err)
		return nil, err
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return nil, err
	}

	return body, nil
}

func GetSearchResults(searchTerm SearchTerm) (SearchResult, error) {
	fmt.Printf("Searching for SecDim Sandbox related to SARIF Rule ID: %s\n", searchTerm.ID)
	var searchResult = SearchResult{
		RuleID: searchTerm.ID,
		Title:  searchTerm.CWEDescription[0],
	}

	var jsonResponse []apiresponse.Vulnerability

	// Initial API search, search CWE Description
	for _, cweDescription := range searchTerm.CWEDescription {
		response, err := SearchAPI(cweDescription)
		if err != nil {
			fmt.Printf("Error reading response body: %v\n", err)
			return searchResult, err
		}

		// var jsonResponse []apiresponse.Vulnerability
		if err := json.Unmarshal(response, &jsonResponse); err != nil {
			fmt.Printf("Error unmarshaling SARIF: %v\n", err)
			return searchResult, err
		}

		// If API search isn't empty, return result
		if len(jsonResponse) > 0 {
			searchResult.ResultJson = jsonResponse
			searchResult.Title = cweDescription
			return searchResult, nil
		}
	}

	if len(jsonResponse) == 0 {
		for _, owaspDescription := range searchTerm.OWASPDescription {
			response, err := SearchAPI(owaspDescription)
			if err != nil {
				fmt.Printf("Error reading response body: %v\n", err)
				return searchResult, err
			}

			var jsonResponse []apiresponse.Vulnerability
			if err := json.Unmarshal(response, &jsonResponse); err != nil {
				fmt.Printf("Error unmarshaling SARIF: %v\n", err)
				return searchResult, err
			}
			// If API search isn't empty, return result
			if len(jsonResponse) > 0 {
				searchResult.ResultJson = jsonResponse
				searchResult.Title = owaspDescription
				return searchResult, nil
			}
		}
	}
	searchResult.ResultJson = jsonResponse
	return searchResult, nil
}
