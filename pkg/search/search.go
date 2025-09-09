package search

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
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
	FreeText         []string // Additional search terms from rule descriptions, tags, etc.
}

type SearchResult struct {
	RuleID     string
	Title      string
	ResultJson []apiresponse.Vulnerability
}

// removeCWELeadingZeros removes leading zeros from CWE codes
// e.g., "089" becomes "89", "094" becomes "94"
func removeCWELeadingZeros(cweCode string) string {
	// Remove leading zeros but keep at least one digit
	for len(cweCode) > 1 && cweCode[0] == '0' {
		cweCode = cweCode[1:]
	}
	return cweCode
}

func ParseSarifStruct(sarifData sarif.Sarif, toolHint string) []SearchTerm {
	fmt.Printf("Parsing SARIF file for search terms\n")
	
	// Auto-detect tool if not specified
	tool := detectTool(sarifData, toolHint)
	fmt.Printf("Detected tool: %s\n", tool)
	
	switch tool {
	case "semgrep":
		return parseSemgrepSarif(sarifData)
	case "snyk":
		return parseSnykSarif(sarifData)
	case "codeql":
		return parseCodeQLSarif(sarifData)
	default:
		fmt.Printf("Unknown tool, falling back to generic parsing\n")
		return parseSemgrepSarif(sarifData) // fallback to semgrep-style parsing
	}
}

// detectTool auto-detects the security scanning tool based on SARIF structure
func detectTool(sarifData sarif.Sarif, toolHint string) string {
	if toolHint != "" {
		return strings.ToLower(toolHint)
	}

	if len(sarifData.Runs) == 0 {
		return "unknown"
	}

	driver := sarifData.Runs[0].Tool.Driver
	
	// Check driver name
	switch strings.ToLower(driver.Name) {
	case "semgrep oss", "semgrep":
		return "semgrep"
	case "snyk code", "snyk":
		return "snyk"
	case "codeql":
		return "codeql"
	}

	// Check for tool-specific patterns
	if len(driver.Rules) > 1000 {
		// Semgrep typically has thousands of rules
		return "semgrep"
	}

	if len(driver.Rules) == 0 && len(sarifData.Runs[0].Tool.Extensions) > 0 {
		// CodeQL pattern - no rules in driver but has extensions
		return "codeql"
	}

	if len(driver.Rules) < 10 && len(driver.Rules) > 0 {
		// Check if rules have Snyk-specific properties
		for _, rule := range driver.Rules {
			if len(rule.Properties.CWE) > 0 || strings.Contains(rule.ID, "/") {
				return "snyk"
			}
		}
	}

	return "unknown"
}

// parseSemgrepSarif handles Semgrep SARIF format
func parseSemgrepSarif(sarifData sarif.Sarif) []SearchTerm {
	var searchTerms []SearchTerm
	for _, result := range sarifData.Runs[0].Results {
		for _, rule := range sarifData.Runs[0].Tool.Driver.Rules {
			if result.RuleId == rule.ID {
				var searchTerm = SearchTerm{
					ID:          rule.ID,
					Description: rule.FullDescription.Text,
				}

				// Extract CWE and OWASP from tags
				for _, tag := range rule.Properties.Tags {
					if strings.HasPrefix(tag, "CWE") {
						// Format: "CWE-95: Improper Neutralization..."
						substrings := strings.Split(tag, ":")
						cweCode := strings.TrimSpace(strings.TrimPrefix(substrings[0], "CWE-"))
						cweCode = removeCWELeadingZeros(cweCode)
						searchTerm.CWECode = append(searchTerm.CWECode, cweCode)
						
						if len(substrings) >= 2 {
							cweDesc := strings.TrimSpace(substrings[1])
							searchTerm.CWEDescription = append(searchTerm.CWEDescription, cweDesc)
						} else {
							searchTerm.CWEDescription = append(searchTerm.CWEDescription, "")
						}
					} else if strings.HasPrefix(tag, "OWASP") {
						// Format: "OWASP-A03:2021 - Injection"
						substrings := strings.Split(tag, " ")
						owaspCode := strings.TrimSpace(strings.TrimPrefix(substrings[0], "OWASP-"))
						searchTerm.OWASPCode = append(searchTerm.OWASPCode, owaspCode)
						
						if len(substrings) >= 3 {
							owaspDesc := strings.TrimSpace(strings.Join(substrings[2:], " "))
							searchTerm.OWASPDescription = append(searchTerm.OWASPDescription, owaspDesc)
						} else {
							searchTerm.OWASPDescription = append(searchTerm.OWASPDescription, "")
						}
					}
				}

				// Add additional search terms from rule text and names
				if rule.Name != "" && rule.Name != rule.ID {
					searchTerm.FreeText = append(searchTerm.FreeText, rule.Name)
				}
				if rule.ShortDescription.Text != "" {
					searchTerm.FreeText = append(searchTerm.FreeText, rule.ShortDescription.Text)
				}

				searchTerms = append(searchTerms, searchTerm)
			}
		}
	}
	return searchTerms
}

// parseSnykSarif handles Snyk SARIF format
func parseSnykSarif(sarifData sarif.Sarif) []SearchTerm {
	var searchTerms []SearchTerm
	for _, result := range sarifData.Runs[0].Results {
		for _, rule := range sarifData.Runs[0].Tool.Driver.Rules {
			if result.RuleId == rule.ID {
				var searchTerm = SearchTerm{
					ID:          rule.ID,
					Description: rule.ShortDescription.Text,
				}

				// Extract CWE information from properties.cwe
				for _, cwe := range rule.Properties.CWE {
					cweCode := strings.TrimPrefix(cwe, "CWE-")
					cweCode = removeCWELeadingZeros(cweCode)
					searchTerm.CWECode = append(searchTerm.CWECode, cweCode)
				}

				// Add rule name and descriptions as free text search terms
				if rule.Name != "" {
					searchTerm.FreeText = append(searchTerm.FreeText, rule.Name)
				}
				if rule.ShortDescription.Text != "" {
					searchTerm.FreeText = append(searchTerm.FreeText, rule.ShortDescription.Text)
				}
				if rule.FullDescription.Text != "" && rule.FullDescription.Text != rule.ShortDescription.Text {
					searchTerm.FreeText = append(searchTerm.FreeText, rule.FullDescription.Text)
				}

				// Add categories as search terms
				for _, category := range rule.Properties.Categories {
					if category != "" {
						searchTerm.FreeText = append(searchTerm.FreeText, category)
					}
				}

				searchTerms = append(searchTerms, searchTerm)
			}
		}
	}
	return searchTerms
}

// parseCodeQLSarif handles CodeQL SARIF format
func parseCodeQLSarif(sarifData sarif.Sarif) []SearchTerm {
	var searchTerms []SearchTerm
	
	// CodeQL stores rules in extensions, not in driver.rules
	var allRules []sarif.Rules
	for _, ext := range sarifData.Runs[0].Tool.Extensions {
		for _, rule := range ext.Rules {
			allRules = append(allRules, rule)
		}
	}

	for _, result := range sarifData.Runs[0].Results {
		var ruleId string
		if result.Rule != nil {
			ruleId = result.Rule.ID
		} else {
			ruleId = result.RuleId
		}

		// Find the rule in extensions
		for _, rule := range allRules {
			if rule.ID == ruleId {
				var searchTerm = SearchTerm{
					ID:          rule.ID,
					Description: rule.FullDescription.Text,
				}

				// Extract CWE information from tags with format "external/cwe/cwe-XXX"
				for _, tag := range rule.Properties.Tags {
					if strings.HasPrefix(tag, "external/cwe/cwe-") {
						cweCode := strings.TrimPrefix(tag, "external/cwe/cwe-")
						cweCode = removeCWELeadingZeros(cweCode)
						searchTerm.CWECode = append(searchTerm.CWECode, cweCode)
						// We don't have descriptions for CWE in CodeQL, but we can use the rule description
						searchTerm.CWEDescription = append(searchTerm.CWEDescription, "")
					} else if tag != "" && tag != "security" && tag != "correctness" && tag != "quality" {
						// Add other meaningful tags as free text (exclude generic ones)
						searchTerm.FreeText = append(searchTerm.FreeText, tag)
					}
				}

				// Extract information from rule name and description generically
				if rule.Name != "" {
					searchTerm.FreeText = append(searchTerm.FreeText, rule.Name)
				}
				if rule.ShortDescription.Text != "" {
					searchTerm.FreeText = append(searchTerm.FreeText, rule.ShortDescription.Text)
				}
				if rule.FullDescription.Text != "" {
					searchTerm.FreeText = append(searchTerm.FreeText, rule.FullDescription.Text)
				}

				// Add search term if we have any information to search for
				if len(searchTerm.CWECode) > 0 || len(searchTerm.FreeText) > 0 || searchTerm.Description != "" {
					searchTerms = append(searchTerms, searchTerm)
				}
				break
			}
		}
	}
	return searchTerms
}

func SearchAPI(searchTerm string) ([]byte, error) {
	u, err := url.Parse(globals.SEARCH_API_URL)
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("search", searchTerm)
	q.Set("catalog", "true")
	u.RawQuery = q.Encode()

	fmt.Printf("Requesting: %s\n", u.String())
	response, err := http.Get(u.String())
	if err != nil {
		fmt.Printf("Error sending GET request: %v\n", err)
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		fmt.Printf("Error sending GET request: %s\n", response.Status)
		return nil, err
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return nil, err
	}

	return body, nil
}

// SearchAPIWithParams searches SecDim API with specific parameters (cwe, owasp, search)
func SearchAPIWithParams(cwe, owasp, search string) ([]byte, error) {
	u, err := url.Parse(globals.SEARCH_API_URL)
	if err != nil {
		return nil, err
	}
	
	q := u.Query()
	q.Set("catalog", "true")
	
	if cwe != "" {
		q.Set("cwe", cwe)
	}
	if owasp != "" {
		q.Set("owasp", owasp)
	}
	if search != "" {
		q.Set("search", search)
	}
	
	u.RawQuery = q.Encode()
	fmt.Printf("Requesting: %s\n", u.String())
	
	response, err := http.Get(u.String())
	if err != nil {
		fmt.Printf("Error sending GET request: %v\n", err)
		return nil, err
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		fmt.Printf("Error sending GET request: %s\n", response.Status)
		return nil, fmt.Errorf("API request failed with status: %s", response.Status)
	}

	body, err := io.ReadAll(response.Body)
	if err != nil {
		fmt.Printf("Error reading response body: %v\n", err)
		return nil, err
	}

	return body, nil
}

func GetSearchResults(searchTerm SearchTerm) (SearchResult, error) {
	fmt.Printf("Searching for SecDim related to SARIF Rule ID: %s\n", searchTerm.ID)
	var searchResult = SearchResult{
		RuleID: searchTerm.ID,
	}

	var jsonResponse []apiresponse.Vulnerability

	// Search by CWE first (most specific)
	for i, cweCode := range searchTerm.CWECode {
		response, err := SearchAPIWithParams(cweCode, "", "")
		if err != nil {
			fmt.Printf("Error searching by CWE %s: %v\n", cweCode, err)
			continue
		}

		if err := json.Unmarshal(response, &jsonResponse); err != nil {
			fmt.Printf("Error unmarshaling CWE search response: %v\n", err)
			continue
		}

		if len(jsonResponse) > 0 {
			searchResult.ResultJson = jsonResponse
			if i < len(searchTerm.CWEDescription) && searchTerm.CWEDescription[i] != "" {
				searchResult.Title = fmt.Sprintf("CWE-%s: %s", cweCode, searchTerm.CWEDescription[i])
			} else {
				searchResult.Title = fmt.Sprintf("CWE-%s", cweCode)
			}
			return searchResult, nil
		}
	}

	// Search by OWASP if no CWE results
	for i, owaspCode := range searchTerm.OWASPCode {
		response, err := SearchAPIWithParams("", owaspCode, "")
		if err != nil {
			fmt.Printf("Error searching by OWASP %s: %v\n", owaspCode, err)
			continue
		}

		if err := json.Unmarshal(response, &jsonResponse); err != nil {
			fmt.Printf("Error unmarshaling OWASP search response: %v\n", err)
			continue
		}

		if len(jsonResponse) > 0 {
			searchResult.ResultJson = jsonResponse
			if i < len(searchTerm.OWASPDescription) && searchTerm.OWASPDescription[i] != "" {
				searchResult.Title = fmt.Sprintf("OWASP-%s: %s", owaspCode, searchTerm.OWASPDescription[i])
			} else {
				searchResult.Title = fmt.Sprintf("OWASP-%s", owaspCode)
			}
			return searchResult, nil
		}
	}

	// Search by CWE descriptions as free text
	for _, cweDesc := range searchTerm.CWEDescription {
		if cweDesc == "" {
			continue
		}
		response, err := SearchAPIWithParams("", "", cweDesc)
		if err != nil {
			fmt.Printf("Error searching by CWE description '%s': %v\n", cweDesc, err)
			continue
		}

		if err := json.Unmarshal(response, &jsonResponse); err != nil {
			fmt.Printf("Error unmarshaling CWE description search response: %v\n", err)
			continue
		}

		if len(jsonResponse) > 0 {
			searchResult.ResultJson = jsonResponse
			searchResult.Title = cweDesc
			return searchResult, nil
		}
	}

	// Search by OWASP descriptions as free text
	for _, owaspDesc := range searchTerm.OWASPDescription {
		if owaspDesc == "" {
			continue
		}
		response, err := SearchAPIWithParams("", "", owaspDesc)
		if err != nil {
			fmt.Printf("Error searching by OWASP description '%s': %v\n", owaspDesc, err)
			continue
		}

		if err := json.Unmarshal(response, &jsonResponse); err != nil {
			fmt.Printf("Error unmarshaling OWASP description search response: %v\n", err)
			continue
		}

		if len(jsonResponse) > 0 {
			searchResult.ResultJson = jsonResponse
			searchResult.Title = owaspDesc
			return searchResult, nil
		}
	}

	// Search by free text terms
	for _, freeText := range searchTerm.FreeText {
		if freeText == "" {
			continue
		}
		response, err := SearchAPIWithParams("", "", freeText)
		if err != nil {
			fmt.Printf("Error searching by free text '%s': %v\n", freeText, err)
			continue
		}

		if err := json.Unmarshal(response, &jsonResponse); err != nil {
			fmt.Printf("Error unmarshaling free text search response: %v\n", err)
			continue
		}

		if len(jsonResponse) > 0 {
			searchResult.ResultJson = jsonResponse
			searchResult.Title = freeText
			return searchResult, nil
		}
	}

	// If nothing found, search by rule description as fallback
	if searchTerm.Description != "" {
		response, err := SearchAPIWithParams("", "", searchTerm.Description)
		if err != nil {
			fmt.Printf("Error searching by rule description: %v\n", err)
		} else {
			if err := json.Unmarshal(response, &jsonResponse); err != nil {
				fmt.Printf("Error unmarshaling rule description search response: %v\n", err)
			} else if len(jsonResponse) > 0 {
				searchResult.ResultJson = jsonResponse
				searchResult.Title = searchTerm.Description
				return searchResult, nil
			}
		}
	}

	searchResult.ResultJson = jsonResponse // Will be empty
	return searchResult, nil
}
