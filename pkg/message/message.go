package message

import (
	"fmt"
	"sandbox/pkg/globals"
	"sandbox/pkg/search"
	"strings"
)

func generateHelpTextMessage(result search.SearchResult) string {
	var builder strings.Builder
	urlSlug := ""

	// If there is match one challenges, link it directly
	if len(result.ResultJson) == 1 {
		builder.WriteString("Explore and debug the " + result.ResultJson[0].Title + " vulnerability on [SecDim](" + globals.CATALOG_URL)
		for i := 0; i < len(result.ResultJson[0].Sandboxes); i++ {
			lowerRuleID := strings.ToLower(result.RuleID)
			lowerLanguage := strings.ToLower(result.ResultJson[0].Sandboxes[i].Language)
			// Split rule ID by '-' or '.'
			splitFunc := func(c rune) bool {
				return c == '-' || c == '.'
			}
			resultIDSplit := strings.FieldsFunc(lowerRuleID, splitFunc)

			if containsString(resultIDSplit, lowerLanguage) {
				urlSlug = *result.ResultJson[0].Sandboxes[i].GameSlug + "/challenge/" + *result.ResultJson[0].Sandboxes[i].ChallengeSlug + "?vulnerability=" + cleanSearchTerm(result.Title)
				break
			}

			for _, tech := range result.ResultJson[0].Sandboxes[i].Technologies {
				if containsString(resultIDSplit, tech) {
					urlSlug = *result.ResultJson[0].Sandboxes[i].GameSlug + "/challenge/" + *result.ResultJson[0].Sandboxes[i].ChallengeSlug + "?vulnerability=" + cleanSearchTerm(result.Title)
					break
				}
			}
		}

		if urlSlug == "" {
			urlSlug = "?search=" + cleanSearchTerm(result.Title)
		}
	} else if len(result.ResultJson) > 1 {
		builder.WriteString("Explore and debug the " + result.Title + " vulnerability on [SecDim](" + globals.CATALOG_URL)
		urlSlug = "?search=" + cleanSearchTerm(result.Title)
	}

	builder.WriteString(urlSlug + ")\n\n")
	return builder.String()
}

func UpdateSarif(sarifData map[string]interface{}, searchResults []search.SearchResult, toolType string) map[string]interface{} {
	fmt.Printf("Updating SARIF data with SecDim information\n")

	runs, ok := sarifData["runs"].([]interface{})
	if !ok {
		return sarifData
	}

	for _, run := range runs {
		runMap, ok := run.(map[string]interface{})
		if !ok {
			continue
		}

		tool, ok := runMap["tool"].(map[string]interface{})
		if !ok {
			continue
		}

		// Handle CodeQL (extensions)
		if toolType == "codeql" {
			extensions, ok := tool["extensions"].([]interface{})
			if !ok {
				continue
			}
			for _, extension := range extensions {
				extMap, ok := extension.(map[string]interface{})
				if !ok {
					continue
				}
				rules, ok := extMap["rules"].([]interface{})
				if !ok {
					continue
				}
				updateRules(rules, searchResults)
			}
		} else { // Handle Semgrep, Snyk (driver)
			driver, ok := tool["driver"].(map[string]interface{})
			if !ok {
				continue
			}
			rules, ok := driver["rules"].([]interface{})
			if !ok {
				continue
			}
			updateRules(rules, searchResults)
		}
	}

	return sarifData
}

func updateRules(rules []interface{}, searchResults []search.SearchResult) {
	for _, rule := range rules {
		ruleMap, ok := rule.(map[string]interface{})
		if !ok {
			continue
		}

		ruleID, ok := ruleMap["id"].(string)
		if !ok {
			continue
		}

		for _, searchResult := range searchResults {
			if searchResult.RuleID == ruleID {
				help, ok := ruleMap["help"].(map[string]interface{})
				if !ok {
					// If help doesn't exist, create it
					help = make(map[string]interface{})
					ruleMap["help"] = help
				}

				// Add to markdown
				if markdown, ok := help["markdown"].(string); ok {
					if !strings.Contains(markdown, "SecDim") {
						help["markdown"] = generateHelpTextMessage(searchResult) + markdown
					}
				} else {
					// If markdown doesn't exist, create it
					help["markdown"] = generateHelpTextMessage(searchResult)
				}

				// Add to text
				if text, ok := help["text"].(string); ok {
					if !strings.Contains(text, "SecDim") {
						help["text"] = generateHelpTextMessage(searchResult) + text
					}
				} else {
					// If text doesn't exist, create it
					help["text"] = generateHelpTextMessage(searchResult)
				}
			}
		}
	}
}

func trimSearchTitlePrefix(title string) string {
	prefixes := []string{"CWE-", "OWASP-"}
	for _, prefix := range prefixes {
		title = strings.TrimPrefix(title, prefix)
	}
	return title
}

func containsString(arr []string, givenStr string) bool {
	for _, str := range arr {
		if str == givenStr {
			return true
		}
	}
	return false
}

func cleanSearchTerm(term string) string {
	term = trimSearchTitlePrefix(term)
	// Simplified URL encoding - avoid %20 which might cause SARIF parsing issues
	term = strings.ReplaceAll(term, " ", "+")
	term = strings.ReplaceAll(term, "'", "")
	term = strings.ReplaceAll(term, "\"", "")
	term = strings.ReplaceAll(term, "(", "")
	term = strings.ReplaceAll(term, ")", "")
	return term
}
