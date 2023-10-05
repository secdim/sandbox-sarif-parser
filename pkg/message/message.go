package message

import (
	"fmt"
	"sandbox/pkg/globals"
	"sandbox/pkg/sarif"
	"sandbox/pkg/search"
	"strings"
)

func generateHelpTextMessage(result search.SearchResult) string {
	var builder strings.Builder
	urlSlug := ""

	if len(result.ResultJson) == 1 {
		builder.WriteString("Explore and debug the " + result.ResultJson[0].Title + " vulnerability on [SecDim Sandbox](" + globals.SANDBOX_URL)
		for i := 0; i < len(result.ResultJson[0].Sandboxes); i++ {
			lowerRuleID := strings.ToLower(result.RuleID)
			lowerLanguage := strings.ToLower(result.ResultJson[0].Sandboxes[i].Language)
			// Split rule ID by '-' or '.'
			splitFunc := func(c rune) bool {
				return c == '-' || c == '.'
			}
			resultIDSplit := strings.FieldsFunc(lowerRuleID, splitFunc)

			if containsString(resultIDSplit, lowerLanguage) {
				urlSlug = result.ResultJson[0].Slug + "/id/" + fmt.Sprintf("%d", result.ResultJson[0].Sandboxes[i].ID)
				break
			}

			for _, tech := range result.ResultJson[0].Sandboxes[i].Technologies {
				if containsString(resultIDSplit, tech) {
					urlSlug = result.ResultJson[0].Slug + "/id/" + fmt.Sprintf("%d", result.ResultJson[0].Sandboxes[i].ID)
					break
				}
			}
		}

		if urlSlug == "" {
			urlSlug = "?search=" + cleanSearchTerm(result.Title)
		}
	} else if len(result.ResultJson) > 1 {
		builder.WriteString("Explore and debug the " + result.Title + " vulnerability on [SecDim Sandbox](" + globals.SANDBOX_URL)
		urlSlug = "?search=" + cleanSearchTerm(result.Title)
	}

	builder.WriteString(urlSlug + ")\n\n")
	return builder.String()
}

func UpdateOutputSarifHelpMessage(outSarif sarif.Sarif, results []search.SearchResult) sarif.Sarif {
	fmt.Printf("Updating output SARIF file with SecDim Sandbox information\n")
	for _, result := range results {
		for _, run := range outSarif.Runs {
			for i := 0; i < len(run.Tool.Driver.Rules); i++ {
				if run.Tool.Driver.Rules[i].ID == result.RuleID {
					if len(result.ResultJson) == 1 {
						run.Tool.Driver.Rules[i].ShortDescription.Text = "SecDim Sandbox: " + result.ResultJson[0].Title
					} else if len(result.ResultJson) > 1 {
						run.Tool.Driver.Rules[i].ShortDescription.Text = "SecDim Sandbox: " + result.Title
					}
					run.Tool.Driver.Rules[i].HelpUri = globals.SANDBOX_URL
					if !strings.Contains(run.Tool.Driver.Rules[i].Help.Text, "SecDim Sandbox") {
						run.Tool.Driver.Rules[i].Help.Text = generateHelpTextMessage(result) + run.Tool.Driver.Rules[i].Help.Text
						run.Tool.Driver.Rules[i].Help.Markdown = generateHelpTextMessage(result) + run.Tool.Driver.Rules[i].Help.Markdown
					}
				}
			}
		}
	}

	return outSarif
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
	term = strings.ReplaceAll(term, " ", "%20")
	term = strings.ReplaceAll(term, "'", "")
	term = strings.ReplaceAll(term, "\"", "")
	term = strings.ReplaceAll(term, "(", "")
	term = strings.ReplaceAll(term, ")", "")
	return term
}
