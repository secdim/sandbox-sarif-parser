package message

import (
	"fmt"
	apiresponse "sandbox/pkg/apireponse"
	"sandbox/pkg/sarif"
	"sandbox/pkg/search"
	"strings"
)

func generateHelpTextMessage(vulnerability []apiresponse.Vulnerability, ruleId string) string {
	var builder strings.Builder
	for _, vuln := range vulnerability {
		builder.WriteString("Explore and debug this vulnerability in [SecDim Sandbox](https://play.secdim.com/sandbox/")

		urlSlug := ""
		for i := 0; i < len(vuln.Sandboxes); i++ {
			if strings.Contains(strings.ToLower(ruleId), strings.ToLower(vuln.Sandboxes[i].Language)) {
				urlSlug = vuln.Slug + "/id/" + fmt.Sprintf("%d", vuln.Sandboxes[i].ID)
				break
			}
		}
		builder.WriteString(urlSlug + "/)\n\n")
	}
	return builder.String()
}

func UpdateOutputSarifHelpMessage(outSarif sarif.Sarif, results []search.SearchResult) sarif.Sarif {
	const HelpUri = "https://play.secdim.com/sandbox/"
	for _, result := range results {
		for _, run := range outSarif.Runs {
			for i := 0; i < len(run.Tool.Driver.Rules); i++ {
				if run.Tool.Driver.Rules[i].ID == result.RuleID {
					run.Tool.Driver.Rules[i].ShortDescription.Text = "SecDim: " + result.ResultJson[0].Title
					run.Tool.Driver.Rules[i].HelpUri = HelpUri
					run.Tool.Driver.Rules[i].Help.Text = generateHelpTextMessage(result.ResultJson, result.RuleID) + run.Tool.Driver.Rules[i].Help.Text
					run.Tool.Driver.Rules[i].Help.Markdown = generateHelpTextMessage(result.ResultJson, result.RuleID) + run.Tool.Driver.Rules[i].Help.Markdown
				}
			}
		}
	}

	return outSarif
}
