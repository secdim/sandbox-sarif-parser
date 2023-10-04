package message

import (
	"fmt"
	"sandbox/pkg/sarif"
	"sandbox/pkg/search"
	"strings"
)

func generateHelpTextMessage(result search.SearchResult) string {
	var builder strings.Builder
	builder.WriteString("Explore and debug this vulnerability in [SecDim Sandbox](https://play.secdim.com/sandbox/")
	urlSlug := ""

	if len(result.ResultJson) == 1 {
		for i := 0; i < len(result.ResultJson[0].Sandboxes); i++ {
			if strings.Contains(strings.ToLower(result.RuleID), strings.ToLower(result.ResultJson[0].Sandboxes[i].Language)) {
				urlSlug = result.ResultJson[0].Slug + "/id/" + fmt.Sprintf("%d", result.ResultJson[0].Sandboxes[i].ID)
				break
			}
		}
	} else if len(result.ResultJson) > 1 {
		urlSlug = "?search=" + strings.ReplaceAll(result.Title, " ", "%20")
	}

	builder.WriteString(urlSlug + "/)\n\n")
	return builder.String()
}

func UpdateOutputSarifHelpMessage(outSarif sarif.Sarif, results []search.SearchResult) sarif.Sarif {
	fmt.Printf("Updating output SARIF file with SecDim Sandbox information\n")
	const HelpUri = "https://play.secdim.com/sandbox/"
	for _, result := range results {
		for _, run := range outSarif.Runs {
			for i := 0; i < len(run.Tool.Driver.Rules); i++ {
				if run.Tool.Driver.Rules[i].ID == result.RuleID {
					if len(result.ResultJson) == 1 {
						run.Tool.Driver.Rules[i].ShortDescription.Text = "SecDim Sandbox: " + result.ResultJson[0].Title
					} else if len(result.ResultJson) > 1 {
						run.Tool.Driver.Rules[i].ShortDescription.Text = "SecDim Sandbox: " + result.Title
					}
					run.Tool.Driver.Rules[i].HelpUri = HelpUri
					run.Tool.Driver.Rules[i].Help.Text = generateHelpTextMessage(result) + run.Tool.Driver.Rules[i].Help.Text
					run.Tool.Driver.Rules[i].Help.Markdown = generateHelpTextMessage(result) + run.Tool.Driver.Rules[i].Help.Markdown
				}
			}
		}
	}

	return outSarif
}
