package main

import (
	"fmt"
	"os"
	"reflect"
	"sandbox/pkg/globals"
	"sandbox/pkg/message"
	"sandbox/pkg/sarif"
	"sandbox/pkg/search"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Println(`
Usage:
	sandbox <input_file> <output_file>
	`)
		os.Exit(1)
		return
	}
	arg1 := os.Args[1]
	arg2 := os.Args[2]

	inSarifFile, err := sarif.ReadSarifFile(arg1)
	if err != nil {
		fmt.Printf("Exiting...\n")
		os.Exit(1)
	}
	v := reflect.ValueOf(&inSarifFile).Elem()
	sarif.RemoveNullFields(v)

	var searchTerms = search.ParseSarifStruct(inSarifFile)
	var searchResults []search.SearchResult

	resultCount := 0
	for _, searchTerm := range searchTerms {
		result, err := search.GetSearchResults(searchTerm)

		if err != nil {
			continue
		}
		if len(result.ResultJson) > 0 {
			if len(result.ResultJson) == 1 {
				fmt.Printf("Found %d API search results\n", len(result.ResultJson))
			} else {
				fmt.Printf("Found %d API search results\n", len(result.ResultJson))
			}
			searchResults = append(searchResults, result)
			resultCount++
		}
	}

	if resultCount == 0 {
		fmt.Printf("No results found\n")
	} else if resultCount == 1 {
		fmt.Printf("Found 1 total vulnerability search result\n")
	} else {
		fmt.Printf("Found %d total vulnerability search results\n", resultCount)
	}

	outSarifFile := message.UpdateOutputSarifHelpMessage(inSarifFile, searchResults)
	cleanedSarif := sarif.RemoveEmptyResults(outSarifFile)
	sarif.WriteSarifFile(arg2, cleanedSarif)

	fmt.Printf("Please visit " + globals.SANDBOX_URL + " to explore and debug other security vulnerabilities with SecDim Sandbox\n")

	os.Exit(0)
}
