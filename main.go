package main

import (
	"fmt"
	"os"
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
		return
	}
	arg1 := os.Args[1]
	arg2 := os.Args[2]

	inSarifFile, err := sarif.ReadSarifFile(arg1)
	if err != nil {
		return
	}

	var searchTerms = search.ParseSarifStruct(inSarifFile)
	var searchResults []search.SearchResult

	for _, searchTerm := range searchTerms {
		result, err := search.GetSearchResults(searchTerm)

		if err != nil {
			return
		}
		if len(result.ResultJson) > 0 {
			searchResults = append(searchResults, result)
		}
	}

	outSarifFile := message.UpdateOutputSarifHelpMessage(inSarifFile, searchResults)
	sarif.WriteSarifFile(arg2, outSarifFile)
}
