package sarif

import (
	"encoding/json"
	"fmt"
	"os"
)

func ReadSarifFile(file string) (map[string]interface{}, error) {
	fmt.Printf("Reading SARIF file: %s\n", file)
	data, err := os.ReadFile(file)
	if err != nil {
		fmt.Printf("Error reading SARIF file: %v\n", err)
		return nil, err
	}
	var sarifData map[string]interface{}
	if err := json.Unmarshal(data, &sarifData); err != nil {
		fmt.Printf("Error unmarshaling file data: %v\n", err)
		return nil, err
	}
	fmt.Printf("Read SARIF file: %s\n", file)
	return sarifData, nil
}

func WriteSarifFile(file string, sarifData map[string]interface{}) error {
	fmt.Printf("Writing SARIF file: %s\n", file)
	jsonData, err := json.MarshalIndent(sarifData, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling file data: %v\n", err)
		return err
	}
	err = os.WriteFile(file, jsonData, 0644)
	if err != nil {
		fmt.Printf("Error writing SARIF file: %v\n", err)
		return err
	}
	fmt.Printf("Wrote SARIF file: %s\n", file)
	return nil
}

// ReadSarifFileForParsing reads the file into the struct model just for parsing.
func ReadSarifFileForParsing(file string) (Sarif, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return Sarif{}, err
	}
	var sarifData Sarif
	if err := json.Unmarshal(data, &sarifData); err != nil {
		return Sarif{}, err
	}
	return sarifData, nil
}
