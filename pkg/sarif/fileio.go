package sarif

import (
	"encoding/json"
	"fmt"
	"os"
)

func ReadSarifFile(file string) (Sarif, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		fmt.Printf("Error reading file: %v\n", err)
		return Sarif{}, err
	}

	var sarifData Sarif
	if err := json.Unmarshal(data, &sarifData); err != nil {
		fmt.Printf("Error unmarshaling JSON: %v\n", err)
		return Sarif{}, err
	}

	return sarifData, nil
}

func WriteSarifFile(file string, sarifData Sarif) error {
	jsonData, err := json.MarshalIndent(sarifData, "", "  ")
	if err != nil {
		fmt.Printf("Error marshaling JSON: %v\n", err)
		return err
	}

	err = os.WriteFile(file, jsonData, 0644)
	if err != nil {
		fmt.Printf("Error writing JSON file: %v\n", err)
		return err
	}

	return nil
}
