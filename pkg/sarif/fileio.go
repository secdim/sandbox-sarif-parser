package sarif

import (
	"encoding/json"
	"fmt"
	"os"
)

func ReadSarifFile(file string) (Sarif, error) {
	fmt.Printf("Reading SARIF file: %s\n", file)
	data, err := os.ReadFile(file)
	if err != nil {
		fmt.Errorf("Error reading SARIF file: %v\n", err)
		return Sarif{}, err
	}
	var sarifData Sarif
	if err := json.Unmarshal(data, &sarifData); err != nil {
		fmt.Errorf("Error unmarshaling file data: %v\n", err)
		return Sarif{}, err
	}
	fmt.Printf("Read SARIF file: %s\n", file)
	return sarifData, nil
}

func WriteSarifFile(file string, sarifData Sarif) error {
	fmt.Printf("Writing SARIF file: %s\n", file)
	jsonData, err := json.MarshalIndent(sarifData, "", "  ")
	if err != nil {
		fmt.Errorf("Error marshaling file data: %v\n", err)
		return err
	}
	err = os.WriteFile(file, jsonData, 0644)
	if err != nil {
		fmt.Errorf("Error writing SARIF file: %v\n", err)
		return err
	}
	fmt.Printf("Wrote SARIF file: %s\n", file)
	return nil
}
