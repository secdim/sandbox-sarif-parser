package sarif

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
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

func RemoveNullFields(v reflect.Value) {
	switch v.Kind() {
	case reflect.Ptr:
		if v.IsNil() {
			return
		}
		RemoveNullFields(v.Elem())
	case reflect.Interface:
		if v.IsNil() {
			return
		}
		RemoveNullFields(v.Elem())
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			field := v.Field(i)
			if field.Kind() == reflect.Ptr && field.IsNil() {
				// Replace nil pointer with zero value of its type
				field.Set(reflect.New(field.Type().Elem()))
			} else if field.Kind() == reflect.Slice && field.IsNil() {
				// Replace nil slice with empty slice of its type
				field.Set(reflect.MakeSlice(field.Type(), 0, 0))
			} else {
				RemoveNullFields(field)
			}
		}
	case reflect.Slice:
		for i := 0; i < v.Len(); i++ {
			RemoveNullFields(v.Index(i))
		}
	case reflect.Map:
		for _, key := range v.MapKeys() {
			RemoveNullFields(v.MapIndex(key))
		}
	}
}
