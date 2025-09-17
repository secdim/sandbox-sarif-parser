package language

import (
	"path/filepath"
	"strings"
)

// LanguageDetector extracts programming languages from SARIF files
type LanguageDetector struct {
	ExtensionMap map[string]string
}

// NewLanguageDetector creates a new language detector with common file extensions
func NewLanguageDetector() *LanguageDetector {
	return &LanguageDetector{
		ExtensionMap: map[string]string{
			".py":    "python",
			".js":    "javascript",
			".ts":    "typescript",
			".java":  "java",
			".c":     "c",
			".cpp":   "cpp",
			".cc":    "cpp",
			".cxx":   "cpp",
			".cs":    "csharp",
			".go":    "go",
			".rs":    "rust",
			".php":   "php",
			".rb":    "ruby",
			".kt":    "kotlin",
			".swift": "swift",
			".scala": "scala",
			".sh":    "shell",
			".bash":  "shell",
			".sql":   "sql",
			".html":  "html",
			".css":   "css",
			".xml":   "xml",
			".json":  "json",
			".yaml":  "yaml",
			".yml":   "yaml",
		},
	}
}

// DetectLanguagesFromSarif extracts languages from a SARIF struct
func (ld *LanguageDetector) DetectLanguagesFromSarif(sarifData interface{}) []string {
	languages := make(map[string]bool)
	
	// Handle both map[string]interface{} and sarif.Sarif types
	switch data := sarifData.(type) {
	case map[string]interface{}:
		ld.extractFromMap(data, languages)
	default:
		// For sarif.Sarif struct, we'll need to convert or handle differently
		// For now, return empty slice for struct types
		return []string{}
	}
	
	// Convert map to slice
	result := make([]string, 0, len(languages))
	for lang := range languages {
		result = append(result, lang)
	}
	
	return result
}

// extractFromMap extracts languages from SARIF map structure
func (ld *LanguageDetector) extractFromMap(sarifData map[string]interface{}, languages map[string]bool) {
	runs, ok := sarifData["runs"].([]interface{})
	if !ok {
		return
	}
	
	for _, run := range runs {
		runMap, ok := run.(map[string]interface{})
		if !ok {
			continue
		}
		
		// Priority 1: Check results for file paths and rule IDs (actual findings)
		resultsLanguages := make(map[string]bool)
		if results, ok := runMap["results"].([]interface{}); ok {
			for _, result := range results {
				if resultMap, ok := result.(map[string]interface{}); ok {
					if locations, ok := resultMap["locations"].([]interface{}); ok {
						for _, location := range locations {
							if locMap, ok := location.(map[string]interface{}); ok {
								if physicalLocation, ok := locMap["physicalLocation"].(map[string]interface{}); ok {
									if artifactLocation, ok := physicalLocation["artifactLocation"].(map[string]interface{}); ok {
										if uri, ok := artifactLocation["uri"].(string); ok {
											if lang := ld.getLanguageFromPath(uri); lang != "" {
												resultsLanguages[lang] = true
											}
										}
									}
								}
							}
						}
					}
					
					// Check rule IDs from actual results
					if ruleId, ok := resultMap["ruleId"].(string); ok {
						if lang := ld.getLanguageFromRuleId(ruleId); lang != "" {
							resultsLanguages[lang] = true
						}
					}
				}
			}
		}
		
		// Priority 2: Check artifacts for file extensions (if we have results languages, filter artifacts)
		if artifacts, ok := runMap["artifacts"].([]interface{}); ok {
			for _, artifact := range artifacts {
				if artifactMap, ok := artifact.(map[string]interface{}); ok {
					if location, ok := artifactMap["location"].(map[string]interface{}); ok {
						if uri, ok := location["uri"].(string); ok {
							if lang := ld.getLanguageFromPath(uri); lang != "" {
								// Only add artifact languages if they match result languages or if no result languages found
								if len(resultsLanguages) == 0 || resultsLanguages[lang] {
									languages[lang] = true
								}
							}
						}
					}
				}
			}
		}
		
		// Add all languages from actual results
		for lang := range resultsLanguages {
			languages[lang] = true
		}
		
		// Priority 3: Check tool driver rules only if no languages found from results/artifacts
		// This prevents Semgrep from detecting too many irrelevant languages
		if len(languages) == 0 {
			if tool, ok := runMap["tool"].(map[string]interface{}); ok {
				if driver, ok := tool["driver"].(map[string]interface{}); ok {
					if rules, ok := driver["rules"].([]interface{}); ok {
						for _, rule := range rules {
							if ruleMap, ok := rule.(map[string]interface{}); ok {
								if ruleId, ok := ruleMap["id"].(string); ok {
									if lang := ld.getLanguageFromRuleId(ruleId); lang != "" {
										languages[lang] = true
									}
								}
							}
						}
					}
				}
			}
		}
	}
}

// getLanguageFromPath determines the programming language from a file path
func (ld *LanguageDetector) getLanguageFromPath(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	if lang, ok := ld.ExtensionMap[ext]; ok {
		return lang
	}
	return ""
}

// getLanguageFromRuleId extracts language from rule IDs
func (ld *LanguageDetector) getLanguageFromRuleId(ruleId string) string {
	ruleId = strings.ToLower(ruleId)
	
	// Common patterns in rule IDs
	patterns := map[string]string{
		"python.":     "python",
		"py/":         "python",
		"javascript.": "javascript",
		"js/":         "javascript",
		"java.":       "java",
		"java/":       "java",
		"go.":         "go",
		"go/":         "go",
		"php.":        "php",
		"php/":        "php",
		"ruby.":       "ruby",
		"rb/":         "ruby",
		"csharp.":     "csharp",
		"cs/":         "csharp",
		"cpp.":        "cpp",
		"cpp/":        "cpp",
		"c.":          "c",
		"c/":          "c",
		"typescript.": "typescript",
		"ts/":         "typescript",
		"kotlin.":     "kotlin",
		"kt/":         "kotlin",
		"swift.":      "swift",
		"rust.":       "rust",
		"rs/":         "rust",
		"/python":     "python",
		"/java":       "java",
		"/javascript": "javascript",
	}
	
	for pattern, lang := range patterns {
		if strings.Contains(ruleId, pattern) {
			return lang
		}
	}
	
	return ""
}

// DetectPrimaryLanguage returns the most likely primary language based on frequency
func (ld *LanguageDetector) DetectPrimaryLanguage(sarifData map[string]interface{}) string {
	languageCounts := make(map[string]int)
	
	runs, ok := sarifData["runs"].([]interface{})
	if !ok {
		return ""
	}
	
	for _, run := range runs {
		runMap, ok := run.(map[string]interface{})
		if !ok {
			continue
		}
		
		// Count languages from results (most accurate as it represents actual findings)
		if results, ok := runMap["results"].([]interface{}); ok {
			for _, result := range results {
				if resultMap, ok := result.(map[string]interface{}); ok {
					// Count from file paths
					if locations, ok := resultMap["locations"].([]interface{}); ok {
						for _, location := range locations {
							if locMap, ok := location.(map[string]interface{}); ok {
								if physicalLocation, ok := locMap["physicalLocation"].(map[string]interface{}); ok {
									if artifactLocation, ok := physicalLocation["artifactLocation"].(map[string]interface{}); ok {
										if uri, ok := artifactLocation["uri"].(string); ok {
											if lang := ld.getLanguageFromPath(uri); lang != "" {
												languageCounts[lang]++
											}
										}
									}
								}
							}
						}
					}
					
					// Count from rule IDs
					if ruleId, ok := resultMap["ruleId"].(string); ok {
						if lang := ld.getLanguageFromRuleId(ruleId); lang != "" {
							languageCounts[lang]++
						}
					}
				}
			}
		}
	}
	
	// Find the most common language
	maxCount := 0
	primaryLang := ""
	for lang, count := range languageCounts {
		if count > maxCount {
			maxCount = count
			primaryLang = lang
		}
	}
	
	return primaryLang
}
