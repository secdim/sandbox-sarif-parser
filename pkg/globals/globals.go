package globals

import (
	"fmt"
	"os"
)

// getEnv retrieves the environment variable by key or returns the default value if unset.
func GetEnv(key, defaultVal string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultVal
}

// mustGetEnv retrieves the environment variable by key or panics if unset.
func MustGetEnv(key string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	panic(fmt.Sprintf("environment variable %s must be set", key))
}

var (
	SEARCH_API_URL = GetEnv("SECDIM_SEARCH_API_URLL", "https://play.secdim.com/play/vuln/")
	GAME_URL       = GetEnv("SECDIM_GAME_URL", "https://play.secdim.com/game/")
	CATALOG_URL    = GetEnv("SECDIM_CATALOG_URL", "https://play.secdim.com/browse/")
	// GAME_API_URL is the base URL for the SecDim game API (e.g. https://play.secdim.com/play).
	GAME_API_URL = GetEnv("SECDIM_GAME_API_URL", "https://play.secdim.com/play")
	// API_KEY
	API_KEY = GetEnv("SECDIM_API_KEY", "API-KEY-IS-REQUIRED-FOR-JIT")
)
