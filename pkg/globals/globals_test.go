package globals

import (
    "os"
    "testing"
)

func TestGetEnv(t *testing.T) {
    const key = "TEST_ENV_KEY"
    os.Unsetenv(key)
    def := "default"
    if val := GetEnv(key, def); val != def {
        t.Errorf("GetEnv: expected default %q, got %q", def, val)
    }
    os.Setenv(key, "value")
    if val := GetEnv(key, def); val != "value" {
        t.Errorf("GetEnv: expected %q, got %q", "value", val)
    }
}

func TestMustGetEnv(t *testing.T) {
    const key = "TEST_MUST_ENV"
    os.Setenv(key, "must")
    if val := MustGetEnv(key); val != "must" {
        t.Errorf("MustGetEnv: expected %q, got %q", "must", val)
    }
    os.Unsetenv(key)
    defer func() {
        if r := recover(); r == nil {
            t.Errorf("MustGetEnv: expected panic for missing key")
        }
    }()
    _ = MustGetEnv(key)
}
