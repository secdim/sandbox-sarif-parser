
package apiresponse

import (
    "encoding/json"
    "reflect"
    "testing"
)

func TestVulnerabilityUnmarshal(t *testing.T) {
    jsonData := []byte(`{
        "vulnerability_id": "1234",
        "title": "Test Vuln",
        "description": "This is a test vulnerability",
        "tags": [
            {"name": "test", "category": "cat", "search_able": true, "slug": "test-slug"}
        ],
        "severity": "high",
        "sandboxes": [
            {
                "id": 1,
                "tags": [{"name":"easy","slug":"easy"}],
                "language": "go",
                "technologies": ["go","cli"],
                "challengeSlug": "challenge-1",
                "gameSlug": "game-1"
            }
        ],
        "cwes": [
            {"cwe_id": 79, "title": "XSS", "slug": "xss"}
        ],
        "owasps": [
            {"owasp_id": "A1", "title": "Injection", "slug": "injection"}
        ],
        "slug": "test-vuln",
        "created_at": "2025-05-20T12:00:00Z"
    }`)

    var v Vulnerability
    if err := json.Unmarshal(jsonData, &v); err != nil {
        t.Fatalf("Unmarshal failed: %v", err)
    }

    want := Vulnerability{
        VulnerabilityID: "1234",
        Title:           "Test Vuln",
        Description:     "This is a test vulnerability",
        Tags: []Tag{
            {Name: "test", Category: "cat", Searchable: true, Slug: "test-slug"},
        },
        Severity: "high",
        Sandboxes: []Sandbox{
            {
                ID:           1,
                SandboxTags:  []SandboxTag{{Name: "easy", Slug: "easy"}},
                Language:     "go",
                Technologies: []string{"go", "cli"},
                ChallengeSlug: ptr("challenge-1"),
                GameSlug:      ptr("game-1"),
            },
        },
        CWES: []CWE{
            {CWEID: 79, Title: "XSS", Slug: "xss"},
        },
        OWASPS: []OWASP{
            {OWASPId: "A1", Title: "Injection", Slug: "injection"},
        },
        Slug:      "test-vuln",
        CreatedAt: "2025-05-20T12:00:00Z",
    }

    if !reflect.DeepEqual(v, want) {
        t.Errorf("Unmarshaled Vulnerability = %+v, want %+v", v, want)
    }
}

// helper to get pointer of string
func ptr(s string) *string {
    return &s
}
