package main

import (
    "reflect"
    "testing"
)

func TestParseCSV(t *testing.T) {
    cases := []struct {
        input string
        want  []string
    }{
        {"", nil},
        {"a", []string{"a"}},
        {"a,b", []string{"a", "b"}},
        {"a, b, c", []string{"a", "b", "c"}},
    }

    for _, tc := range cases {
        got := parseCSV(tc.input)
        if !reflect.DeepEqual(got, tc.want) {
            t.Errorf("parseCSV(%q) = %v; want %v", tc.input, got, tc.want)
        }
    }
}
