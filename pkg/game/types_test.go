package game

import (
    "strings"
    "testing"
    "time"
)

func TestCreateGamePayloadValidate(t *testing.T) {
    now := time.Now()
    cases := []struct {
        name    string
        payload CreateGamePayload
        wantErr string
    }{
        {
            name:    "empty payload",
            payload: CreateGamePayload{},
            wantErr: "title is required",
        },
        {
            name: "no description",
            payload: CreateGamePayload{
                Title: "Game Title",
            },
            wantErr: "description is required",
        },
        {
            name: "no challenges",
            payload: CreateGamePayload{
                Title:       "Game",
                Description: "Desc",
            },
            wantErr: "at least one challenge is required",
        },
        {
            name: "no start time",
            payload: CreateGamePayload{
                Title:       "Game",
                Description: "Desc",
                Challenges:  []string{"c1"},
            },
            wantErr: "start_time is required",
        },
        {
            name: "no end time",
            payload: CreateGamePayload{
                Title:       "Game",
                Description: "Desc",
                Challenges:  []string{"c1"},
                StartTime:   now,
            },
            wantErr: "end_time is required",
        },
        {
            name: "valid payload",
            payload: CreateGamePayload{
                Title:       "Game",
                Description: "Desc",
                Challenges:  []string{"c1"},
                StartTime:   now,
                EndTime:     now.Add(time.Hour),
            },
            wantErr: "",
        },
    }

    for _, tc := range cases {
        t.Run(tc.name, func(t *testing.T) {
            err := tc.payload.Validate()
            if tc.wantErr == "" {
                if err != nil {
                    t.Errorf("Validate() unexpected error: %v", err)
                }
            } else {
                if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
                    t.Errorf("Validate() expected error containing %q, got %v", tc.wantErr, err)
                }
            }
        })
    }
}
