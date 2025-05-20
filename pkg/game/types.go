package game

import (
	"fmt"
	"time"
)

type Tag struct {
	Name     string  `json:"name"`
	TagColor string  `json:"tag_color"`
	Icon     string  `json:"icon"`
	Category *string `json:"category"`
	Slug     string  `json:"slug"`
}

type Game struct {
	Title       string    `json:"title"`
	Slug        string    `json:"slug"`
	Description string    `json:"description"`
	Tags        []Tag     `json:"tags"`
	Departments []string  `json:"departments"`
	Challenges  []string  `json:"challenges"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
}

type CreateGamePayload struct {
	Title       string    `json:"title"`
	Description string    `json:"description"`
	Challenges  []string  `json:"challenges"`
	StartTime   time.Time `json:"start_time"`
	EndTime     time.Time `json:"end_time"`
	Tags        []string  `json:"tags,omitempty"`
	Departments []string  `json:"departments,omitempty"`
}

type GamePatch struct {
	Slug        string   `json:"slug"`
	Tags        []string `json:"tags,omitempty"`
	Departments []string `json:"departments,omitempty"`
	Challenges  []string `json:"challenges,omitempty"`
}

func (p *CreateGamePayload) Validate() error {
	if p.Title == "" {
		return fmt.Errorf("%w: title is required", ErrInvalidPayload)
	}
	if p.Description == "" {
		return fmt.Errorf("%w: description is required", ErrInvalidPayload)
	}
	if len(p.Challenges) == 0 {
		return fmt.Errorf("%w: at least one challenge is required", ErrInvalidPayload)
	}
	if p.StartTime.IsZero() {
		return fmt.Errorf("%w: start_time is required", ErrInvalidPayload)
	}
	if p.EndTime.IsZero() {
		return fmt.Errorf("%w: end_time is required", ErrInvalidPayload)
	}
	return nil
}
