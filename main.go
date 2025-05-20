package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"sandbox/pkg/game"
	"sandbox/pkg/globals"
	"sandbox/pkg/message"
	"sandbox/pkg/sarif"
	"sandbox/pkg/search"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "enrich":
		enrichCmd := flag.NewFlagSet("enrich", flag.ExitOnError)
		inPath := enrichCmd.String("in", "", "input SARIF file path")
		outPath := enrichCmd.String("out", "", "output SARIF file path")
		enrichCmd.Parse(os.Args[2:])

		if *inPath == "" || *outPath == "" {
			fmt.Fprintln(os.Stderr, "enrich requires --in and --out")
			enrichCmd.Usage()
			os.Exit(1)
		}

		// Load and enrich SARIF
		inSarifFile, err := sarif.ReadSarifFile(*inPath)
		if err != nil {
			fmt.Printf("Exiting...\n")
			os.Exit(1)
		}
		v := reflect.ValueOf(&inSarifFile).Elem()
		sarif.RemoveNullFields(v)

		var searchTerms = search.ParseSarifStruct(inSarifFile)
		var searchResults []search.SearchResult

		resultCount := 0
		for _, searchTerm := range searchTerms {
			result, err := search.GetSearchResults(searchTerm)

			if err != nil {
				continue
			}
			if len(result.ResultJson) > 0 {
				if len(result.ResultJson) == 1 {
					fmt.Printf("Found %d API search results\n", len(result.ResultJson))
				} else {
					fmt.Printf("Found %d API search results\n", len(result.ResultJson))
				}
				searchResults = append(searchResults, result)
				resultCount++
			}
		}

		if resultCount == 0 {
			fmt.Printf("No results found\n")
		} else if resultCount == 1 {
			fmt.Printf("Found 1 total vulnerability search result\n")
		} else {
			fmt.Printf("Found %d total vulnerability search results\n", resultCount)
		}

		outSarifFile := message.UpdateOutputSarifHelpMessage(inSarifFile, searchResults)
		cleanedSarif := sarif.RemoveEmptyResults(outSarifFile)
		sarif.WriteSarifFile(*outPath, cleanedSarif)

		fmt.Println("Please visit " + globals.CATALOG_URL + " to explore and debug other security vulnerabilities with SecDim")

	case "jit":
		jitCmd := flag.NewFlagSet("jit", flag.ExitOnError)
		slug := jitCmd.String("game-slug", globals.GetEnv("JIT_GAME_SLUG", ""), "game slug (or JIT_GAME_SLUG)")
		title := jitCmd.String("game-title", globals.GetEnv("JIT_GAME_TITLE", ""), "game title")
		desc := jitCmd.String("game-desc", globals.GetEnv("JIT_GAME_DESC", ""), "game description")
		chals := jitCmd.String("game-chals", globals.GetEnv("JIT_GAME_CHALS", ""), "comma-separated challenges")
		tags := jitCmd.String("game-tags", globals.GetEnv("JIT_GAME_TAGS", ""), "comma-separated tags")
		depts := jitCmd.String("game-deps", globals.GetEnv("JIT_GAME_DEPARTMENTS", ""), "comma-separated departments")
		start := jitCmd.String("game-start", globals.GetEnv("JIT_GAME_START_TIME", ""), "start time (RFC3339)")
		end := jitCmd.String("game-end", globals.GetEnv("JIT_GAME_END_TIME", ""), "end time (RFC3339)")
		inSarifPath := jitCmd.String("in", "", "input SARIF file path to extract challenges")
		newGame := jitCmd.Bool("new", false, "create a new game if it does not already exist")
		jitCmd.Parse(os.Args[2:])

		if *slug == "" {
			fmt.Fprintln(os.Stderr, "jit requires --game-slug or JIT_GAME_SLUG")
			jitCmd.Usage()
			os.Exit(1)
		}

		// Parse parameters
		tagList := parseCSV(*tags)
		deptList := parseCSV(*depts)
		chalList := parseCSV(*chals)
		var startTime, endTime time.Time
		var err error

		if *start != "" {
			startTime, err = time.Parse(time.RFC3339, *start)
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid start time: %v\n", err)
				os.Exit(1)
			}
		} else {
			startTime = time.Now()
		}

		if *end != "" {
			endTime, err = time.Parse(time.RFC3339, *end)
			if err != nil {
				fmt.Fprintf(os.Stderr, "invalid end time: %v\n", err)
				os.Exit(1)
			}
		} else {
			endTime = startTime.Add(30 * 24 * time.Hour)
		}

		// HTTP client init
		client := game.NewClient(globals.GAME_API_URL, globals.API_KEY)
		ctx := context.Background()

		// Create a new game if newGame is true
		if *newGame {
			payload := &game.CreateGamePayload{
				Title:       *title,
				Description: *desc,
				Challenges:  chalList,
				StartTime:   startTime,
				EndTime:     endTime,
				Tags:        tagList,
				Departments: deptList,
			}
			fmt.Printf("Creating game: %s\n", payload.Title)
			created, err := client.Create(ctx, payload)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error creating game: %v", err)
				os.Exit(1)
			}
			fmt.Printf("Created game '%s' with %d challenges", created.Slug, len(chalList))
			os.Exit(0)
		}

		// Update or patch a game
		gameTags := make([]game.Tag, len(tagList))
		for i, tag := range tagList {
			gameTags[i] = game.Tag{Name: tag}
		}

		gameObj := &game.Game{
			Title:       *title,
			Slug:        *slug,
			Description: *desc,
			Tags:        gameTags,
			Departments: deptList,
			StartTime:   startTime,
			EndTime:     endTime,
		}

		created, err := client.Ensure(ctx, gameObj)
		if err != nil {
			if errors.Is(err, game.ErrUnauthorized) {
				fmt.Fprintln(os.Stderr, "unauthorized: invalid or missing API key")
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "error ensuring game: %v\n", err)
			os.Exit(1)
		}

		// Verify SARIF input for challenges
		if *inSarifPath == "" {
			fmt.Fprintln(os.Stderr, "jit requires --in for SARIF file to extract challenges")
			jitCmd.Usage()
			os.Exit(1)
		}

		inSarif, err := sarif.ReadSarifFile(*inSarifPath)
		if err != nil {
			fmt.Printf("Exiting...\n")
			os.Exit(1)
		}
		v := reflect.ValueOf(&inSarif).Elem()
		sarif.RemoveNullFields(v)

		terms := search.ParseSarifStruct(inSarif)
		challengeSet := make(map[string]struct{})
		for _, term := range terms {
			res, err := search.GetSearchResults(term)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error searching term %s: %v\n", term.ID, err)
				continue
			}
			for _, vuln := range res.ResultJson {
				for _, sb := range vuln.Sandboxes {
					challengeSet[*sb.ChallengeSlug] = struct{}{}
				}
			}
		}
		var challenges []string
		for slug := range challengeSet {
			fmt.Printf("Found related challenge: %s\n", slug)
			challenges = append(challenges, slug)
		}

		fmt.Printf("Updating '%s' with %d challenges\n", created.Slug, len(challenges))

		// Update game with challenges
		patch := &game.GamePatch{Slug: created.Slug, Challenges: challenges, Tags: tagList, Departments: deptList}
		_, err = client.Patch(ctx, patch)
		if err != nil {
			if errors.Is(err, game.ErrUnauthorized) {
				fmt.Fprintf(os.Stderr, err.Error())
				os.Exit(1)
			}
			fmt.Fprintf(os.Stderr, "error patching game: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Game '%s' updated with %d challenges\n", created.Slug, len(challenges))

	default:
		printUsage()
		os.Exit(1)
	}
}

// parseCSV splits a comma-separated string into a slice, trimming spaces.
func parseCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}

func printUsage() {
	fmt.Print(`Usage:
  sandbox enrich --in <input.sarif> --out <output.sarif>
  sandbox jit --game-slug <slug> [--game-title <title>] [--game-desc <desc>] [--game-tags <t1,t2>] \
    [--game-deps <d1,d2>] [--game-chals <c1,c2>] [--game-start <RFC3339>] [--game-end <RFC3339>] [--new] --in <input.sarif>

Environment variables:
  SECDIM_SEARCH_API_URL	(SARIF enrichment search base URL)
  SECDIM_GAME_URL 	   	(Game/Challenge UI URL)
  SECDIM_CATALOG_URL 	(Catalog UI URL)
  SECDIM_GAME_API_URL  	(Game API base URL)
  SECDIM_API_KEY       	(API key for both enrichment and game endpoints)

JIT-specific overrides:
  JIT_GAME_SLUG
  JIT_GAME_TITLE
  JIT_GAME_DESC
  JIT_GAME_TAGS
  JIT_GAME_DEPARTMENTS
  JIT_GAME_START_TIME
  JIT_GAME_END_TIME
`)
}
