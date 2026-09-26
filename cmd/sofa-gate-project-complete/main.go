// sofa-gate-project-complete closes only suite-owned disposable issue and
// Project resources after the trusted observer has validated the hosted run.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"time"

	"github.com/kevinmartin/sofa-disposable/internal/fixturelifecycle"
)

var sha40 = regexp.MustCompile(`^[0-9a-f]{40}$`)

type completer interface {
	Verify(context.Context, fixturelifecycle.Suite) (fixturelifecycle.Resource, error)
	Complete(context.Context, fixturelifecycle.Suite) (fixturelifecycle.Resource, error)
}

type observed struct {
	SchemaVersion     int    `json:"schema_version"`
	SofaPR            int    `json:"sofa_pr"`
	CandidateSHA      string `json:"candidate_sha"`
	PRBaseSHA         string `json:"pr_base_sha"`
	DisposableBaseSHA string `json:"disposable_base_sha"`
	SuiteID           string `json:"suite_id"`
}

func exactSuite(r observed) (fixturelifecycle.Suite, error) {
	if r.SchemaVersion != 4 || r.SofaPR < 1 || !sha40.MatchString(r.CandidateSHA) || !sha40.MatchString(r.PRBaseSHA) || !sha40.MatchString(r.DisposableBaseSHA) {
		return fixturelifecycle.Suite{}, errors.New("invalid trusted observer suite identity")
	}
	digest := sha256.Sum256([]byte(r.CandidateSHA + ":" + r.PRBaseSHA + ":" + r.DisposableBaseSHA))
	if r.SuiteID != fmt.Sprintf("p%d-%x", r.SofaPR, digest[:12]) {
		return fixturelifecycle.Suite{}, errors.New("trusted observer suite digest mismatch")
	}
	return fixturelifecycle.Suite{ID: r.SuiteID, CandidateSHA: r.CandidateSHA, PRBaseSHA: r.PRBaseSHA, DisposableBaseSHA: r.DisposableBaseSHA}, nil
}

func complete(ctx context.Context, data []byte, gate completer) ([]byte, error) {
	if len(data) > 100<<10 {
		return nil, errors.New("trusted observer result exceeds limit")
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte{'\n'})
	if len(lines) > 100 {
		return nil, errors.New("too many trusted observer results")
	}
	var out bytes.Buffer
	for _, line := range lines {
		var r observed
		decoder := json.NewDecoder(bytes.NewReader(line))
		if err := decoder.Decode(&r); err != nil || decoder.Decode(new(any)) != io.EOF {
			return nil, errors.New("trusted observer result invalid")
		}
		suite, err := exactSuite(r)
		if err != nil {
			return nil, err
		}
		var record map[string]json.RawMessage
		if err := json.Unmarshal(line, &record); err != nil || len(record) == 0 {
			return nil, errors.New("trusted observer report invalid")
		}
		for _, key := range []string{"test_issue", "test_issue_url", "project_item", "test_item_state"} {
			if _, exists := record[key]; exists {
				return nil, errors.New("trusted observer report preclaims Project cleanup")
			}
		}
		resource, err := gate.Verify(ctx, suite)
		if err != nil || resource.IssueNumber < 1 || resource.ProjectItem == "" {
			return nil, errors.New("suite-owned Project item unavailable")
		}
		completed, err := gate.Complete(ctx, suite)
		if err != nil || !completed.Closed || !completed.Archived || completed.IssueNumber != resource.IssueNumber || completed.ProjectItem != resource.ProjectItem {
			return nil, errors.New("suite-owned Project item cleanup unavailable")
		}
		for key, value := range map[string]any{
			"test_issue":      completed.IssueNumber,
			"test_issue_url":  completed.IssueURL,
			"project_item":    completed.ProjectItem,
			"test_item_state": "closed_archived",
		} {
			encoded, err := json.Marshal(value)
			if err != nil {
				return nil, errors.New("cannot encode Project cleanup result")
			}
			record[key] = encoded
		}
		encoded, err := json.Marshal(record)
		if err != nil {
			return nil, errors.New("cannot encode completed observer result")
		}
		out.Write(encoded)
		out.WriteByte('\n')
	}
	return out.Bytes(), nil
}

func main() {
	if os.Getenv("GITHUB_REPOSITORY") != "kevinmartin/sofa-disposable" || os.Getenv("GITHUB_REF") != "refs/heads/main" {
		fmt.Fprintln(os.Stderr, "trusted Project completion identity unavailable")
		os.Exit(1)
	}
	token, projectToken := os.Getenv("GH_TOKEN"), os.Getenv("SOFA_PROJECTS_TOKEN")
	if token == "" || projectToken == "" {
		fmt.Fprintln(os.Stderr, "trusted Project completion credentials unavailable")
		os.Exit(1)
	}
	file, err := os.Open("gate-results.jsonl")
	if err != nil {
		fmt.Fprintln(os.Stderr, "trusted observer report unavailable")
		os.Exit(1)
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(bufio.NewReader(file), (100<<10)+1))
	if err != nil || len(data) > 100<<10 {
		fmt.Fprintln(os.Stderr, "trusted observer report exceeds limit")
		os.Exit(1)
	}
	httpClient := &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}
	gate := fixturelifecycle.Client{HTTP: httpClient, Token: projectToken, IssueToken: token}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	completed, err := complete(ctx, data, gate)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trusted Project completion:", err)
		os.Exit(1)
	}
	if err := os.WriteFile("gate-results-complete.jsonl", completed, 0600); err != nil {
		fmt.Fprintln(os.Stderr, "completed observer report unavailable")
		os.Exit(1)
	}
	fmt.Printf("completed %s suite-owned Project item report bytes\n", strconv.Itoa(len(completed)))
}
