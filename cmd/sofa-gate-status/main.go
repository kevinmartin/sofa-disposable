// sofa-gate-status publishes only trusted observer results from the
// disposable default-branch job. It never reads candidate artifacts.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/kevinmartin/sofa-disposable/internal/gatestatus"
)

var sha40 = regexp.MustCompile(`^[0-9a-f]{40}$`)
var sha64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
var suitePattern = regexp.MustCompile(`^p[1-9][0-9]*-[0-9a-f]{24}$`)

type observed struct {
	SchemaVersion       int    `json:"schema_version"`
	SofaPR              int    `json:"sofa_pr"`
	CandidateSHA        string `json:"candidate_sha"`
	PRBaseSHA           string `json:"pr_base_sha"`
	DisposableBaseSHA   string `json:"disposable_base_sha"`
	SuiteID             string `json:"suite_id"`
	CandidateDigest     string `json:"candidate_digest"`
	CandidateRunID      int64  `json:"candidate_run_id"`
	CandidateRunAttempt int    `json:"candidate_run_attempt"`
	DraftPR             int    `json:"draft_pr"`
	DraftPRURL          string `json:"draft_pr_url"`
	DraftHeadSHA        string `json:"draft_head_sha"`
}

func parseResults(data []byte) ([]observed, error) {
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
	results := make([]observed, 0, len(lines))
	for _, line := range lines {
		var r observed
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&r); err != nil || r.SchemaVersion != 1 || r.SofaPR < 1 || !sha40.MatchString(r.CandidateSHA) || !sha40.MatchString(r.PRBaseSHA) || !sha40.MatchString(r.DisposableBaseSHA) || !sha40.MatchString(r.DraftHeadSHA) || !sha64.MatchString(r.CandidateDigest) || !suitePattern.MatchString(r.SuiteID) || r.CandidateRunID < 1 || r.CandidateRunAttempt != 1 || r.DraftPR < 1 || r.DraftPRURL != fmt.Sprintf("https://github.com/kevinmartin/sofa-disposable/pull/%d", r.DraftPR) {
			return nil, errors.New("trusted observer result invalid")
		}
		digest := sha256.Sum256([]byte(r.CandidateSHA + ":" + r.PRBaseSHA + ":" + r.DisposableBaseSHA))
		if r.SuiteID != fmt.Sprintf("p%d-%x", r.SofaPR, digest[:12]) {
			return nil, errors.New("trusted observer suite does not match exact revision")
		}
		if decoder.Decode(new(any)) != io.EOF {
			return nil, errors.New("trusted observer result has trailing data")
		}
		results = append(results, r)
	}
	return results, nil
}

func run(ctx context.Context, data []byte, writer gatestatus.Writer) error {
	results, err := parseResults(data)
	if err != nil {
		return err
	}
	for _, r := range results {
		runURL := fmt.Sprintf("https://github.com/kevinmartin/sofa-disposable/actions/runs/%d", r.CandidateRunID)
		status := gatestatus.Result{PRNumber: r.SofaPR, HeadSHA: r.CandidateSHA, BaseSHA: r.PRBaseSHA, State: gatestatus.Success, RunURL: runURL, Description: fmt.Sprintf("Hosted E2E %s success", r.SuiteID)}
		if err := writer.Publish(ctx, status); err != nil {
			return fmt.Errorf("publish sofa PR %d gate status: %w", r.SofaPR, err)
		}
	}
	return nil
}

func main() {
	if os.Getenv("GITHUB_REPOSITORY") != "kevinmartin/sofa-disposable" || os.Getenv("GITHUB_REF") != "refs/heads/main" {
		fmt.Fprintln(os.Stderr, "trusted status writer identity unavailable")
		os.Exit(1)
	}
	path := os.Getenv("SOFA_GATE_RESULT_PATH")
	if path == "" || strings.ContainsRune(path, '\x00') {
		fmt.Fprintln(os.Stderr, "trusted observer result path unavailable")
		os.Exit(1)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, "trusted observer result unavailable")
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	w := gatestatus.Writer{AppID: os.Getenv("SOFA_GATE_APP_ID"), PrivateKeyPEM: os.Getenv("SOFA_GATE_APP_PRIVATE_KEY")}
	if err := run(ctx, data, w); err != nil {
		fmt.Fprintln(os.Stderr, "sofa gate status:", err)
		os.Exit(1)
	}
}
