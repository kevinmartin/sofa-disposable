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
	SchemaVersion         int       `json:"schema_version"`
	SofaPR                int       `json:"sofa_pr"`
	CandidateSHA          string    `json:"candidate_sha"`
	PRBaseSHA             string    `json:"pr_base_sha"`
	DisposableBaseSHA     string    `json:"disposable_base_sha"`
	SuiteID               string    `json:"suite_id"`
	CandidateDigest       string    `json:"candidate_digest"`
	CandidateRunID        int64     `json:"candidate_run_id"`
	CandidateRunAttempt   int       `json:"candidate_run_attempt"`
	CandidateRunURL       string    `json:"candidate_run_url"`
	CandidateRunStartedAt time.Time `json:"candidate_run_started_at"`
	CandidateRunUpdatedAt time.Time `json:"candidate_run_updated_at"`
	CandidateDurationMS   int64     `json:"candidate_duration_ms"`
	ReportArtifactID      int64     `json:"report_artifact_id"`
	ReportArtifactURL     string    `json:"report_artifact_url"`
	Denials               []struct {
		Kind        string `json:"kind"`
		SuiteID     string `json:"suite_id"`
		Decision    string `json:"decision"`
		ArtifactID  int64  `json:"artifact_id"`
		ArtifactURL string `json:"artifact_url"`
	} `json:"denials"`
	DraftPR            int    `json:"draft_pr"`
	DraftPRURL         string `json:"draft_pr_url"`
	DraftHeadSHA       string `json:"draft_head_sha"`
	DraftHeadRef       string `json:"draft_head_ref"`
	DraftBaseRef       string `json:"draft_base_ref"`
	DraftState         string `json:"draft_state"`
	DraftIsDraft       bool   `json:"draft_is_draft"`
	OwnedResourceState string `json:"owned_resource_cleanup_state"`
}

func validObserved(r observed) bool {
	if r.SchemaVersion != 3 || r.SofaPR < 1 || !sha40.MatchString(r.CandidateSHA) || !sha40.MatchString(r.PRBaseSHA) || !sha40.MatchString(r.DisposableBaseSHA) || !sha40.MatchString(r.DraftHeadSHA) || !sha64.MatchString(r.CandidateDigest) || !suitePattern.MatchString(r.SuiteID) || r.CandidateRunID < 1 || r.CandidateRunAttempt != 1 || r.ReportArtifactID < 1 || r.DraftPR < 1 {
		return false
	}
	if r.CandidateRunURL != fmt.Sprintf("https://github.com/kevinmartin/sofa-disposable/actions/runs/%d", r.CandidateRunID) ||
		r.ReportArtifactURL != fmt.Sprintf("https://github.com/kevinmartin/sofa-disposable/actions/runs/%d/artifacts/%d", r.CandidateRunID, r.ReportArtifactID) ||
		r.DraftPRURL != fmt.Sprintf("https://github.com/kevinmartin/sofa-disposable/pull/%d", r.DraftPR) ||
		r.DraftHeadRef != "sofa-e2e-result/"+r.SuiteID || r.DraftBaseRef != "main" || r.DraftState != "open" || !r.DraftIsDraft || r.OwnedResourceState != "retained_for_replay" {
		return false
	}
	if r.CandidateRunStartedAt.IsZero() || r.CandidateRunUpdatedAt.IsZero() || !r.CandidateRunUpdatedAt.After(r.CandidateRunStartedAt) {
		return false
	}
	duration := r.CandidateRunUpdatedAt.Sub(r.CandidateRunStartedAt)
	if duration > 6*time.Hour || duration.Milliseconds() != r.CandidateDurationMS || r.CandidateDurationMS < 1 {
		return false
	}
	digest := sha256.Sum256([]byte(r.CandidateSHA + ":" + r.PRBaseSHA + ":" + r.DisposableBaseSHA))
	if r.SuiteID != fmt.Sprintf("p%d-%x", r.SofaPR, digest[:12]) || len(r.Denials) != 2 {
		return false
	}
	for i, kind := range []string{"non-ready", "completed-redelivery"} {
		d := r.Denials[i]
		digest := sha256.Sum256([]byte(r.SuiteID + ":denied:" + kind))
		decision := map[string]string{"non-ready": "admission-denied", "completed-redelivery": "already-completed"}[kind]
		if d.Kind != kind || d.SuiteID != fmt.Sprintf("p%d-%x", r.SofaPR, digest[:12]) || d.Decision != decision || d.ArtifactID < 1 || d.ArtifactID == r.ReportArtifactID ||
			d.ArtifactURL != fmt.Sprintf("https://github.com/kevinmartin/sofa-disposable/actions/runs/%d/artifacts/%d", r.CandidateRunID, d.ArtifactID) {
			return false
		}
		if i > 0 && d.ArtifactID == r.Denials[0].ArtifactID {
			return false
		}
	}
	return true
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
		if err := decoder.Decode(&r); err != nil || !validObserved(r) {
			return nil, errors.New("trusted observer result invalid")
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
		status := gatestatus.Result{PRNumber: r.SofaPR, HeadSHA: r.CandidateSHA, BaseSHA: r.PRBaseSHA, State: gatestatus.Success, RunURL: r.CandidateRunURL, Description: fmt.Sprintf("Hosted E2E %s success", r.SuiteID)}
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
