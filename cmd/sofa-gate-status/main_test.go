package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/kevinmartin/sofa-disposable/internal/gatestatus"
)

func TestTrustedStatusInputIsBoundedAndFailClosed(t *testing.T) {
	if results, err := parseResults(nil); err != nil || len(results) != 0 {
		t.Fatal("empty observer result should publish no status", err)
	}
	if err := run(context.Background(), nil, gatestatus.Writer{}); err != nil {
		t.Fatal("pending suite should not require an App credential", err)
	}
	started := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	r := observed{
		SchemaVersion: 2, SofaPR: 2, CandidateSHA: strings.Repeat("a", 40), PRBaseSHA: strings.Repeat("b", 40), DisposableBaseSHA: strings.Repeat("c", 40), CandidateDigest: strings.Repeat("e", 64),
		CandidateRunID: 42, CandidateRunAttempt: 1, CandidateRunURL: "https://github.com/kevinmartin/sofa-disposable/actions/runs/42",
		CandidateRunStartedAt: started, CandidateRunUpdatedAt: started.Add(90 * time.Second), CandidateDurationMS: 90000,
		ReportArtifactID: 77, ReportArtifactURL: "https://github.com/kevinmartin/sofa-disposable/actions/runs/42/artifacts/77",
		DraftPR: 7, DraftPRURL: "https://github.com/kevinmartin/sofa-disposable/pull/7", DraftHeadSHA: strings.Repeat("f", 40),
		DraftBaseRef: "main", DraftState: "open", DraftIsDraft: true, OwnedResourceState: "retained_for_replay",
	}
	suiteDigest := sha256.Sum256([]byte(r.CandidateSHA + ":" + r.PRBaseSHA + ":" + r.DisposableBaseSHA))
	r.SuiteID = fmt.Sprintf("p%d-%x", r.SofaPR, suiteDigest[:12])
	r.DraftHeadRef = "sofa-e2e-result/" + r.SuiteID
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if results, err := parseResults(append(data, '\n')); err != nil || len(results) != 1 || results[0] != r {
		t.Fatalf("valid trusted result rejected: %+v, %v", results, err)
	}
	for _, invalid := range [][]byte{
		[]byte(`{"schema_version":1}`),
		[]byte(strings.Replace(string(data), r.SuiteID, "p2-"+strings.Repeat("d", 24), 1)),
		[]byte(strings.Replace(string(data), "https://github.com/kevinmartin/sofa-disposable/pull/7", "https://example.com/pull/7", 1)),
		[]byte(strings.Replace(string(data), "https://github.com/kevinmartin/sofa-disposable/actions/runs/42", "https://example.com/actions/runs/42", 1)),
		[]byte(strings.Replace(string(data), "https://github.com/kevinmartin/sofa-disposable/actions/runs/42/artifacts/77", "https://example.com/actions/runs/42/artifacts/77", 1)),
		[]byte(strings.Replace(string(data), started.Format(time.RFC3339), "not-a-timestamp", 1)),
		append(append([]byte{}, data...), []byte(`{"other":true}`)...),
		[]byte(strings.Repeat("x", 100<<10+1)),
	} {
		if _, err := parseResults(invalid); err == nil {
			t.Fatal("accepted invalid trusted status input")
		}
	}
	if err := run(context.Background(), append(data, '\n'), gatestatus.Writer{}); err == nil {
		t.Fatal("validated result gained a green status without App credential")
	}
	for _, tc := range []struct {
		name string
		edit func(*observed)
	}{
		{"duration mismatch", func(r *observed) { r.CandidateDurationMS++ }},
		{"negative duration", func(r *observed) { r.CandidateRunUpdatedAt = r.CandidateRunStartedAt.Add(-time.Second) }},
		{"duration over bound", func(r *observed) {
			r.CandidateRunUpdatedAt = r.CandidateRunStartedAt.Add(6*time.Hour + time.Millisecond)
			r.CandidateDurationMS = int64((6*time.Hour + time.Millisecond) / time.Millisecond)
		}},
		{"wrong artifact ID", func(r *observed) { r.ReportArtifactID = 78 }},
		{"wrong run URL", func(r *observed) { r.CandidateRunURL += "/other" }},
		{"wrong draft branch", func(r *observed) { r.DraftHeadRef = "other" }},
		{"cleanup falsely claimed", func(r *observed) { r.OwnedResourceState = "cleaned" }},
		{"draft no longer open", func(r *observed) { r.DraftState = "closed" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := r
			tc.edit(&mutated)
			input, err := json.Marshal(mutated)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := parseResults(input); err == nil {
				t.Fatal("accepted invalid trusted report")
			}
		})
	}
}
