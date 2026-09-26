package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"reflect"
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
		SchemaVersion: 5, SofaPR: 2, CandidateSHA: strings.Repeat("a", 40), PRBaseSHA: strings.Repeat("b", 40), DisposableBaseSHA: strings.Repeat("c", 40), CandidateDigest: strings.Repeat("e", 64),
		ProducerRunID: 41, ProducerRunURL: "https://github.com/kevinmartin/sofa-disposable/actions/runs/41", ProducerDurationMS: 90000,
		RetainedArtifactID: 75, ConflictArtifactID: 76, ConflictArtifactURL: "https://github.com/kevinmartin/sofa-disposable/actions/runs/41/artifacts/76", ConflictBranchHead: strings.Repeat("b", 40),
		TestIssue: 62, TestIssueURL: "https://github.com/kevinmartin/sofa-disposable/issues/62", ProjectItem: "PVTI_62", TestItemState: "closed_archived",
		CandidateRunID: 42, CandidateRunAttempt: 1, CandidateRunURL: "https://github.com/kevinmartin/sofa-disposable/actions/runs/42",
		CandidateRunStartedAt: started, CandidateRunUpdatedAt: started.Add(90 * time.Second), CandidateDurationMS: 90000,
		ReportArtifactID: 77, ReportArtifactURL: "https://github.com/kevinmartin/sofa-disposable/actions/runs/42/artifacts/77",
		DraftPR: 7, DraftPRURL: "https://github.com/kevinmartin/sofa-disposable/pull/7", DraftHeadSHA: strings.Repeat("f", 40),
		DraftBaseRef: "main", DraftState: "closed", DraftIsDraft: true, CallerHeadSHA: strings.Repeat("d", 40), CallerRefState: "absent", ResultRefState: "absent", OwnedResourceState: "cleaned",
	}
	suiteDigest := sha256.Sum256([]byte(r.CandidateSHA + ":" + r.PRBaseSHA + ":" + r.DisposableBaseSHA))
	r.SuiteID = fmt.Sprintf("p%d-%x", r.SofaPR, suiteDigest[:12])
	r.DraftHeadRef = "sofa-e2e-result/" + r.SuiteID
	r.Scenarios = []scenarioEvidence{
		{ID: "edit-fault", RunID: 41, Job: "candidate / execute", Command: "/toolkit/sofa execute", JobDurationMS: 12000, FakePromptRequests: 1},
		{ID: "branch-conflict", RunID: 41, Job: "candidate / publish", Command: "go test -count=1 -run '^TestHostedArtifactPublicationConflict$' ./cmd/sofa", JobDurationMS: 12000},
		{ID: "non-ready", RunID: 41, Job: "deny-non-ready / assert-denied", Command: "bin/e2e-fixture deny", JobDurationMS: 12000},
		{ID: "completed-redelivery", RunID: 41, Job: "deny-completed-redelivery / assert-denied", Command: "bin/e2e-fixture deny", JobDurationMS: 12000},
		{ID: "recovery-publication", RunID: 42, Job: "recover / publish", Command: "go test -count=1 -run '^TestHostedArtifactPublication$' ./cmd/sofa", JobDurationMS: 12000},
	}
	for i, kind := range []string{"non-ready", "completed-redelivery"} {
		digest := sha256.Sum256([]byte(r.SuiteID + ":denied:" + kind))
		decision := map[string]string{"non-ready": "admission-denied", "completed-redelivery": "already-completed"}[kind]
		r.Denials = append(r.Denials, struct {
			Kind        string `json:"kind"`
			SuiteID     string `json:"suite_id"`
			Decision    string `json:"decision"`
			ArtifactID  int64  `json:"artifact_id"`
			ArtifactURL string `json:"artifact_url"`
		}{kind, fmt.Sprintf("p%d-%x", r.SofaPR, digest[:12]), decision, int64(78 + i), fmt.Sprintf("https://github.com/kevinmartin/sofa-disposable/actions/runs/41/artifacts/%d", 78+i)})
	}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if results, err := parseResults(append(data, '\n')); err != nil || len(results) != 1 || !reflect.DeepEqual(results[0], r) {
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
		{"missing conflict evidence", func(r *observed) { r.ConflictArtifactID = 0 }},
		{"wrong conflict URL", func(r *observed) { r.ConflictArtifactURL += "/forged" }},
		{"wrong producer", func(r *observed) { r.ProducerRunID = r.CandidateRunID }},
		{"wrong branch head", func(r *observed) { r.ConflictBranchHead = strings.Repeat("f", 40) }},
		{"missing Project item", func(r *observed) { r.ProjectItem = "" }},
		{"Project item not completed", func(r *observed) { r.TestItemState = "Ready" }},
		{"wrong test issue URL", func(r *observed) { r.TestIssueURL += "/forged" }},
		{"wrong run URL", func(r *observed) { r.CandidateRunURL += "/other" }},
		{"wrong draft branch", func(r *observed) { r.DraftHeadRef = "other" }},
		{"missing denial", func(r *observed) { r.Denials = r.Denials[:1] }},
		{"missing scenario", func(r *observed) { r.Scenarios = r.Scenarios[:4] }},
		{"wrong scenario command", func(r *observed) { r.Scenarios[0].Command = "untrusted" }},
		{"missing job duration", func(r *observed) { r.Scenarios[1].JobDurationMS = 0 }},
		{"wrong denial decision", func(r *observed) { r.Denials[0].Decision = "allowed" }},
		{"duplicate denial artifact", func(r *observed) {
			r.Denials[1].ArtifactID = r.Denials[0].ArtifactID
			r.Denials[1].ArtifactURL = r.Denials[0].ArtifactURL
		}},
		{"cleanup missing", func(r *observed) { r.OwnedResourceState = "retained_for_replay" }},
		{"caller ref not absent", func(r *observed) { r.CallerRefState = "present" }},
		{"result ref not absent", func(r *observed) { r.ResultRefState = "present" }},
		{"draft still open", func(r *observed) { r.DraftState = "open" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := r
			mutated.Denials = append(mutated.Denials[:0:0], r.Denials...)
			mutated.Scenarios = append(mutated.Scenarios[:0:0], r.Scenarios...)
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
