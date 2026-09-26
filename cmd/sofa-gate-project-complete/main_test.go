package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/kevinmartin/sofa-disposable/internal/fixturelifecycle"
)

type fakeGate struct {
	verified, completed int
	resource            fixturelifecycle.Resource
	completeErr         error
}

func (g *fakeGate) Verify(_ context.Context, _ fixturelifecycle.Suite) (fixturelifecycle.Resource, error) {
	g.verified++
	return g.resource, nil
}

func (g *fakeGate) Complete(_ context.Context, _ fixturelifecycle.Suite) (fixturelifecycle.Resource, error) {
	g.completed++
	return g.resource, g.completeErr
}

func TestProjectCompletionRequiresExactOwnedResource(t *testing.T) {
	r := observed{SchemaVersion: 4, SofaPR: 2, CandidateSHA: strings.Repeat("a", 40), PRBaseSHA: strings.Repeat("b", 40), DisposableBaseSHA: strings.Repeat("c", 40)}
	digest := sha256.Sum256([]byte(r.CandidateSHA + ":" + r.PRBaseSHA + ":" + r.DisposableBaseSHA))
	r.SuiteID = fmt.Sprintf("p%d-%x", r.SofaPR, digest[:12])
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	gate := &fakeGate{resource: fixturelifecycle.Resource{IssueNumber: 62, IssueURL: "https://github.com/kevinmartin/sofa-disposable/issues/62", ProjectItem: "PVTI_62", Closed: true, Archived: true}}
	out, err := complete(context.Background(), data, gate)
	if err != nil || gate.verified != 1 || gate.completed != 1 {
		t.Fatalf("exact owned completion failed: verified=%d completed=%d err=%v", gate.verified, gate.completed, err)
	}
	var result struct {
		TestIssue     int    `json:"test_issue"`
		TestIssueURL  string `json:"test_issue_url"`
		ProjectItem   string `json:"project_item"`
		TestItemState string `json:"test_item_state"`
	}
	if json.Unmarshal(out, &result) != nil || result.TestIssue != 62 || result.ProjectItem != "PVTI_62" || result.TestItemState != "closed_archived" {
		t.Fatalf("completed report lost exact identity: %s", out)
	}
	for _, invalid := range [][]byte{
		[]byte(`{"schema_version":4,"sofa_pr":2,"candidate_sha":"` + r.CandidateSHA + `","pr_base_sha":"` + r.PRBaseSHA + `","disposable_base_sha":"` + r.DisposableBaseSHA + `","suite_id":"p2-ffffffffffffffffffffffff"}`),
		[]byte(strings.TrimSuffix(string(data), "}") + `,"test_item_state":"closed_archived"}`),
	} {
		gate.verified, gate.completed = 0, 0
		if _, err := complete(context.Background(), invalid, gate); err == nil || gate.verified != 0 || gate.completed != 0 {
			t.Fatal("malformed or preclaimed completion caused a Project write")
		}
	}
	gate.resource.Archived = false
	gate.verified, gate.completed = 0, 0
	if _, err := complete(context.Background(), data, gate); err == nil || gate.completed != 1 {
		t.Fatal("unarchived Project item produced a completed report")
	}
}
