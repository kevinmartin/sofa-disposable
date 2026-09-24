package main

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestWorkflowAuthoringUsesOnlyScopedCredential(t *testing.T) {
	var requests int
	a := api{token: "default-token", workflowToken: "workflow-token", http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests++
		if r.URL.Path != "/repos/"+disposableRepo+"/git/trees" || r.Header.Get("Authorization") != "Bearer workflow-token" {
			t.Fatalf("workflow authoring used the wrong path or credential")
		}
		return &http.Response{StatusCode: http.StatusCreated, Body: io.NopCloser(strings.NewReader(`{"sha":"` + strings.Repeat("a", 40) + `"}`)), Header: make(http.Header)}, nil
	})}}
	var tree struct {
		SHA string `json:"sha"`
	}
	if err := a.postWorkflow(context.Background(), "/repos/"+disposableRepo+"/git/trees", map[string]string{"base_tree": "test"}, &tree); err != nil || tree.SHA != strings.Repeat("a", 40) || requests != 1 {
		t.Fatalf("expected one scoped workflow authoring request: tree=%q requests=%d err=%v", tree.SHA, requests, err)
	}
	a.workflowToken = ""
	if err := a.postWorkflow(context.Background(), "/repos/"+disposableRepo+"/git/trees", nil, nil); err == nil || !strings.Contains(err.Error(), "credential unavailable") || requests != 1 {
		t.Fatalf("missing scoped credential must fail before a request: requests=%d err=%v", requests, err)
	}
}

func testPull(head, base string) pull {
	var p pull
	p.Number = 2
	p.State = "open"
	p.Head.SHA = head
	p.Head.Repo.FullName = sofaRepo
	p.Base.SHA = base
	return p
}

func TestSuiteBranchBindsFullCandidateAndBaseWithoutSecrets(t *testing.T) {
	head, base := strings.Repeat("a", 40), strings.Repeat("b", 40)
	p := testPull(head, base)
	id := suiteID(p)
	if len(id) > 40 || id != suiteID(p) || id == suiteID(testPull(head, strings.Repeat("c", 40))) {
		t.Fatalf("suite ID is not stable and base-bound: %q", id)
	}
	workflow := branchWorkflow(p, strings.Repeat("d", 40))
	for _, required := range []string{
		"uses: kevinmartin/sofa/.github/workflows/e2e-fake.yml@" + head,
		"suite_id: " + id,
		"candidate_sha: " + head,
		"base_sha: " + base,
		"disposable_base_sha: " + strings.Repeat("d", 40),
		"contents: read", "actions: read", "reconcile_candidate: false",
	} {
		if !strings.Contains(workflow, required) {
			t.Fatalf("generated workflow lacks %q", required)
		}
	}
	for _, forbidden := range []string{"secrets:", "SOFA_PROJECTS_TOKEN", "SOFA_PUBLISH_TOKEN", "SOFA_GATE_APP_PRIVATE_KEY", "copilot-requests: write", "contents: write"} {
		if strings.Contains(workflow, forbidden) {
			t.Fatalf("generated candidate workflow contains %q", forbidden)
		}
	}
}
