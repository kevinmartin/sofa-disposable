package main

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
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

func TestEnsureBranchUsesScopedCredentialForEveryGitWrite(t *testing.T) {
	base, treeSHA := strings.Repeat("a", 40), strings.Repeat("b", 40)
	createdTree, createdCommit := strings.Repeat("c", 40), strings.Repeat("d", 40)
	p := testPull(strings.Repeat("e", 40), strings.Repeat("f", 40))
	writes := []string{}
	a := api{token: "default-token", workflowToken: "workflow-token", http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		status, body := http.StatusOK, "{}"
		if r.Method == http.MethodGet {
			if r.Header.Get("Authorization") != "Bearer default-token" {
				t.Fatal("metadata read used workflow-authoring credential")
			}
			switch {
			case strings.HasSuffix(r.URL.Path, "/git/ref/heads/main"):
				body = `{"object":{"sha":"` + base + `"}}`
			case strings.Contains(r.URL.Path, "/git/ref/heads/sofa-e2e/"):
				status = http.StatusNotFound
			case strings.HasSuffix(r.URL.Path, "/git/commits/"+base):
				body = `{"sha":"` + base + `","tree":{"sha":"` + treeSHA + `"}}`
			default:
				t.Fatalf("unexpected metadata path: %s", r.URL.Path)
			}
		} else if r.Method == http.MethodPost {
			if r.Header.Get("Authorization") != "Bearer workflow-token" {
				t.Fatal("Git write used general job token")
			}
			writes = append(writes, r.URL.Path)
			switch {
			case strings.HasSuffix(r.URL.Path, "/git/trees"):
				body = `{"sha":"` + createdTree + `"}`
			case strings.HasSuffix(r.URL.Path, "/git/commits"):
				body = `{"sha":"` + createdCommit + `"}`
			case strings.HasSuffix(r.URL.Path, "/git/refs"):
				status = http.StatusCreated
			default:
				t.Fatalf("unexpected write path: %s", r.URL.Path)
			}
		} else {
			t.Fatalf("unexpected method: %s", r.Method)
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}}
	branch, err := a.ensureBranch(context.Background(), p)
	if err != nil || branch != "sofa-e2e/"+suiteID(p, base) || len(writes) != 3 || !strings.HasSuffix(writes[0], "/git/trees") || !strings.HasSuffix(writes[1], "/git/commits") || !strings.HasSuffix(writes[2], "/git/refs") {
		t.Fatalf("unexpected suite writes: branch=%q writes=%v err=%v", branch, writes, err)
	}
}

func TestHostedDispatchRetriesStayWithinOriginalBudget(t *testing.T) {
	branch := "sofa-e2e/p2-test"
	now := time.Date(2026, 9, 25, 1, 0, 0, 0, time.UTC)
	if dispatch, err := shouldDispatch(runList{}, branch, now); err != nil || !dispatch {
		t.Fatalf("new exact suite did not dispatch: %v", err)
	}
	base := workflowRun{ID: 1, HeadBranch: branch, Status: "completed", Conclusion: "failure", CreatedAt: now.Add(-10 * time.Minute)}
	for _, tc := range []struct {
		name     string
		list     runList
		dispatch bool
		err      bool
	}{
		{"failed retry", runList{1, []workflowRun{base}}, true, false},
		{"active", runList{1, []workflowRun{{ID: 1, HeadBranch: branch, Status: "in_progress", CreatedAt: base.CreatedAt}}}, false, false},
		{"passed", runList{1, []workflowRun{{ID: 1, HeadBranch: branch, Status: "completed", Conclusion: "success", CreatedAt: base.CreatedAt}}}, false, false},
		{"expired", runList{1, []workflowRun{{ID: 1, HeadBranch: branch, Status: "completed", Conclusion: "failure", CreatedAt: now.Add(-46 * time.Minute)}}}, false, true},
		{"wrong branch", runList{1, []workflowRun{{ID: 1, HeadBranch: "other", Status: "completed", Conclusion: "failure", CreatedAt: base.CreatedAt}}}, false, true},
		{"truncated", runList{2, []workflowRun{base}}, false, true},
		{"run cap", runList{9, []workflowRun{base}}, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dispatch, err := shouldDispatch(tc.list, branch, now)
			if dispatch != tc.dispatch || (err != nil) != tc.err {
				t.Fatalf("dispatch=%v err=%v, want dispatch=%v error=%v", dispatch, err, tc.dispatch, tc.err)
			}
		})
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
	consumerBase := strings.Repeat("d", 40)
	id := suiteID(p, consumerBase)
	if len(id) > 40 || id != suiteID(p, consumerBase) || id == suiteID(testPull(head, strings.Repeat("c", 40)), consumerBase) || id == suiteID(p, strings.Repeat("e", 40)) {
		t.Fatalf("suite ID is not stable and base-bound: %q", id)
	}
	workflow := branchWorkflow(p, consumerBase)
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
