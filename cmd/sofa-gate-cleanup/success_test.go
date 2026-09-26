package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
)

func completedFixture(o options) completedResult {
	return completedResult{
		SchemaVersion: 5, SofaPR: o.SofaPR, CandidateSHA: o.CandidateSHA,
		PRBaseSHA: o.PRBaseSHA, DisposableBaseSHA: o.DisposableBaseSHA,
		SuiteID: o.suite(), CandidateDigest: o.CandidateDigest,
		ProducerRunID: 41, CandidateRunID: 42, DraftPR: o.DraftPR,
		DraftHeadSHA: o.ResultSHA, DraftHeadRef: o.result(), DraftState: "open", DraftIsDraft: true,
		TestIssue: 62, ProjectItem: "PVTI_62", TestItemState: "closed_archived", OwnedResourceState: "retained_for_replay",
	}
}

func TestCleanCompletedClosesOnlyOwnedResourcesAndReplays(t *testing.T) {
	o := testOptions()
	r := completedFixture(o)
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := testAPI(t, o, true, false, false, false)
	underlying := a.client.Transport
	callerExists, resultExists := true, true
	runAttempt := 1
	a.client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		for _, ref := range []struct {
			name   string
			exists bool
		}{{o.caller(), callerExists}, {o.result(), resultExists}} {
			if req.Method == http.MethodGet && req.URL.Path == "/repos/"+consumerRepo+"/git/ref/heads/"+ref.name && !ref.exists {
				return &http.Response{StatusCode: 404, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
			}
		}
		for _, id := range []int64{41, 42} {
			if req.Method == http.MethodGet && req.URL.Path == fmt.Sprintf("/repos/%s/actions/runs/%d", consumerRepo, id) {
				conclusion := "failure"
				if id == 42 {
					conclusion = "success"
				}
				body, _ := json.Marshal(candidateRun{ID: id, HeadSHA: o.CallerSHA, HeadBranch: o.caller(), Event: "workflow_dispatch", Path: workflowPath, RunAttempt: runAttempt, Status: "completed", Conclusion: conclusion})
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}, nil
			}
		}
		return underlying.RoundTrip(req)
	})}
	var deleted []string
	deleteRef := func(_ context.Context, branch, sha string) error {
		deleted = append(deleted, branch+":"+sha)
		switch branch {
		case o.caller():
			callerExists = false
		case o.result():
			resultExists = false
		default:
			t.Fatalf("unexpected ref deletion %s", branch)
		}
		return nil
	}
	cleaned, err := cleanCompleted(context.Background(), a, data, deleteRef)
	if err != nil || len(deleted) != 2 || callerExists || resultExists {
		t.Fatalf("exact cleanup failed: deleted=%v err=%v", deleted, err)
	}
	var receipt struct {
		DraftState     string `json:"draft_state"`
		State          string `json:"owned_resource_cleanup_state"`
		CallerHeadSHA  string `json:"caller_head_sha"`
		CallerRefState string `json:"caller_ref_state"`
		ResultRefState string `json:"result_ref_state"`
	}
	if err := json.Unmarshal(cleaned, &receipt); err != nil || receipt.DraftState != "closed" || receipt.State != "cleaned" || receipt.CallerHeadSHA != o.CallerSHA || receipt.CallerRefState != "absent" || receipt.ResultRefState != "absent" {
		t.Fatalf("invalid cleanup receipt: %s, %v", cleaned, err)
	}
	deleted = nil
	if _, err := cleanCompleted(context.Background(), a, data, deleteRef); err != nil || len(deleted) != 0 {
		t.Fatalf("exact replay was not idempotent: deleted=%v err=%v", deleted, err)
	}
	runAttempt = 2
	if _, err := cleanCompleted(context.Background(), a, data, deleteRef); err == nil {
		t.Fatal("rerun with changed candidate attempt was accepted")
	}
}

func TestCompletedProofRejectsClosedDraftBeforeWrites(t *testing.T) {
	o := testOptions()
	r := completedFixture(o)
	r.DraftState = "closed"
	data, _ := json.Marshal(r)
	if _, err := parseCompleted(data); err == nil {
		t.Fatal("closed draft accepted as fresh Project-completion proof")
	}
}
