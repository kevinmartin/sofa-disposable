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
)

// completedResult is produced by the trusted Project-completion job in this
// workflow run. Candidate artifacts never enter this job directly.
type completedResult struct {
	SchemaVersion      int    `json:"schema_version"`
	SofaPR             int    `json:"sofa_pr"`
	CandidateSHA       string `json:"candidate_sha"`
	PRBaseSHA          string `json:"pr_base_sha"`
	DisposableBaseSHA  string `json:"disposable_base_sha"`
	SuiteID            string `json:"suite_id"`
	CandidateDigest    string `json:"candidate_digest"`
	ProducerRunID      int64  `json:"producer_run_id"`
	CandidateRunID     int64  `json:"candidate_run_id"`
	DraftPR            int    `json:"draft_pr"`
	DraftHeadSHA       string `json:"draft_head_sha"`
	DraftHeadRef       string `json:"draft_head_ref"`
	DraftState         string `json:"draft_state"`
	DraftIsDraft       bool   `json:"draft_is_draft"`
	TestIssue          int    `json:"test_issue"`
	ProjectItem        string `json:"project_item"`
	TestItemState      string `json:"test_item_state"`
	OwnedResourceState string `json:"owned_resource_cleanup_state"`
}

func (r completedResult) options() (options, error) {
	o := options{SofaPR: r.SofaPR, CandidateSHA: r.CandidateSHA, PRBaseSHA: r.PRBaseSHA,
		DisposableBaseSHA: r.DisposableBaseSHA, ResultSHA: r.DraftHeadSHA,
		CandidateDigest: r.CandidateDigest, DraftPR: r.DraftPR, Apply: true, AllowActive: true}
	digest := sha256.Sum256([]byte(r.CandidateSHA + ":" + r.PRBaseSHA + ":" + r.DisposableBaseSHA))
	if r.SchemaVersion != 5 || r.SofaPR < 1 || r.DraftPR < 1 || r.ProducerRunID < 1 || r.CandidateRunID <= r.ProducerRunID ||
		!sha40.MatchString(r.CandidateSHA) || !sha40.MatchString(r.PRBaseSHA) || !sha40.MatchString(r.DisposableBaseSHA) ||
		!sha40.MatchString(r.DraftHeadSHA) || !sha64.MatchString(r.CandidateDigest) ||
		r.SuiteID != fmt.Sprintf("p%d-%x", r.SofaPR, digest[:12]) ||
		r.DraftHeadRef != o.result() || r.DraftState != "open" || !r.DraftIsDraft ||
		r.TestIssue < 1 || r.ProjectItem == "" || r.TestItemState != "closed_archived" ||
		r.OwnedResourceState != "retained_for_replay" {
		return options{}, errors.New("completed suite cleanup proof invalid")
	}
	return o, nil
}

func parseCompleted(data []byte) ([]completedResult, error) {
	if len(data) > 100<<10 {
		return nil, errors.New("completed report too large")
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte{'\n'})
	if len(lines) > 100 {
		return nil, errors.New("too many completed suites")
	}
	results := make([]completedResult, 0, len(lines))
	seen := map[string]bool{}
	for _, line := range lines {
		var r completedResult
		dec := json.NewDecoder(bytes.NewReader(line))
		if err := dec.Decode(&r); err != nil || dec.Decode(new(any)) != io.EOF {
			return nil, errors.New("completed report invalid")
		}
		if _, err := r.options(); err != nil || seen[r.SuiteID] {
			return nil, errors.New("completed suite identity invalid or repeated")
		}
		seen[r.SuiteID] = true
		results = append(results, r)
	}
	return results, nil
}

type candidateRun struct {
	ID         int64  `json:"id"`
	HeadSHA    string `json:"head_sha"`
	HeadBranch string `json:"head_branch"`
	Event      string `json:"event"`
	Path       string `json:"path"`
	RunAttempt int    `json:"run_attempt"`
	Status     string `json:"status"`
	Conclusion string `json:"conclusion"`
}

func (a api) callerFromRuns(ctx context.Context, r completedResult, o options) (string, error) {
	for _, id := range []int64{r.ProducerRunID, r.CandidateRunID} {
		var run candidateRun
		if err := a.get(ctx, fmt.Sprintf("/repos/%s/actions/runs/%d", consumerRepo, id), &run); err != nil {
			return "", err
		}
		if run.ID != id || !sha40.MatchString(run.HeadSHA) || run.HeadBranch != o.caller() || run.Event != "workflow_dispatch" || run.Path != workflowPath || run.RunAttempt != 1 || run.Status != "completed" {
			return "", errors.New("candidate run does not belong to exact completed suite")
		}
		if id == r.ProducerRunID && run.Conclusion != "failure" || id == r.CandidateRunID && run.Conclusion != "success" {
			return "", errors.New("candidate run outcome invalid for cleanup")
		}
		if id == r.ProducerRunID {
			o.CallerSHA = run.HeadSHA
		}
		if id == r.CandidateRunID && run.HeadSHA != o.CallerSHA {
			return "", errors.New("candidate runs used different caller heads")
		}
	}
	return o.CallerSHA, nil
}

func (a api) verifyCleaned(ctx context.Context, o options) error {
	pr, err := a.pull(ctx, consumerRepo, o.DraftPR)
	if err != nil || pr.State != "closed" || !ownedDraft(o, pr, false) {
		return errors.New("suite draft was not exactly closed")
	}
	for _, branch := range []string{o.caller(), o.result()} {
		_, exists, err := a.optionalRef(ctx, branch)
		if err != nil || exists {
			return errors.New("suite ref remains after cleanup")
		}
	}
	return nil
}

func cleanCompleted(ctx context.Context, a api, data []byte, deleteRef refDeleter) ([]byte, error) {
	results, err := parseCompleted(data)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	for _, r := range results {
		o, _ := r.options()
		o.CallerSHA, err = a.callerFromRuns(ctx, r, o)
		if err != nil {
			return nil, err
		}
		if err = cleanup(ctx, a, o, deleteRef); err != nil {
			return nil, err
		}
		if err = a.verifyCleaned(ctx, o); err != nil {
			return nil, err
		}
		var record map[string]json.RawMessage
		// Preserve the full observer report, including its scenario and artifact links.
		for _, original := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
			var identity struct {
				SuiteID string `json:"suite_id"`
			}
			if json.Unmarshal(original, &identity) == nil && identity.SuiteID == r.SuiteID {
				if err := json.Unmarshal(original, &record); err != nil {
					return nil, err
				}
				break
			}
		}
		if record == nil {
			return nil, errors.New("completed report missing after cleanup")
		}
		for key, value := range map[string]string{
			"owned_resource_cleanup_state": "cleaned",
			"draft_state":                  "closed",
			"caller_head_sha":              o.CallerSHA,
			"caller_ref_state":             "absent",
			"result_ref_state":             "absent",
		} {
			encoded, _ := json.Marshal(value)
			record[key] = encoded
		}
		encoded, err := json.Marshal(record)
		if err != nil {
			return nil, err
		}
		out.Write(encoded)
		out.WriteByte('\n')
	}
	return out.Bytes(), nil
}

func runSuccess(ctx context.Context, a api, path string) error {
	if os.Getenv("GITHUB_REPOSITORY") != consumerRepo || os.Getenv("GITHUB_REF") != "refs/heads/main" ||
		os.Getenv("GH_TOKEN") == "" || os.Getenv("SOFA_PUBLISH_TOKEN") == "" ||
		path != "gate-results-complete.jsonl" {
		return errors.New("trusted successful-cleanup boundary unavailable")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	cleaned, err := cleanCompleted(ctx, a, data, deleteWithLease(os.Getenv("SOFA_PUBLISH_TOKEN")))
	if err != nil {
		return err
	}
	return os.WriteFile("gate-results-cleaned.jsonl", cleaned, 0600)
}
