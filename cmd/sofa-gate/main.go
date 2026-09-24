// sofa-gate is trusted disposable-default-branch orchestration. Candidate
// code runs only later in a separate read-only workflow without these rights.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/kevinmartin/sofa-disposable/internal/gatestatus"
)

const (
	sofaRepo       = "kevinmartin/sofa"
	disposableRepo = "kevinmartin/sofa-disposable"
	workflowPath   = ".github/workflows/sofa-gate.yml"
	candidatePath  = ".github/workflows/e2e-fake.yml"
)

var shaPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)

type api struct {
	http          *http.Client
	token         string
	workflowToken string
}

type pull struct {
	Number int    `json:"number"`
	State  string `json:"state"`
	Head   struct {
		SHA  string `json:"sha"`
		Repo struct {
			FullName string `json:"full_name"`
		} `json:"repo"`
	} `json:"head"`
	Base struct {
		SHA string `json:"sha"`
	} `json:"base"`
}

type ref struct {
	Object struct {
		SHA string `json:"sha"`
	} `json:"object"`
}

type commit struct {
	SHA  string `json:"sha"`
	Tree struct {
		SHA string `json:"sha"`
	} `json:"tree"`
	Parents []struct {
		SHA string `json:"sha"`
	} `json:"parents"`
}

type content struct {
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
}

type runList struct {
	TotalCount int `json:"total_count"`
	Runs       []struct {
		ID         int64  `json:"id"`
		HeadBranch string `json:"head_branch"`
		Status     string `json:"status"`
		Conclusion string `json:"conclusion"`
	} `json:"workflow_runs"`
}

type apiError struct{ status int }

func (e apiError) Error() string { return fmt.Sprintf("GitHub API returned HTTP %d", e.status) }

func (a api) request(ctx context.Context, method, path, token string, input, output any) error {
	if !strings.HasPrefix(path, "/repos/") || strings.ContainsAny(path, "\r\n#") {
		return errors.New("invalid API path")
	}
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, "https://api.github.com"+path, body)
	if err != nil {
		return err
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	request.Header.Set("User-Agent", "sofa-disposable-gate")
	response, err := a.http.Do(request)
	if err != nil {
		return errors.New("GitHub transport unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return apiError{response.StatusCode}
	}
	if output == nil {
		return nil
	}
	limited := io.LimitReader(response.Body, 4<<20)
	return json.NewDecoder(limited).Decode(output)
}

func (a api) get(ctx context.Context, path string, output any) error {
	return a.request(ctx, http.MethodGet, path, a.token, nil, output)
}

func (a api) post(ctx context.Context, path string, input, output any) error {
	return a.request(ctx, http.MethodPost, path, a.token, input, output)
}

func (a api) postWorkflow(ctx context.Context, path string, input, output any) error {
	if a.workflowToken == "" {
		return errors.New("disposable workflow-authoring credential unavailable")
	}
	return a.request(ctx, http.MethodPost, path, a.workflowToken, input, output)
}

func suiteID(p pull, consumerBase string) string {
	digest := sha256.Sum256([]byte(p.Head.SHA + ":" + p.Base.SHA + ":" + consumerBase))
	return fmt.Sprintf("p%d-%x", p.Number, digest[:12])
}

func branchWorkflow(p pull, consumerBase string) string {
	// GitHub requires a literal reusable-workflow ref. This entire caller is
	// generated from verified fixed metadata; no issue/PR prose enters YAML.
	return fmt.Sprintf(`name: sofa hosted E2E candidate
on:
  workflow_dispatch:
    inputs:
      sofa_pr: {type: string, required: false}
      candidate_sha: {type: string, required: false}
      base_sha: {type: string, required: false}
      source_run_id: {type: string, required: false}
      source_run_attempt: {type: string, required: false}
permissions: {}
jobs:
  candidate:
    permissions:
      contents: read
      actions: read
    uses: kevinmartin/sofa/.github/workflows/e2e-fake.yml@%s
    with:
      suite_id: %s
      scenario: edit
      candidate_sha: %s
      base_sha: %s
      disposable_base_sha: %s
      reconcile_candidate: false
`, p.Head.SHA, suiteID(p, consumerBase), p.Head.SHA, p.Base.SHA, consumerBase)
}

func (a api) checkCandidate(ctx context.Context, p pull) (bool, error) {
	var file content
	path := "/repos/" + sofaRepo + "/contents/" + candidatePath + "?ref=" + p.Head.SHA
	err := a.get(ctx, path, &file)
	if errors.As(err, new(apiError)) {
		var apiErr apiError
		if errors.As(err, &apiErr) && apiErr.status == 404 {
			return false, nil // Existing milestone 01 lacks the test adapter.
		}
	}
	return err == nil, err
}

func (a api) currentPR(ctx context.Context, number int) (pull, error) {
	var p pull
	if err := a.get(ctx, fmt.Sprintf("/repos/%s/pulls/%d", sofaRepo, number), &p); err != nil {
		return p, err
	}
	if p.Number != number || p.State != "open" || p.Head.Repo.FullName != sofaRepo || !shaPattern.MatchString(p.Head.SHA) || !shaPattern.MatchString(p.Base.SHA) {
		return p, errors.New("PR identity is not an open same-repository sofa revision")
	}
	return p, nil
}

func (a api) listPRs(ctx context.Context) ([]pull, error) {
	var prs []pull
	if err := a.get(ctx, "/repos/"+sofaRepo+"/pulls?state=open&per_page=100", &prs); err != nil {
		return nil, err
	}
	if len(prs) == 100 {
		return nil, errors.New("PR discovery exceeded bounded page")
	}
	return prs, nil
}

func (a api) branch(ctx context.Context, name string) (ref, bool, error) {
	var r ref
	err := a.get(ctx, "/repos/"+disposableRepo+"/git/ref/heads/"+name, &r)
	var apiErr apiError
	if errors.As(err, &apiErr) && apiErr.status == 404 {
		return r, false, nil
	}
	return r, err == nil, err
}

func (a api) ensureBranch(ctx context.Context, p pull) (string, error) {
	mainRef, ok, err := a.branch(ctx, "main")
	if err != nil || !ok || !shaPattern.MatchString(mainRef.Object.SHA) {
		return "", errors.New("disposable main identity unavailable")
	}
	name := "sofa-e2e/" + suiteID(p, mainRef.Object.SHA)
	want := branchWorkflow(p, mainRef.Object.SHA)
	if existing, exists, err := a.branch(ctx, name); err != nil {
		return "", err
	} else if exists {
		if !shaPattern.MatchString(existing.Object.SHA) {
			return "", errors.New("owned branch SHA invalid")
		}
		var file content
		path := "/repos/" + disposableRepo + "/contents/" + workflowPath + "?ref=" + url.QueryEscape(name)
		if err := a.get(ctx, path, &file); err != nil || file.Encoding != "base64" {
			return "", errors.New("owned branch workflow unavailable")
		}
		actual, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(file.Content, "\n", ""))
		if err != nil || string(actual) != want {
			return "", errors.New("owned branch workflow differs from exact suite")
		}
		return name, nil
	}
	var base commit
	if err := a.get(ctx, "/repos/"+disposableRepo+"/git/commits/"+mainRef.Object.SHA, &base); err != nil || !shaPattern.MatchString(base.Tree.SHA) {
		return "", errors.New("disposable base tree unavailable")
	}
	var tree struct {
		SHA string `json:"sha"`
	}
	if err := a.postWorkflow(ctx, "/repos/"+disposableRepo+"/git/trees", map[string]any{
		"base_tree": base.Tree.SHA,
		"tree":      []map[string]any{{"path": workflowPath, "mode": "100644", "type": "blob", "content": want}},
	}, &tree); err != nil {
		return "", fmt.Errorf("cannot create suite workflow tree: %w", err)
	} else if !shaPattern.MatchString(tree.SHA) {
		return "", errors.New("invalid suite workflow tree")
	}
	var made commit
	if err := a.postWorkflow(ctx, "/repos/"+disposableRepo+"/git/commits", map[string]any{
		"message": "Test sofa PR at exact candidate and base revisions",
		"tree":    tree.SHA,
		"parents": []string{mainRef.Object.SHA},
	}, &made); err != nil {
		return "", fmt.Errorf("cannot create suite workflow commit: %w", err)
	} else if !shaPattern.MatchString(made.SHA) {
		return "", errors.New("invalid suite workflow commit")
	}
	if err := a.postWorkflow(ctx, "/repos/"+disposableRepo+"/git/refs", map[string]any{"ref": "refs/heads/" + name, "sha": made.SHA}, nil); err != nil {
		return "", fmt.Errorf("cannot create suite workflow ref: %w", err)
	}
	return name, nil
}

func (a api) dispatchOnce(ctx context.Context, p pull, branch string) error {
	var runs runList
	path := "/repos/" + disposableRepo + "/actions/workflows/sofa-gate.yml/runs?event=workflow_dispatch&branch=" + url.QueryEscape(branch) + "&per_page=8"
	if err := a.get(ctx, path, &runs); err != nil {
		return err
	}
	if runs.TotalCount > 0 {
		fmt.Printf("suite %s already has %d hosted run(s)\n", strings.TrimPrefix(branch, "sofa-e2e/"), runs.TotalCount)
		return nil
	}
	// Re-read after branch creation; changed base/head cannot dispatch the old suite.
	current, err := a.currentPR(ctx, p.Number)
	if err != nil || current.Head.SHA != p.Head.SHA || current.Base.SHA != p.Base.SHA {
		return errors.New("sofa PR changed before dispatch")
	}
	appID, appKey := os.Getenv("SOFA_GATE_APP_ID"), os.Getenv("SOFA_GATE_APP_PRIVATE_KEY")
	if (appID == "") != (appKey == "") {
		return errors.New("incomplete sofa gate App credential")
	}
	if appID != "" {
		writer := gatestatus.Writer{Client: a.http, AppID: appID, PrivateKeyPEM: appKey}
		if err := writer.Publish(ctx, gatestatus.Result{
			PRNumber: p.Number, HeadSHA: p.Head.SHA, BaseSHA: p.Base.SHA,
			State:       gatestatus.Pending,
			RunURL:      fmt.Sprintf("https://github.com/%s/actions/runs/%s", disposableRepo, os.Getenv("GITHUB_RUN_ID")),
			Description: "Hosted fake ACP E2E queued for exact revision",
		}); err != nil {
			return fmt.Errorf("mark exact sofa revision pending: %w", err)
		}
	}
	err = a.post(ctx, "/repos/"+disposableRepo+"/actions/workflows/sofa-gate.yml/dispatches", map[string]any{
		"ref":    branch,
		"inputs": map[string]string{"sofa_pr": strconv.Itoa(p.Number), "candidate_sha": p.Head.SHA, "base_sha": p.Base.SHA},
	}, nil)
	if err == nil {
		fmt.Printf("dispatched suite %s on %s\n", strings.TrimPrefix(branch, "sofa-e2e/"), branch)
	}
	return err
}

func run(ctx context.Context, a api) error {
	manual := os.Getenv("SOFA_GATE_PR")
	head := os.Getenv("SOFA_GATE_HEAD")
	base := os.Getenv("SOFA_GATE_BASE")
	if (head == "") != (base == "") || (manual == "" && head != "") || (head != "" && (!shaPattern.MatchString(head) || !shaPattern.MatchString(base))) {
		return errors.New("dispatch inputs are incomplete or invalid")
	}
	var prs []pull
	if manual != "" {
		number, err := strconv.Atoi(manual)
		if err != nil || number < 1 {
			return errors.New("invalid sofa PR number")
		}
		p, err := a.currentPR(ctx, number)
		if err != nil {
			return err
		}
		if head != "" && (p.Head.SHA != head || p.Base.SHA != base) {
			return errors.New("stale source event revision")
		}
		prs = []pull{p}
	} else {
		var err error
		prs, err = a.listPRs(ctx)
		if err != nil {
			return err
		}
	}
	for _, listed := range prs {
		p, err := a.currentPR(ctx, listed.Number)
		if err != nil {
			return err
		}
		if p.Head.SHA != listed.Head.SHA || p.Base.SHA != listed.Base.SHA {
			return errors.New("PR changed during discovery")
		}
		ready, err := a.checkCandidate(ctx, p)
		if err != nil {
			return err
		}
		if !ready {
			fmt.Printf("PR %d has no candidate test workflow; awaiting rollout\n", p.Number)
			continue
		}
		branch, err := a.ensureBranch(ctx, p)
		if err != nil {
			return err
		}
		if err := a.dispatchOnce(ctx, p, branch); err != nil {
			return err
		}
	}
	return nil
}

func main() {
	token := os.Getenv("GH_TOKEN")
	if token == "" || os.Getenv("GITHUB_REPOSITORY") != disposableRepo || os.Getenv("GITHUB_REF") != "refs/heads/main" {
		fmt.Fprintln(os.Stderr, "trusted coordinator identity unavailable")
		os.Exit(1)
	}
	a := api{token: token, workflowToken: os.Getenv("SOFA_DISPOSABLE_WORKFLOW_TOKEN"), http: &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("redirect refused")
	}}}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	if err := run(ctx, a); err != nil {
		fmt.Fprintln(os.Stderr, "hosted gate coordinator:", err)
		os.Exit(1)
	}
}
