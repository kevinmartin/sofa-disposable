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

	"github.com/kevinmartin/sofa-disposable/internal/fixturelifecycle"
	"github.com/kevinmartin/sofa-disposable/internal/gatecaller"
	"github.com/kevinmartin/sofa-disposable/internal/gatestatus"
)

const (
	sofaRepo       = "kevinmartin/sofa"
	disposableRepo = "kevinmartin/sofa-disposable"
	workflowPath   = ".github/workflows/sofa-gate.yml"
	candidatePath  = ".github/workflows/e2e-fake.yml"
)

var shaPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
var errRetryBudget = errors.New("hosted suite retry budget exhausted")
var errNotReady = errors.New("sofa candidate test workflow unavailable")
var errSuiteCompleted = errors.New("hosted suite already completed")
var errSuiteItemCompleted = errors.New("hosted suite Project item already completed")

type fixtureGate interface {
	EnsureReady(context.Context, fixturelifecycle.Suite) (fixturelifecycle.Resource, error)
	Verify(context.Context, fixturelifecycle.Suite) (fixturelifecycle.Resource, error)
}

func readyOrCompleted(ctx context.Context, gate fixtureGate, suite fixturelifecycle.Suite) (bool, error) {
	if resource, err := gate.EnsureReady(ctx, suite); err == nil {
		if resource.Closed || resource.Archived || resource.IssueNumber < 1 || resource.ProjectItem == "" {
			return false, errors.New("suite test item is not Ready")
		}
		return true, nil
	} else {
		resource, verifyErr := gate.Verify(ctx, suite)
		if verifyErr == nil && resource.Closed && resource.Archived && resource.IssueNumber > 0 && resource.ProjectItem != "" {
			return false, nil
		}
		return false, err
	}
}

type api struct {
	http          *http.Client
	token         string
	workflowToken string
	status        gateStatus
	fixture       fixtureGate
	projectToken  string
}

type gateStatus interface {
	Latest(context.Context, string) (gatestatus.Snapshot, error)
	Publish(context.Context, gatestatus.Result) error
	DispatchToken(context.Context) (string, error)
}

func (a api) statusWriter() gateStatus {
	if a.status != nil {
		return a.status
	}
	return gatestatus.Writer{Client: a.http, AppID: os.Getenv("SOFA_GATE_APP_ID"), PrivateKeyPEM: os.Getenv("SOFA_GATE_APP_PRIVATE_KEY")}
}

func (a api) fixtureWriter() fixtureGate {
	if a.fixture != nil {
		return a.fixture
	}
	return fixturelifecycle.Client{HTTP: a.http, Token: a.projectToken, IssueToken: a.token}
}

func coordinatorRunURL() string {
	return fmt.Sprintf("https://github.com/%s/actions/runs/%s", disposableRepo, os.Getenv("GITHUB_RUN_ID"))
}

func suiteDescription(suite string, state gatestatus.State) string {
	return fmt.Sprintf("Hosted E2E %s %s", suite, state)
}

func (a api) publishPending(ctx context.Context, p pull, suite, runURL string) error {
	return a.statusWriter().Publish(ctx, gatestatus.Result{
		PRNumber: p.Number, HeadSHA: p.Head.SHA, BaseSHA: p.Base.SHA,
		State: gatestatus.Pending, RunURL: runURL, Description: suiteDescription(suite, gatestatus.Pending),
	})
}

func (a api) publishFailure(ctx context.Context, p pull, description, runURL string) error {
	current, err := a.statusWriter().Latest(ctx, p.Head.SHA)
	if err == nil && current.Found && current.Source && current.State == gatestatus.Failure && current.Description == description {
		return nil
	}
	return a.statusWriter().Publish(ctx, gatestatus.Result{
		PRNumber: p.Number, HeadSHA: p.Head.SHA, BaseSHA: p.Base.SHA,
		State: gatestatus.Failure, RunURL: runURL, Description: description,
	})
}

func (a api) reconcileStatus(ctx context.Context, p pull, suite string) error {
	status, err := a.statusWriter().Latest(ctx, p.Head.SHA)
	if err != nil {
		if publishErr := a.publishPending(ctx, p, suite, coordinatorRunURL()); publishErr != nil {
			return fmt.Errorf("inspect exact sofa gate status (%v) and mark pending: %w", err, publishErr)
		}
		return nil
	}
	if status.Found && status.Source && status.Description == suiteDescription(suite, status.State) &&
		(status.State == gatestatus.Pending || status.State == gatestatus.Success || status.State == gatestatus.Failure) {
		return nil
	}
	return a.publishPending(ctx, p, suite, coordinatorRunURL())
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
	TotalCount int           `json:"total_count"`
	Runs       []workflowRun `json:"workflow_runs"`
}

type suiteJobs struct {
	TotalCount int `json:"total_count"`
	Jobs       []struct {
		Name       string `json:"name"`
		Status     string `json:"status"`
		Conclusion string `json:"conclusion"`
		RunAttempt int    `json:"run_attempt"`
	} `json:"jobs"`
}

type workflowRun struct {
	ID         int64     `json:"id"`
	HeadBranch string    `json:"head_branch"`
	Status     string    `json:"status"`
	Conclusion string    `json:"conclusion"`
	CreatedAt  time.Time `json:"created_at"`
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

func denialSuiteID(p pull, consumerBase, kind string) string {
	// Each reusable call uploads artifacts under its suite ID and GitHub run
	// identity. Distinct IDs keep both denial reports separate from the edit.
	digest := sha256.Sum256([]byte(suiteID(p, consumerBase) + ":denied:" + kind))
	return fmt.Sprintf("p%d-%x", p.Number, digest[:12])
}

func branchWorkflow(p pull, consumerBase string) string {
	return gatecaller.BranchWorkflow(gatecaller.Pull{Number: p.Number, HeadSHA: p.Head.SHA, BaseSHA: p.Base.SHA}, consumerBase)
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
	return a.ensureBranchGuarded(ctx, p, nil)
}

func (a api) ensureBranchGuarded(ctx context.Context, p pull, guard func(context.Context, pull, string) error) (string, error) {
	mainRef, ok, err := a.branch(ctx, "main")
	if err != nil || !ok || !shaPattern.MatchString(mainRef.Object.SHA) {
		return "", errors.New("disposable main identity unavailable")
	}
	name := "sofa-e2e/" + suiteID(p, mainRef.Object.SHA)
	if guard != nil {
		if err := guard(ctx, p, suiteID(p, mainRef.Object.SHA)); err != nil {
			return name, err
		}
	}
	want := branchWorkflow(p, mainRef.Object.SHA)
	if existing, exists, err := a.branch(ctx, name); err != nil {
		return name, err
	} else if exists {
		if !shaPattern.MatchString(existing.Object.SHA) {
			return name, errors.New("owned branch SHA invalid")
		}
		var file content
		path := "/repos/" + disposableRepo + "/contents/" + workflowPath + "?ref=" + url.QueryEscape(name)
		if err := a.get(ctx, path, &file); err != nil || file.Encoding != "base64" {
			return name, errors.New("owned branch workflow unavailable")
		}
		actual, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(file.Content, "\n", ""))
		if err != nil || string(actual) != want {
			return name, errors.New("owned branch workflow differs from exact suite")
		}
		return name, nil
	}
	var base commit
	if err := a.get(ctx, "/repos/"+disposableRepo+"/git/commits/"+mainRef.Object.SHA, &base); err != nil || !shaPattern.MatchString(base.Tree.SHA) {
		return name, errors.New("disposable base tree unavailable")
	}
	var tree struct {
		SHA string `json:"sha"`
	}
	if err := a.postWorkflow(ctx, "/repos/"+disposableRepo+"/git/trees", map[string]any{
		"base_tree": base.Tree.SHA,
		"tree":      []map[string]any{{"path": workflowPath, "mode": "100644", "type": "blob", "content": want}},
	}, &tree); err != nil {
		return name, fmt.Errorf("cannot create suite workflow tree: %w", err)
	} else if !shaPattern.MatchString(tree.SHA) {
		return name, errors.New("invalid suite workflow tree")
	}
	var made commit
	if err := a.postWorkflow(ctx, "/repos/"+disposableRepo+"/git/commits", map[string]any{
		"message": "Test sofa PR at exact candidate and base revisions",
		"tree":    tree.SHA,
		"parents": []string{mainRef.Object.SHA},
	}, &made); err != nil {
		return name, fmt.Errorf("cannot create suite workflow commit: %w", err)
	} else if !shaPattern.MatchString(made.SHA) {
		return name, errors.New("invalid suite workflow commit")
	}
	if err := a.postWorkflow(ctx, "/repos/"+disposableRepo+"/git/refs", map[string]any{"ref": "refs/heads/" + name, "sha": made.SHA}, nil); err != nil {
		return name, fmt.Errorf("cannot create suite workflow ref: %w", err)
	}
	return name, nil
}

func (a api) dispatchOnce(ctx context.Context, p pull, branch string) error {
	var runs runList
	path := "/repos/" + disposableRepo + "/actions/workflows/sofa-gate.yml/runs?event=workflow_dispatch&branch=" + url.QueryEscape(branch) + "&per_page=8"
	if err := a.get(ctx, path, &runs); err != nil {
		return err
	}
	dispatch, err := shouldDispatch(runs, branch, time.Now().UTC())
	if err != nil {
		if errors.Is(err, errRetryBudget) {
			runURL := coordinatorRunURL()
			if newest := newestRun(runs); newest.ID > 0 {
				runURL = fmt.Sprintf("https://github.com/%s/actions/runs/%d", disposableRepo, newest.ID)
			}
			if publishErr := a.publishFailure(ctx, p, suiteDescription(strings.TrimPrefix(branch, "sofa-e2e/"), gatestatus.Failure), runURL); publishErr != nil {
				return fmt.Errorf("hosted retry budget exhausted and failure status unavailable: %w", publishErr)
			}
		}
		return err
	}
	if !dispatch {
		newest := newestRun(runs)
		if newest.Status != "completed" {
			suite := strings.TrimPrefix(branch, "sofa-e2e/")
			status, err := a.statusWriter().Latest(ctx, p.Head.SHA)
			if err != nil || !status.Found || !status.Source || status.Description != suiteDescription(suite, status.State) || status.State == gatestatus.Success {
				if err := a.publishPending(ctx, p, suite, fmt.Sprintf("https://github.com/%s/actions/runs/%d", disposableRepo, newest.ID)); err != nil {
					return fmt.Errorf("mark active sofa suite pending: %w", err)
				}
			}
		}
		fmt.Printf("suite %s already has an active or passing hosted run\n", strings.TrimPrefix(branch, "sofa-e2e/"))
		return nil
	}
	mode, producer, err := a.nextScenario(ctx, runs)
	if err != nil {
		return err
	}
	// Re-read after branch creation; changed base/head cannot dispatch the old suite.
	current, err := a.currentPR(ctx, p.Number)
	if err != nil || current.Head.SHA != p.Head.SHA || current.Base.SHA != p.Base.SHA {
		return errors.New("sofa PR changed before dispatch")
	}
	if err := a.statusWriter().Publish(ctx, gatestatus.Result{
		PRNumber: p.Number, HeadSHA: p.Head.SHA, BaseSHA: p.Base.SHA,
		State: gatestatus.Pending, RunURL: coordinatorRunURL(), Description: suiteDescription(strings.TrimPrefix(branch, "sofa-e2e/"), gatestatus.Pending),
	}); err != nil {
		return fmt.Errorf("mark exact sofa revision pending: %w", err)
	}
	// A GITHUB_TOKEN dispatch did not emit a workflow_run wakeup, and the
	// workflow-authoring token lacks Actions permission. Mint a short-lived
	// App token limited to disposable Actions dispatch instead.
	dispatchToken, err := a.statusWriter().DispatchToken(ctx)
	if err != nil {
		return fmt.Errorf("disposable App dispatch credential unavailable: %w", err)
	}
	err = a.request(ctx, http.MethodPost, "/repos/"+disposableRepo+"/actions/workflows/sofa-gate.yml/dispatches", dispatchToken, map[string]any{
		"ref":    branch,
		"inputs": map[string]string{"sofa_pr": strconv.Itoa(p.Number), "candidate_sha": p.Head.SHA, "base_sha": p.Base.SHA, "mode": mode, "producer_run_id": producer},
	}, nil)
	if err == nil {
		fmt.Printf("dispatched suite %s on %s\n", strings.TrimPrefix(branch, "sofa-e2e/"), branch)
	}
	return err
}

func (a api) suiteJobs(ctx context.Context, id int64) (suiteJobs, error) {
	var jobs suiteJobs
	if id < 1 {
		return jobs, errors.New("invalid hosted run ID")
	}
	err := a.get(ctx, fmt.Sprintf("/repos/%s/actions/runs/%d/jobs?per_page=100", disposableRepo, id), &jobs)
	if err != nil || jobs.TotalCount < 0 || jobs.TotalCount > 100 || jobs.TotalCount != len(jobs.Jobs) {
		return jobs, errors.New("hosted scenario jobs unavailable")
	}
	return jobs, nil
}

func initialFaultJobs(j suiteJobs) bool {
	want := map[string]string{"candidate / execute": "success", "candidate / verify": "success", "candidate / publish": "failure", "candidate / assert-denied": "skipped", "recover": "skipped"}
	for _, prefix := range []string{"deny-non-ready", "deny-completed-redelivery"} {
		for _, stage := range []string{"execute", "verify", "publish"} {
			want[prefix+" / "+stage] = "skipped"
		}
		want[prefix+" / assert-denied"] = "success"
	}
	if j.TotalCount != len(want) {
		return false
	}
	seen := make(map[string]bool, len(want))
	for _, job := range j.Jobs {
		if want[job.Name] == "" || seen[job.Name] || job.Status != "completed" || job.Conclusion != want[job.Name] || job.RunAttempt != 1 {
			return false
		}
		seen[job.Name] = true
	}
	return true
}

func recoveryJobs(j suiteJobs) bool {
	if j.TotalCount != 7 || len(j.Jobs) != 7 {
		return false
	}
	want := map[string]bool{"candidate": true, "deny-non-ready": true, "deny-completed-redelivery": true, "recover / execute": true, "recover / verify": true, "recover / publish": true, "recover / assert-denied": true}
	for _, job := range j.Jobs {
		if !want[job.Name] || job.RunAttempt != 1 || job.Status != "completed" {
			return false
		}
		if (job.Name == "candidate" || job.Name == "deny-non-ready" || job.Name == "deny-completed-redelivery") && job.Conclusion != "skipped" {
			return false
		}
		delete(want, job.Name)
	}
	return len(want) == 0
}

// A controlled first-run publication failure is followed by one recovery
// dispatch bound to its producing run. Ordinary unexpected failures retain
// the existing finite retry behavior.
func (a api) nextScenario(ctx context.Context, runs runList) (string, string, error) {
	if runs.TotalCount == 0 {
		return "initial", "", nil
	}
	latest := newestRun(runs)
	if latest.Status != "completed" || latest.Conclusion != "failure" {
		return "initial", "", nil
	}
	jobs, err := a.suiteJobs(ctx, latest.ID)
	if err != nil {
		return "", "", err
	}
	if initialFaultJobs(jobs) {
		return "recovery", strconv.FormatInt(latest.ID, 10), nil
	}
	if !recoveryJobs(jobs) {
		return "initial", "", nil
	}
	var producer workflowRun
	for _, r := range runs.Runs {
		if !r.CreatedAt.Before(latest.CreatedAt) {
			continue
		}
		j, err := a.suiteJobs(ctx, r.ID)
		if err != nil {
			return "", "", err
		}
		if initialFaultJobs(j) && (producer.ID == 0 || r.CreatedAt.After(producer.CreatedAt)) {
			producer = r
		}
	}
	if producer.ID == 0 {
		return "", "", errors.New("recovery has no exact controlled producer")
	}
	return "recovery", strconv.FormatInt(producer.ID, 10), nil
}

// A failed or cancelled Actions run can be retried only within the original
// suite's finite time and dispatch budget. Successful or active runs never
// dispatch a duplicate. The observer separately insists on a successful
// latest run and never treats a failed or missing run as green.
func shouldDispatch(list runList, branch string, now time.Time) (bool, error) {
	if list.TotalCount > 8 {
		if len(list.Runs) != 8 {
			return false, errors.New("hosted suite run listing invalid")
		}
		return shouldDispatch(runList{TotalCount: 8, Runs: list.Runs}, branch, now)
	}
	if list.TotalCount < 0 || len(list.Runs) != list.TotalCount {
		return false, errors.New("hosted suite run listing invalid")
	}
	if list.TotalCount == 0 {
		return true, nil
	}
	newest := newestRun(list)
	oldest := now
	for _, r := range list.Runs {
		if r.ID < 1 || r.HeadBranch != branch || r.CreatedAt.IsZero() || r.CreatedAt.After(now.Add(time.Minute)) {
			return false, errors.New("hosted suite run identity invalid")
		}
		if r.CreatedAt.Before(oldest) {
			oldest = r.CreatedAt
		}
	}
	if newest.Status != "completed" {
		for _, active := range []string{"queued", "in_progress", "waiting", "requested", "pending"} {
			if newest.Status == active {
				return false, nil
			}
		}
		return false, errors.New("unknown hosted suite run state")
	}
	if newest.Conclusion == "success" {
		return false, nil
	}
	if newest.Conclusion != "failure" && newest.Conclusion != "cancelled" && newest.Conclusion != "timed_out" {
		return false, errors.New("hosted suite run outcome needs inspection")
	}
	if list.TotalCount >= 8 || now.Sub(oldest) >= 45*time.Minute {
		return false, errRetryBudget
	}
	return true, nil
}

func newestRun(list runList) workflowRun {
	var newest workflowRun
	for _, r := range list.Runs {
		if newest.ID == 0 || r.CreatedAt.After(newest.CreatedAt) || (r.CreatedAt.Equal(newest.CreatedAt) && r.ID > newest.ID) {
			newest = r
		}
	}
	return newest
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
	exhausted := 0
	for _, listed := range prs {
		p, err := a.currentPR(ctx, listed.Number)
		if err != nil {
			return err
		}
		if p.Head.SHA != listed.Head.SHA || p.Base.SHA != listed.Base.SHA {
			return errors.New("PR changed during discovery")
		}
		branch, err := a.ensureBranchGuarded(ctx, p, func(ctx context.Context, p pull, suite string) error {
			if err := a.reconcileStatus(ctx, p, suite); err != nil {
				return err
			}
			status, err := a.statusWriter().Latest(ctx, p.Head.SHA)
			if err != nil {
				return err
			}
			if status.Found && status.Source && status.State == gatestatus.Success && status.Description == suiteDescription(suite, gatestatus.Success) {
				name := "sofa-e2e/" + suite
				ref, exists, err := a.branch(ctx, name)
				if err != nil {
					return err
				}
				if exists {
					if !shaPattern.MatchString(ref.Object.SHA) {
						return errors.New("completed suite branch SHA invalid")
					}
					var file content
					path := "/repos/" + disposableRepo + "/contents/" + workflowPath + "?ref=" + url.QueryEscape(name)
					if err := a.get(ctx, path, &file); err != nil || file.Encoding != "base64" {
						return errors.New("completed suite workflow unavailable")
					}
					actual, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(file.Content, "\n", ""))
					mainRef, ok, readErr := a.branch(ctx, "main")
					if err != nil || readErr != nil || !ok || suiteID(p, mainRef.Object.SHA) != suite || string(actual) != branchWorkflow(p, mainRef.Object.SHA) {
						return errors.New("completed suite workflow differs from exact suite")
					}
				}
				return errSuiteCompleted
			}
			ready, err := a.checkCandidate(ctx, p)
			if err != nil {
				return err
			}
			if !ready {
				return errNotReady
			}
			// Successful cleanup removes the caller ref. Check the exact owned
			// Project item before branch authoring so a later scan cannot recreate
			// that ref while a status retry is still pending.
			mainRef, ok, err := a.branch(ctx, "main")
			if err != nil || !ok || suiteID(p, mainRef.Object.SHA) != suite {
				return errors.New("disposable base changed before Project replay check")
			}
			if a.fixture != nil || a.projectToken != "" {
				fixture := fixturelifecycle.Suite{ID: suite, CandidateSHA: p.Head.SHA, PRBaseSHA: p.Base.SHA, DisposableBaseSHA: mainRef.Object.SHA}
				if resource, err := a.fixtureWriter().Verify(ctx, fixture); err == nil && resource.Closed && resource.Archived && resource.IssueNumber > 0 && resource.ProjectItem != "" {
					return errSuiteItemCompleted
				}
			}
			return nil
		})
		if errors.Is(err, errSuiteCompleted) {
			fmt.Printf("PR %d exact hosted suite already completed\n", p.Number)
			continue
		}
		if errors.Is(err, errSuiteItemCompleted) {
			fmt.Printf("PR %d exact suite resources completed; awaiting App status or status retry\n", p.Number)
			continue
		}
		if errors.Is(err, errNotReady) {
			fmt.Printf("PR %d has no candidate test workflow; awaiting rollout\n", p.Number)
			continue
		}
		if err != nil {
			description := "Hosted E2E coordinator failure"
			if branch != "" {
				description = suiteDescription(strings.TrimPrefix(branch, "sofa-e2e/"), gatestatus.Failure)
			}
			if publishErr := a.publishFailure(ctx, p, description, coordinatorRunURL()); publishErr != nil {
				return fmt.Errorf("suite preparation failed (%v) and failure status unavailable: %w", err, publishErr)
			}
			return err
		}
		mainRef, ok, err := a.branch(ctx, "main")
		if err != nil || !ok || "sofa-e2e/"+suiteID(p, mainRef.Object.SHA) != branch {
			return errors.New("disposable base changed before test item setup")
		}
		fixture := fixturelifecycle.Suite{ID: suiteID(p, mainRef.Object.SHA), CandidateSHA: p.Head.SHA, PRBaseSHA: p.Base.SHA, DisposableBaseSHA: mainRef.Object.SHA}
		ready, err := readyOrCompleted(ctx, a.fixtureWriter(), fixture)
		if err != nil {
			if publishErr := a.publishFailure(ctx, p, suiteDescription(fixture.ID, gatestatus.Failure), coordinatorRunURL()); publishErr != nil {
				return fmt.Errorf("suite Project setup failed (%v) and failure status unavailable: %w", err, publishErr)
			}
			return fmt.Errorf("suite Project setup failed: %w", err)
		}
		if !ready {
			fmt.Printf("PR %d exact suite test item is complete; awaiting trusted observer replay\n", p.Number)
			continue
		}
		if err := a.dispatchOnce(ctx, p, branch); err != nil {
			if manual == "" && errors.Is(err, errRetryBudget) {
				exhausted++
				fmt.Printf("PR %d hosted suite exhausted its finite retry budget; continuing discovery\n", p.Number)
				continue
			}
			return err
		}
	}
	if exhausted != 0 {
		return fmt.Errorf("%d hosted suite(s) exhausted their retry budget", exhausted)
	}
	return nil
}

func main() {
	token := os.Getenv("GH_TOKEN")
	if token == "" || os.Getenv("GITHUB_REPOSITORY") != disposableRepo || os.Getenv("GITHUB_REF") != "refs/heads/main" {
		fmt.Fprintln(os.Stderr, "trusted coordinator identity unavailable")
		os.Exit(1)
	}
	a := api{token: token, workflowToken: os.Getenv("SOFA_DISPOSABLE_WORKFLOW_TOKEN"), projectToken: os.Getenv("SOFA_PROJECTS_TOKEN"), http: &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("redirect refused")
	}}}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	if err := run(ctx, a); err != nil {
		fmt.Fprintln(os.Stderr, "hosted gate coordinator:", err)
		os.Exit(1)
	}
}
