// sofa-gate-observe is the trusted, default-branch publication half of the
// disposable hosted gate. It treats every candidate artifact as hostile data.
package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/format"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	sofaRepo              = "kevinmartin/sofa"
	consumerRepo          = "kevinmartin/sofa-disposable"
	workflowPath          = ".github/workflows/sofa-gate.yml"
	candidateWorkflowPath = ".github/workflows/e2e-fake.yml"
	// These reported commands are valid only for this reviewed candidate workflow.
	candidateWorkflowHash = "1f42dba8dfccd5d450c1f9596cc740a8682f93ba909a19effe5d0817942eab84"
	fixturePath           = "fixture/greeting.go"
	maxArtifactZip        = 8 << 20
)

var sha40 = regexp.MustCompile(`^[0-9a-f]{40}$`)
var sha64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

type client struct {
	http           *http.Client
	token          string
	publisherToken string
	base           string
}

type apiError struct{ status int }

func (e apiError) Error() string { return fmt.Sprintf("GitHub API returned HTTP %d", e.status) }

func (c client) call(ctx context.Context, method, path string, input, output any) error {
	if !strings.HasPrefix(path, "/repos/") || strings.ContainsAny(path, "\r\n#") {
		return errors.New("invalid GitHub API path")
	}
	var body io.Reader
	if input != nil {
		encoded, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "sofa-disposable-gate-observe")
	if input != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return errors.New("GitHub transport unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return apiError{resp.StatusCode}
	}
	if output == nil {
		return nil
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(output)
}

func (c client) get(ctx context.Context, path string, output any) error {
	return c.call(ctx, http.MethodGet, path, nil, output)
}

func (c client) post(ctx context.Context, path string, input, output any) error {
	if c.publisherToken == "" {
		return errors.New("trusted disposable publisher credential unavailable")
	}
	c.token = c.publisherToken
	return c.call(ctx, http.MethodPost, path, input, output)
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

func suiteID(p pull, disposableBase string) string {
	h := sha256.Sum256([]byte(p.Head.SHA + ":" + p.Base.SHA + ":" + disposableBase))
	return fmt.Sprintf("p%d-%x", p.Number, h[:12])
}

func denialSuiteID(p pull, disposableBase, kind string) string {
	h := sha256.Sum256([]byte(suiteID(p, disposableBase) + ":denied:" + kind))
	return fmt.Sprintf("p%d-%x", p.Number, h[:12])
}

func (c client) currentPR(ctx context.Context, number int) (pull, error) {
	var p pull
	if err := c.get(ctx, fmt.Sprintf("/repos/%s/pulls/%d", sofaRepo, number), &p); err != nil {
		return p, err
	}
	if p.Number != number || p.State != "open" || p.Head.Repo.FullName != sofaRepo || !sha40.MatchString(p.Head.SHA) || !sha40.MatchString(p.Base.SHA) {
		return p, errors.New("sofa PR identity is not an open same-repository revision")
	}
	return p, nil
}

func (c client) listPRs(ctx context.Context) ([]pull, error) {
	var list []pull
	if err := c.get(ctx, "/repos/"+sofaRepo+"/pulls?state=open&per_page=100", &list); err != nil {
		return nil, err
	}
	if len(list) == 100 {
		return nil, errors.New("sofa PR discovery exceeded bounded page")
	}
	return list, nil
}

type gitRef struct {
	Object struct {
		SHA string `json:"sha"`
	} `json:"object"`
}

func (c client) ref(ctx context.Context, branch string) (string, bool, error) {
	var r gitRef
	err := c.get(ctx, "/repos/"+consumerRepo+"/git/ref/heads/"+url.PathEscape(branch), &r)
	var ae apiError
	if errors.As(err, &ae) && ae.status == 404 {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	if !sha40.MatchString(r.Object.SHA) {
		return "", false, errors.New("invalid GitHub ref SHA")
	}
	return r.Object.SHA, true, nil
}

type gitContent struct {
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
}

func (c client) content(ctx context.Context, path, ref string) ([]byte, error) {
	var item gitContent
	if err := c.get(ctx, "/repos/"+consumerRepo+"/contents/"+path+"?ref="+url.QueryEscape(ref), &item); err != nil {
		return nil, err
	}
	if item.Encoding != "base64" || len(item.Content) > 2<<20 {
		return nil, errors.New("GitHub content encoding or size invalid")
	}
	return base64.StdEncoding.DecodeString(strings.ReplaceAll(item.Content, "\n", ""))
}

func (c client) verifyCandidateCommands(ctx context.Context, candidateSHA, wantHash string) error {
	if !sha40.MatchString(candidateSHA) {
		return errors.New("candidate workflow revision invalid")
	}
	var item gitContent
	path := "/repos/" + sofaRepo + "/contents/" + candidateWorkflowPath + "?ref=" + candidateSHA
	if err := c.get(ctx, path, &item); err != nil {
		return err
	}
	if item.Encoding != "base64" || len(item.Content) > 2<<20 {
		return errors.New("candidate workflow content unavailable")
	}
	content, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(item.Content, "\n", ""))
	if err != nil || hash(content) != wantHash {
		return errors.New("candidate workflow command pin changed")
	}
	return nil
}

type workflowRun struct {
	ID         int64     `json:"id"`
	Status     string    `json:"status"`
	Conclusion string    `json:"conclusion"`
	Event      string    `json:"event"`
	Path       string    `json:"path"`
	HeadBranch string    `json:"head_branch"`
	HeadSHA    string    `json:"head_sha"`
	RunAttempt int       `json:"run_attempt"`
	CreatedAt  time.Time `json:"created_at"`
	StartedAt  time.Time `json:"run_started_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

const maxHostedRunDuration = 6 * time.Hour

func hostedDuration(r workflowRun) (int64, error) {
	if r.CreatedAt.IsZero() || r.StartedAt.IsZero() || r.UpdatedAt.IsZero() ||
		r.StartedAt.Before(r.CreatedAt) || !r.UpdatedAt.After(r.StartedAt) ||
		r.UpdatedAt.Sub(r.StartedAt) > maxHostedRunDuration {
		return 0, errors.New("hosted run timestamps invalid")
	}
	ms := r.UpdatedAt.Sub(r.StartedAt).Milliseconds()
	if ms < 1 {
		return 0, errors.New("hosted run duration below reporting resolution")
	}
	return ms, nil
}

type runList struct {
	TotalCount int           `json:"total_count"`
	Runs       []workflowRun `json:"workflow_runs"`
}

type jobList struct {
	TotalCount int         `json:"total_count"`
	Jobs       []hostedJob `json:"jobs"`
}

type hostedJob struct {
	Name        string    `json:"name"`
	Conclusion  string    `json:"conclusion"`
	Status      string    `json:"status"`
	RunAttempt  int       `json:"run_attempt"`
	StartedAt   time.Time `json:"started_at"`
	CompletedAt time.Time `json:"completed_at"`
}

type scenarioEvidence struct {
	ID                 string `json:"id"`
	RunID              int64  `json:"run_id"`
	Job                string `json:"job"`
	Command            string `json:"command"`
	JobDurationMS      int64  `json:"job_duration_ms"`
	FakePromptRequests int    `json:"fake_prompt_requests"`
	ProviderRequests   int    `json:"provider_requests"`
}

func (c client) scenarioEvidence(ctx context.Context, producer, recovered workflowRun) ([]scenarioEvidence, error) {
	var fault, recovery jobList
	for _, run := range []struct {
		id   int64
		jobs *jobList
	}{{producer.ID, &fault}, {recovered.ID, &recovery}} {
		if err := c.get(ctx, fmt.Sprintf("/repos/%s/actions/runs/%d/jobs?per_page=100", consumerRepo, run.id), run.jobs); err != nil {
			return nil, err
		}
	}
	if !validFaultJobs(fault) || !validRecoveryJobs(recovery) {
		return nil, errors.New("hosted scenario job matrix changed")
	}
	requested := []struct {
		id, job, command string
		run              workflowRun
		jobs             jobList
		prompts          int
	}{
		{"edit-fault", "candidate / execute", "/toolkit/sofa execute", producer, fault, 1},
		{"branch-conflict", "candidate / publish", "go test -count=1 -run '^TestHostedArtifactPublicationConflict$' ./cmd/sofa", producer, fault, 0},
		{"non-ready", "deny-non-ready / assert-denied", "bin/e2e-fixture deny", producer, fault, 0},
		{"completed-redelivery", "deny-completed-redelivery / assert-denied", "bin/e2e-fixture deny", producer, fault, 0},
		{"recovery-publication", "recover / publish", "go test -count=1 -run '^TestHostedArtifactPublication$' ./cmd/sofa", recovered, recovery, 0},
	}
	evidence := make([]scenarioEvidence, 0, len(requested))
	for _, want := range requested {
		var found *hostedJob
		for i := range want.jobs.Jobs {
			if want.jobs.Jobs[i].Name == want.job {
				found = &want.jobs.Jobs[i]
				break
			}
		}
		if found == nil || found.StartedAt.IsZero() || !found.CompletedAt.After(found.StartedAt) || found.CompletedAt.Sub(found.StartedAt) > maxHostedRunDuration {
			return nil, errors.New("hosted scenario job timing unavailable")
		}
		ms := found.CompletedAt.Sub(found.StartedAt).Milliseconds()
		if ms < 1 {
			return nil, errors.New("hosted scenario job timing below reporting resolution")
		}
		evidence = append(evidence, scenarioEvidence{want.id, want.run.ID, want.job, want.command, ms, want.prompts, 0})
	}
	return evidence, nil
}

type artifactList struct {
	TotalCount int `json:"total_count"`
	Artifacts  []struct {
		ID        int64  `json:"id"`
		Name      string `json:"name"`
		Expired   bool   `json:"expired"`
		Size      int64  `json:"size_in_bytes"`
		RunSource struct {
			ID int64 `json:"id"`
		} `json:"workflow_run"`
	} `json:"artifacts"`
}

func (c client) completedRun(ctx context.Context, branch, branchSHA string) (workflowRun, bool, error) {
	var list runList
	path := "/repos/" + consumerRepo + "/actions/workflows/sofa-gate.yml/runs?event=workflow_dispatch&branch=" + url.QueryEscape(branch) + "&per_page=100"
	if err := c.get(ctx, path, &list); err != nil {
		return workflowRun{}, false, err
	}
	if list.TotalCount > 100 {
		return workflowRun{}, false, errors.New("suite has unbounded hosted run history")
	}
	if list.TotalCount < 0 || len(list.Runs) != list.TotalCount {
		return workflowRun{}, false, errors.New("suite hosted run listing invalid")
	}
	var newest workflowRun
	for _, r := range list.Runs {
		if r.HeadBranch != branch || r.HeadSHA != branchSHA || r.Event != "workflow_dispatch" || r.Path != workflowPath {
			continue
		}
		if r.ID < 1 || r.CreatedAt.IsZero() || r.RunAttempt < 1 {
			return workflowRun{}, false, errors.New("suite hosted run identity invalid")
		}
		if newest.ID == 0 || r.CreatedAt.After(newest.CreatedAt) || (r.CreatedAt.Equal(newest.CreatedAt) && r.ID > newest.ID) {
			newest = r
		}
	}
	if newest.ID == 0 || newest.RunAttempt != 1 || newest.Status != "completed" || newest.Conclusion != "success" {
		return workflowRun{}, false, nil
	}
	if _, err := hostedDuration(newest); err != nil {
		return workflowRun{}, false, err
	}
	var jobs jobList
	if err := c.get(ctx, fmt.Sprintf("/repos/%s/actions/runs/%d/jobs?per_page=100", consumerRepo, newest.ID), &jobs); err != nil {
		return workflowRun{}, false, err
	}
	if !validJobs(jobs) {
		return workflowRun{}, false, errors.New("hosted run lacks the exact successful edit and denial job matrix")
	}
	return newest, true, nil
}

func validJobs(j jobList) bool {
	want := map[string]string{"candidate / execute": "success", "candidate / verify": "success", "candidate / publish": "success", "candidate / assert-denied": "skipped", "recover": "skipped"}
	for _, job := range []string{"deny-non-ready", "deny-completed-redelivery"} {
		for _, skipped := range []string{"execute", "verify", "publish"} {
			want[job+" / "+skipped] = "skipped"
		}
		want[job+" / assert-denied"] = "success"
	}
	if j.TotalCount != len(want) || len(j.Jobs) != len(want) {
		return false
	}
	seen := make(map[string]bool, len(want))
	for _, item := range j.Jobs {
		conclusion, ok := want[item.Name]
		if !ok || seen[item.Name] || item.Status != "completed" || item.Conclusion != conclusion || item.RunAttempt != 1 {
			return false
		}
		seen[item.Name] = true
	}
	for name := range want {
		if !seen[name] {
			return false
		}
	}
	return true
}

func validFaultJobs(j jobList) bool {
	want := map[string]string{"candidate / execute": "success", "candidate / verify": "success", "candidate / publish": "failure", "candidate / assert-denied": "skipped", "recover": "skipped"}
	for _, name := range []string{"deny-non-ready", "deny-completed-redelivery"} {
		for _, stage := range []string{"execute", "verify", "publish"} {
			want[name+" / "+stage] = "skipped"
		}
		want[name+" / assert-denied"] = "success"
	}
	return exactJobs(j, want)
}

func validRecoveryJobs(j jobList) bool {
	return exactJobs(j, map[string]string{"candidate": "skipped", "deny-non-ready": "skipped", "deny-completed-redelivery": "skipped", "recover / execute": "skipped", "recover / verify": "success", "recover / publish": "success", "recover / assert-denied": "skipped"})
}

func exactJobs(j jobList, want map[string]string) bool {
	if j.TotalCount != len(want) || len(j.Jobs) != len(want) {
		return false
	}
	seen := make(map[string]bool, len(want))
	for _, item := range j.Jobs {
		conclusion, ok := want[item.Name]
		if !ok || seen[item.Name] || item.Status != "completed" || item.Conclusion != conclusion || item.RunAttempt != 1 {
			return false
		}
		seen[item.Name] = true
	}
	return true
}

func (c client) completedPair(ctx context.Context, branch, branchSHA string) (workflowRun, workflowRun, bool, error) {
	var list runList
	path := "/repos/" + consumerRepo + "/actions/workflows/sofa-gate.yml/runs?event=workflow_dispatch&branch=" + url.QueryEscape(branch) + "&per_page=100"
	if err := c.get(ctx, path, &list); err != nil {
		return workflowRun{}, workflowRun{}, false, err
	}
	if list.TotalCount < 0 || list.TotalCount > 8 || len(list.Runs) != list.TotalCount {
		return workflowRun{}, workflowRun{}, false, errors.New("suite has invalid or unbounded hosted run history")
	}
	var latest workflowRun
	for _, r := range list.Runs {
		if r.HeadBranch != branch || r.HeadSHA != branchSHA || r.Event != "workflow_dispatch" || r.Path != workflowPath || r.ID < 1 || r.RunAttempt != 1 || r.CreatedAt.IsZero() {
			return workflowRun{}, workflowRun{}, false, errors.New("suite hosted run identity invalid")
		}
		if latest.ID == 0 || r.CreatedAt.After(latest.CreatedAt) || (r.CreatedAt.Equal(latest.CreatedAt) && r.ID > latest.ID) {
			latest = r
		}
	}
	if latest.ID == 0 || latest.Status != "completed" || latest.Conclusion != "success" {
		return workflowRun{}, workflowRun{}, false, nil
	}
	if _, err := hostedDuration(latest); err != nil {
		return workflowRun{}, workflowRun{}, false, err
	}
	var recoveredJobs jobList
	if err := c.get(ctx, fmt.Sprintf("/repos/%s/actions/runs/%d/jobs?per_page=100", consumerRepo, latest.ID), &recoveredJobs); err != nil {
		return workflowRun{}, workflowRun{}, false, err
	}
	if !validRecoveryJobs(recoveredJobs) {
		return workflowRun{}, workflowRun{}, false, errors.New("hosted recovery run lacks exact skipped-execute publication graph")
	}
	var producer workflowRun
	for _, r := range list.Runs {
		if r.ID == latest.ID || !r.CreatedAt.Before(latest.CreatedAt) || r.Conclusion != "failure" || r.Status != "completed" {
			continue
		}
		var candidateJobs jobList
		if err := c.get(ctx, fmt.Sprintf("/repos/%s/actions/runs/%d/jobs?per_page=100", consumerRepo, r.ID), &candidateJobs); err != nil {
			return workflowRun{}, workflowRun{}, false, err
		}
		if validFaultJobs(candidateJobs) && (producer.ID == 0 || r.CreatedAt.After(producer.CreatedAt)) {
			producer = r
		}
	}
	if producer.ID == 0 || latest.CreatedAt.Sub(producer.CreatedAt) > 45*time.Minute {
		return workflowRun{}, workflowRun{}, false, errors.New("hosted recovery has no bounded failed producer")
	}
	if _, err := hostedDuration(producer); err != nil {
		return workflowRun{}, workflowRun{}, false, err
	}
	return producer, latest, true, nil
}

func (c client) artifactID(ctx context.Context, r workflowRun, name string) (int64, error) {
	var list artifactList
	if err := c.get(ctx, fmt.Sprintf("/repos/%s/actions/runs/%d/artifacts?per_page=100", consumerRepo, r.ID), &list); err != nil {
		return 0, err
	}
	if list.TotalCount < 0 || list.TotalCount > 100 || len(list.Artifacts) != list.TotalCount {
		return 0, errors.New("suite artifact listing invalid or unbounded")
	}
	var id int64
	for _, a := range list.Artifacts {
		if a.Name != name {
			continue
		}
		if id != 0 || a.ID < 1 || a.RunSource.ID != r.ID || a.Expired || a.Size < 1 || a.Size > maxArtifactZip {
			return 0, errors.New("ambiguous or invalid hosted report artifact")
		}
		id = a.ID
	}
	if id == 0 {
		return 0, errors.New("hosted report artifact unavailable")
	}
	return id, nil
}

func (c client) reportArtifact(ctx context.Context, r workflowRun, suite string) (map[string][]byte, int64, error) {
	id, err := c.artifactID(ctx, r, fmt.Sprintf("sofa-e2e-report-%s-%d-%d", suite, r.ID, r.RunAttempt))
	if err != nil {
		return nil, 0, err
	}
	files, err := c.downloadZIP(ctx, id, false)
	return files, id, err
}

func (c client) denialArtifact(ctx context.Context, r workflowRun, suite string) ([]byte, int64, error) {
	id, err := c.artifactID(ctx, r, fmt.Sprintf("sofa-e2e-denial-%s-%d-%d", suite, r.ID, r.RunAttempt))
	if err != nil {
		return nil, 0, err
	}
	files, err := c.downloadZIP(ctx, id, true)
	if err != nil {
		return nil, 0, err
	}
	return files["denial.json"], id, nil
}

func (c client) conflictArtifact(ctx context.Context, r workflowRun, suite string) ([]byte, int64, error) {
	id, err := c.artifactID(ctx, r, fmt.Sprintf("sofa-e2e-conflict-%s-%d-%d", suite, r.ID, r.RunAttempt))
	if err != nil {
		return nil, 0, err
	}
	files, err := c.downloadZIPWithExpected(ctx, id, map[string]bool{"conflict.json": true})
	if err != nil {
		return nil, 0, err
	}
	return files["conflict.json"], id, nil
}

func (c client) verifiedArtifact(ctx context.Context, r workflowRun, suite string) (map[string][]byte, int64, error) {
	id, err := c.artifactID(ctx, r, fmt.Sprintf("sofa-e2e-verified-%s-%d-%d", suite, r.ID, r.RunAttempt))
	if err != nil {
		return nil, 0, err
	}
	files, err := c.downloadZIPWithExpected(ctx, id, map[string]bool{
		"transport/config.yml": true, "transport/manifest.json": true, "transport/identity.json": true,
		"candidate/bundle.json": true, "candidate/execution.json": true, "candidate/network.json": true, "evidence/checks.json": true,
	})
	return files, id, err
}

func (c client) downloadZIP(ctx context.Context, artifactID int64, denial bool) (map[string][]byte, error) {
	if denial {
		return c.downloadZIPWithExpected(ctx, artifactID, map[string]bool{"denial.json": true})
	}
	return c.downloadZIPWithExpected(ctx, artifactID, map[string]bool{
		"transport/identity.json": true, "transport/manifest.json": true,
		"candidate/execution.json": true, "candidate/bundle.json": true, "candidate/network.json": true,
		"evidence/checks.json": true, "report/publication.json": true,
		"report/scenario.json": true,
	})
}

func (c client) downloadZIPWithExpected(ctx context.Context, artifactID int64, want map[string]bool) (map[string][]byte, error) {
	path := fmt.Sprintf("/repos/%s/actions/artifacts/%d/zip", consumerRepo, artifactID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "sofa-disposable-gate-observe")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, errors.New("GitHub artifact download unavailable")
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, apiError{resp.StatusCode}
	}
	zipBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxArtifactZip+1))
	if err != nil || len(zipBytes) > maxArtifactZip {
		return nil, errors.New("hosted artifact ZIP too large")
	}
	return unpackZIPExpected(zipBytes, want)
}

func unpackZIP(data []byte) (map[string][]byte, error) {
	return unpackZIPExpected(data, map[string]bool{
		"transport/identity.json": true, "transport/manifest.json": true,
		"candidate/execution.json": true, "candidate/bundle.json": true, "candidate/network.json": true,
		"evidence/checks.json": true, "report/publication.json": true,
		"report/scenario.json": true,
	})
}

func unpackZIPExpected(data []byte, want map[string]bool) (map[string][]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil || len(zr.File) > 16 {
		return nil, errors.New("invalid or oversized hosted artifact ZIP")
	}
	out := make(map[string][]byte, len(want))
	total := uint64(0)
	for _, f := range zr.File {
		if !want[f.Name] || f.FileInfo().Mode().IsRegular() == false || f.UncompressedSize64 > 2<<20 || f.CompressedSize64 > maxArtifactZip {
			return nil, errors.New("unexpected hosted artifact entry")
		}
		if _, exists := out[f.Name]; exists {
			return nil, errors.New("duplicate hosted artifact entry")
		}
		total += f.UncompressedSize64
		if total > maxArtifactZip {
			return nil, errors.New("hosted artifact contents too large")
		}
		r, err := f.Open()
		if err != nil {
			return nil, errors.New("hosted artifact entry unavailable")
		}
		b, readErr := io.ReadAll(io.LimitReader(r, int64(f.UncompressedSize64)+1))
		closeErr := r.Close()
		if readErr != nil || closeErr != nil || uint64(len(b)) != f.UncompressedSize64 {
			return nil, errors.New("hosted artifact entry size mismatch")
		}
		out[f.Name] = b
	}
	if len(out) != len(want) {
		return nil, errors.New("incomplete hosted report artifact")
	}
	return out, nil
}

type candidateFile struct {
	Path         string `json:"path"`
	Operation    string `json:"operation"`
	Mode         string `json:"mode"`
	BeforeSHA256 string `json:"before_sha256,omitempty"`
	Content      []byte `json:"content,omitempty"`
}

type bundle struct {
	Version         int             `json:"version"`
	Repository      string          `json:"repository"`
	AttemptID       string          `json:"attempt_id"`
	Generation      uint64          `json:"generation"`
	BaseSHA         string          `json:"base_sha"`
	CandidateDigest string          `json:"candidate_digest"`
	Files           []candidateFile `json:"files"`
}

type identity struct {
	Version           int    `json:"version"`
	SuiteID           string `json:"suite_id"`
	Scenario          string `json:"scenario"`
	CandidateSHA      string `json:"candidate_sha"`
	PRBaseSHA         string `json:"pr_base_sha"`
	DisposableBaseSHA string `json:"disposable_base_sha"`
	AttemptID         string `json:"attempt_id"`
	Generation        int64  `json:"generation"`
	ProducerRunID     string `json:"producer_run_id"`
	FakeAgent         string `json:"fake_agent"`
}

type report struct {
	SchemaVersion            int     `json:"schema_version"`
	SuiteID                  string  `json:"suite_id"`
	Scenario                 string  `json:"scenario"`
	CandidateSHA             string  `json:"candidate_sha"`
	PRBaseSHA                string  `json:"pr_base_sha"`
	DisposableBaseSHA        string  `json:"disposable_base_sha"`
	AttemptID                string  `json:"attempt_id"`
	Generation               int64   `json:"generation"`
	BundleGeneration         uint64  `json:"bundle_generation"`
	ProducerRunID            string  `json:"producer_run_id"`
	CandidateDigest          string  `json:"candidate_digest"`
	FakeAgent                string  `json:"fake_agent"`
	FakePromptRequests       int     `json:"fake_prompt_requests"`
	ProviderRequests         int     `json:"provider_requests"`
	ProviderRequestBasis     string  `json:"provider_request_basis"`
	NetworkTXPackets         *uint64 `json:"network_tx_packets"`
	NetworkMeasurementSource string  `json:"network_measurement_source"`
	SimulatedPRNumber        int64   `json:"simulated_pr_number"`
	SimulatedPRURL           string  `json:"simulated_pr_url"`
	SimulatedPRPostCount     int     `json:"simulated_pr_post_count"`
	VerifiedCheckCount       int     `json:"verified_check_count"`
	RealPublicationOwner     string  `json:"real_publication_owner"`
}

type validated struct {
	id      identity
	report  report
	bundle  bundle
	content []byte
}

type denialReport struct {
	SchemaVersion      int      `json:"schema_version"`
	SuiteID            string   `json:"suite_id"`
	Scenario           string   `json:"scenario"`
	DenialKind         string   `json:"denial_kind"`
	Decision           string   `json:"decision"`
	CandidateSHA       string   `json:"candidate_sha"`
	PRBaseSHA          string   `json:"pr_base_sha"`
	DisposableBaseSHA  string   `json:"disposable_base_sha"`
	RunID              string   `json:"run_id"`
	RunAttempt         int      `json:"run_attempt"`
	SkippedJobs        []string `json:"skipped_jobs"`
	FakePromptRequests int      `json:"fake_prompt_requests"`
	ProviderRequests   int      `json:"provider_requests"`
	PublicationWrites  int      `json:"publication_writes"`
	WriteCredentials   int      `json:"write_credentials"`
}

type denialEvidence struct {
	Kind        string `json:"kind"`
	SuiteID     string `json:"suite_id"`
	Decision    string `json:"decision"`
	ArtifactID  int64  `json:"artifact_id"`
	ArtifactURL string `json:"artifact_url"`
}

type conflictReport struct {
	SchemaVersion    int    `json:"schema_version"`
	Simulation       string `json:"simulation"`
	CandidateDigest  string `json:"candidate_digest"`
	BaseSHA          string `json:"base_sha"`
	AttemptID        string `json:"attempt_id"`
	Generation       uint64 `json:"generation"`
	Branch           string `json:"branch"`
	ExistingHead     string `json:"existing_head"`
	HeadAfterReplay  string `json:"head_after_replay"`
	DeliveryAttempts int    `json:"delivery_attempts"`
	FakeGitWrites    int    `json:"fake_git_writes"`
	PRPosts          int    `json:"pr_posts"`
	ProviderRequests int    `json:"provider_requests"`
}

func validateConflictArtifact(data []byte, verified validated) error {
	var r conflictReport
	if err := decodeStrict(data, &r); err != nil {
		return err
	}
	if r.SchemaVersion != 1 || r.Simulation != "fake-github-transport" || r.CandidateDigest != verified.bundle.CandidateDigest || r.BaseSHA != verified.bundle.BaseSHA || !sha64.MatchString(verified.bundle.AttemptID) || r.AttemptID != verified.bundle.AttemptID || r.Generation != 1 || r.Branch != "sofa/"+verified.bundle.AttemptID[:24] || r.ExistingHead != strings.Repeat("b", 40) || r.HeadAfterReplay != r.ExistingHead || r.DeliveryAttempts != 2 || r.FakeGitWrites != 0 || r.PRPosts != 0 || r.ProviderRequests != 0 {
		return errors.New("hosted conflict report does not preserve unexpected branch")
	}
	return nil
}

func validateProducerArtifact(retained, recovery map[string][]byte, p pull, producer workflowRun, mainSHA string, verified validated) error {
	for _, path := range []string{"candidate/bundle.json", "candidate/execution.json", "candidate/network.json", "evidence/checks.json"} {
		if len(retained[path]) == 0 || !bytes.Equal(retained[path], recovery[path]) {
			return errors.New("recovered candidate differs from retained producer bytes")
		}
	}
	var original identity
	if err := decodeStrict(retained["transport/identity.json"], &original); err != nil {
		return err
	}
	if original.Version != 1 || original.SuiteID != suiteID(p, mainSHA) || original.Scenario != "edit" || original.CandidateSHA != p.Head.SHA || original.PRBaseSHA != p.Base.SHA || original.DisposableBaseSHA != mainSHA || original.AttemptID != verified.id.AttemptID || original.Generation != 1 || original.ProducerRunID != "" || original.FakeAgent != "fake-acp" {
		return errors.New("retained candidate identity differs from recovery")
	}
	var manifest struct {
		Version int `json:"version"`
		Fence   struct {
			AttemptID  string `json:"attempt_id"`
			Generation int64  `json:"generation"`
			Owner      struct {
				RunID      string `json:"run_id"`
				RunAttempt int    `json:"run_attempt"`
			} `json:"owner"`
		} `json:"fence"`
		RecoveryCheckpoint json.RawMessage `json:"recovery_checkpoint"`
		RecoverySource     json.RawMessage `json:"recovery_source"`
	}
	if err := decodeStrict(retained["transport/manifest.json"], &manifest); err != nil {
		return err
	}
	if manifest.Version != 1 || manifest.Fence.AttemptID != original.AttemptID || manifest.Fence.Generation != 1 || manifest.Fence.Owner.RunID != strconv.FormatInt(producer.ID, 10) || manifest.Fence.Owner.RunAttempt != producer.RunAttempt || len(manifest.RecoveryCheckpoint) != 0 || len(manifest.RecoverySource) != 0 {
		return errors.New("retained producer fence invalid")
	}
	return nil
}

func validateDenialArtifact(data []byte, p pull, r workflowRun, mainSHA, kind string) error {
	var d denialReport
	if err := decodeStrict(data, &d); err != nil {
		return err
	}
	decision := map[string]string{"non-ready": "admission-denied", "completed-redelivery": "already-completed"}[kind]
	if decision == "" || d.SchemaVersion != 1 || d.SuiteID != denialSuiteID(p, mainSHA, kind) ||
		d.Scenario != "denied" || d.DenialKind != kind || d.Decision != decision ||
		d.CandidateSHA != p.Head.SHA || d.PRBaseSHA != p.Base.SHA || d.DisposableBaseSHA != mainSHA ||
		d.RunID != strconv.FormatInt(r.ID, 10) || d.RunAttempt != r.RunAttempt ||
		len(d.SkippedJobs) != 3 || d.SkippedJobs[0] != "execute" || d.SkippedJobs[1] != "verify" || d.SkippedJobs[2] != "publish" ||
		d.FakePromptRequests != 0 || d.ProviderRequests != 0 || d.PublicationWrites != 0 || d.WriteCredentials != 0 {
		return errors.New("hosted denial report does not match exact suite")
	}
	return nil
}

func decodeStrict(data []byte, out any) error {
	if len(data) > 2<<20 {
		return errors.New("hosted JSON exceeds limit")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	if err := uniqueJSON(d); err != nil {
		return errors.New("hosted JSON has malformed or duplicate keys")
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("hosted JSON has trailing data")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	if err := d.Decode(out); err != nil {
		return errors.New("hosted JSON cannot be decoded")
	}
	return nil
}

func uniqueJSON(d *json.Decoder) error {
	t, err := d.Token()
	if err != nil {
		return err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			key, err := d.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok || seen[name] {
				return errors.New("duplicate JSON key")
			}
			seen[name] = true
			if err := uniqueJSON(d); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := uniqueJSON(d); err != nil {
				return err
			}
		}
	default:
		return errors.New("invalid JSON delimiter")
	}
	_, err = d.Token()
	return err
}

func digestBundle(b bundle) (string, error) {
	b.CandidateDigest = ""
	b.Files = append([]candidateFile(nil), b.Files...)
	sort.Slice(b.Files, func(i, j int) bool { return b.Files[i].Path < b.Files[j].Path })
	encoded, err := json.Marshal(b)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(encoded)
	return hex.EncodeToString(h[:]), nil
}

func hash(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func validateArtifact(files map[string][]byte, p pull, r workflowRun, mainSHA string, baseContent []byte) (validated, error) {
	return validateArtifactFor(files, p, r, mainSHA, baseContent, suiteID(p, mainSHA), 1, 0)
}

func validateArtifactFor(files map[string][]byte, p pull, r workflowRun, mainSHA string, baseContent []byte, suite string, generation int64, producerID int64) (validated, error) {
	var v validated
	for _, item := range []struct {
		name string
		out  any
	}{
		{"transport/identity.json", &v.id}, {"candidate/bundle.json", &v.bundle}, {"report/scenario.json", &v.report},
	} {
		if err := decodeStrict(files[item.name], item.out); err != nil {
			return v, err
		}
	}
	producer := ""
	if producerID > 0 {
		producer = strconv.FormatInt(producerID, 10)
	}
	if v.id.Version != 1 || v.id.SuiteID != suite || v.id.Scenario != "edit" || v.id.CandidateSHA != p.Head.SHA || v.id.PRBaseSHA != p.Base.SHA || v.id.DisposableBaseSHA != mainSHA || v.id.FakeAgent != "fake-acp" || v.id.Generation != generation || v.id.ProducerRunID != producer {
		return v, errors.New("hosted identity does not match current exact suite")
	}
	if v.report.SchemaVersion != 2 || v.report.SuiteID != suite || v.report.Scenario != "edit" || v.report.CandidateSHA != p.Head.SHA || v.report.PRBaseSHA != p.Base.SHA || v.report.DisposableBaseSHA != mainSHA || v.report.AttemptID != v.id.AttemptID || v.report.Generation != v.id.Generation || v.report.BundleGeneration != 1 || v.report.ProducerRunID != producer || v.report.FakeAgent != "fake-acp" || v.report.FakePromptRequests != 1 || v.report.ProviderRequests != 0 || v.report.ProviderRequestBasis != "measured-zero-network-tx-packets-in-networkless-fake-peer" || v.report.SimulatedPRPostCount != 1 || v.report.VerifiedCheckCount != 1 || v.report.RealPublicationOwner != "trusted-disposable-coordinator-only" {
		return v, errors.New("hosted scenario report does not match exact suite")
	}
	var network struct {
		SchemaVersion   int     `json:"schema_version"`
		NetworkMode     string  `json:"network_mode"`
		Source          string  `json:"source"`
		TXPacketsBefore *uint64 `json:"tx_packets_before"`
		TXPacketsAfter  *uint64 `json:"tx_packets_after"`
		TXPacketsDelta  *uint64 `json:"tx_packets_delta"`
	}
	if err := decodeStrict(files["candidate/network.json"], &network); err != nil {
		return v, err
	}
	if network.SchemaVersion != 1 || network.NetworkMode != "none" || network.Source != "proc-net-dev" ||
		network.TXPacketsBefore == nil || network.TXPacketsAfter == nil || network.TXPacketsDelta == nil ||
		*network.TXPacketsAfter < *network.TXPacketsBefore ||
		*network.TXPacketsAfter-*network.TXPacketsBefore != *network.TXPacketsDelta || *network.TXPacketsDelta != 0 ||
		v.report.NetworkTXPackets == nil || *v.report.NetworkTXPackets != *network.TXPacketsDelta ||
		v.report.NetworkMeasurementSource != network.Source {
		return v, errors.New("hosted zero-network measurement invalid")
	}
	if v.bundle.Version != 1 || v.bundle.Repository != consumerRepo || v.bundle.AttemptID != v.id.AttemptID || v.bundle.Generation != 1 || v.bundle.BaseSHA != mainSHA || !sha64.MatchString(v.bundle.CandidateDigest) || v.report.CandidateDigest != v.bundle.CandidateDigest || len(v.bundle.Files) != 1 {
		return v, errors.New("hosted candidate identity or file count invalid")
	}
	d, err := digestBundle(v.bundle)
	if err != nil || d != v.bundle.CandidateDigest {
		return v, errors.New("hosted candidate digest mismatch")
	}
	f := v.bundle.Files[0]
	if f.Path != fixturePath || f.Operation != "update" || f.Mode != "100644" || f.BeforeSHA256 != hash(baseContent) || len(f.Content) > 8192 || bytes.Equal(f.Content, baseContent) {
		return v, errors.New("hosted candidate exceeds exact fixture change policy")
	}
	formatted, err := format.Source(baseContent)
	if err != nil || !bytes.Equal(f.Content, formatted) {
		return v, errors.New("hosted candidate does not contain exact gofmt fixture result")
	}
	var manifest struct {
		Version int `json:"version"`
		Grant   struct {
			Repository string `json:"repository"`
			BaseSHA    string `json:"base_sha"`
		} `json:"grant"`
		Fence struct {
			AttemptID  string `json:"attempt_id"`
			Generation int64  `json:"generation"`
			Owner      struct {
				RunID      string `json:"run_id"`
				RunAttempt int    `json:"run_attempt"`
			} `json:"owner"`
		} `json:"fence"`
		RecoveryCheckpoint *struct {
			Version      int    `json:"version"`
			Phase        string `json:"phase"`
			ArtifactID   string `json:"artifact_id"`
			Digest       string `json:"digest"`
			CandidateSHA string `json:"candidate_sha"`
			Producer     struct {
				RunID      string `json:"run_id"`
				RunAttempt int    `json:"run_attempt"`
			} `json:"producer"`
			Generation int64     `json:"generation"`
			AcceptedAt time.Time `json:"accepted_at"`
			ExpiresAt  time.Time `json:"expires_at"`
		} `json:"recovery_checkpoint"`
		RecoverySource *struct {
			RunID      string `json:"run_id"`
			RunAttempt int    `json:"run_attempt"`
		} `json:"recovery_source"`
	}
	if err := decodeStrict(files["transport/manifest.json"], &manifest); err != nil {
		return v, err
	}
	if manifest.Version != 1 || manifest.Grant.Repository != consumerRepo || manifest.Grant.BaseSHA != mainSHA || manifest.Fence.AttemptID != v.id.AttemptID || manifest.Fence.Generation != generation || manifest.Fence.Owner.RunID != strconv.FormatInt(r.ID, 10) || manifest.Fence.Owner.RunAttempt != r.RunAttempt {
		return v, errors.New("hosted manifest does not bind producing run")
	}
	if producerID == 0 {
		if manifest.RecoveryCheckpoint != nil || manifest.RecoverySource != nil {
			return v, errors.New("ordinary hosted candidate carries recovery authority")
		}
	} else {
		cp := manifest.RecoveryCheckpoint
		source := manifest.RecoverySource
		bundleBytes := files["candidate/bundle.json"]
		digest := sha256.Sum256(bundleBytes)
		if generation != 2 || cp == nil || source == nil || cp.Version != 1 || cp.Phase != "validating" || cp.ArtifactID != "sofa-e2e-candidate-"+suite || cp.Digest != hex.EncodeToString(digest[:]) || cp.CandidateSHA != v.bundle.CandidateDigest || cp.Producer.RunID != producer || cp.Producer.RunAttempt != 1 || cp.Generation != 1 || source.RunID != producer || source.RunAttempt != 1 || !cp.ExpiresAt.After(cp.AcceptedAt) || cp.ExpiresAt.Sub(cp.AcceptedAt) > 30*time.Minute {
			return v, errors.New("retained hosted checkpoint provenance invalid")
		}
	}
	var execution struct {
		Version         int    `json:"version"`
		UsedAgent       bool   `json:"used_agent"`
		PromptRequests  int    `json:"prompt_requests"`
		ModelCalls      *int   `json:"model_calls"`
		CandidateDigest string `json:"candidate_digest"`
	}
	if err := decodeStrict(files["candidate/execution.json"], &execution); err != nil {
		return v, err
	}
	if execution.Version != 1 || !execution.UsedAgent || execution.PromptRequests != 1 || execution.ModelCalls != nil || execution.CandidateDigest != d {
		return v, errors.New("hosted fake ACP execution telemetry invalid")
	}
	var checks []struct {
		Version         int    `json:"version"`
		Name            string `json:"name"`
		CandidateDigest string `json:"candidate_digest"`
		Passed          bool   `json:"passed"`
	}
	if err := decodeStrict(files["evidence/checks.json"], &checks); err != nil {
		return v, err
	}
	if len(checks) != 1 || checks[0].Version != 1 || checks[0].Name != "go-test" || checks[0].CandidateDigest != d || !checks[0].Passed {
		return v, errors.New("hosted verifier evidence invalid")
	}
	var simulated struct {
		SchemaVersion    int    `json:"schema_version"`
		Simulation       string `json:"simulation"`
		CandidateDigest  string `json:"candidate_digest"`
		BaseSHA          string `json:"base_sha"`
		AttemptID        string `json:"attempt_id"`
		Generation       uint64 `json:"generation"`
		PRNumber         int64  `json:"pr_number"`
		PRPosts          int    `json:"pr_posts"`
		ProviderRequests int    `json:"provider_requests"`
	}
	if err := decodeStrict(files["report/publication.json"], &simulated); err != nil {
		return v, err
	}
	if simulated.SchemaVersion != 1 || simulated.Simulation != "fake-github-transport" || simulated.CandidateDigest != d || simulated.BaseSHA != mainSHA || simulated.AttemptID != v.id.AttemptID || simulated.Generation != 1 || simulated.PRNumber < 1 || simulated.PRPosts != 1 || simulated.ProviderRequests != 0 || v.report.SimulatedPRNumber != simulated.PRNumber {
		return v, errors.New("hosted publication simulation invalid")
	}
	v.content = f.Content
	return v, nil
}

type gitCommit struct {
	SHA     string `json:"sha"`
	Message string `json:"message"`
	Tree    struct {
		SHA string `json:"sha"`
	} `json:"tree"`
	Parents []struct {
		SHA string `json:"sha"`
	} `json:"parents"`
}

type gitTree struct {
	Truncated bool `json:"truncated"`
	Entries   []struct {
		Path string `json:"path"`
		Mode string `json:"mode"`
		Type string `json:"type"`
		SHA  string `json:"sha"`
	} `json:"tree"`
}

func (c client) tree(ctx context.Context, sha string) (gitTree, error) {
	var out gitTree
	if err := c.get(ctx, "/repos/"+consumerRepo+"/git/trees/"+sha+"?recursive=1", &out); err != nil {
		return out, err
	}
	if out.Truncated || len(out.Entries) > 10000 {
		return out, errors.New("GitHub tree is truncated or too large")
	}
	return out, nil
}

func (c client) verifyBranch(ctx context.Context, branchSHA, mainSHA, suite string, v validated) error {
	commit, err := c.commit(ctx, branchSHA)
	if err != nil {
		return err
	}
	if commit.Message != marker(suite, v) || len(commit.Parents) != 1 || commit.Parents[0].SHA != mainSHA {
		return errors.New("existing fixture branch is not the exact suite candidate")
	}
	base, err := c.commit(ctx, mainSHA)
	if err != nil {
		return err
	}
	oldTree, err := c.tree(ctx, base.Tree.SHA)
	if err != nil {
		return err
	}
	newTree, err := c.tree(ctx, commit.Tree.SHA)
	if err != nil {
		return err
	}
	oldFiles := map[string]string{}
	newFiles := map[string]string{}
	for _, entry := range oldTree.Entries {
		if entry.Type != "tree" {
			oldFiles[entry.Path] = entry.Mode + ":" + entry.Type + ":" + entry.SHA
		}
	}
	for _, entry := range newTree.Entries {
		if entry.Type != "tree" {
			newFiles[entry.Path] = entry.Mode + ":" + entry.Type + ":" + entry.SHA
		}
	}
	if len(oldFiles) != len(newFiles) {
		return errors.New("existing fixture branch changes file count")
	}
	changed := 0
	for path, old := range oldFiles {
		newValue, exists := newFiles[path]
		if !exists {
			return errors.New("existing fixture branch changes unrelated path")
		}
		if old != newValue {
			if path != fixturePath || !strings.HasPrefix(old, "100644:blob:") || !strings.HasPrefix(newValue, "100644:blob:") {
				return errors.New("existing fixture branch changes unrelated path")
			}
			changed++
		}
	}
	if changed != 1 {
		return errors.New("existing fixture branch is not one file update")
	}
	actual, err := c.content(ctx, fixturePath, branchSHA)
	if err != nil || !bytes.Equal(actual, v.content) {
		return errors.New("existing fixture branch contents differ from candidate")
	}
	return nil
}

func (c client) commit(ctx context.Context, sha string) (gitCommit, error) {
	var out gitCommit
	if err := c.get(ctx, "/repos/"+consumerRepo+"/git/commits/"+sha, &out); err != nil {
		return out, err
	}
	if out.SHA != sha || !sha40.MatchString(out.Tree.SHA) {
		return out, errors.New("GitHub commit identity invalid")
	}
	return out, nil
}

type draftPR struct {
	Number  int    `json:"number"`
	Draft   bool   `json:"draft"`
	State   string `json:"state"`
	HTMLURL string `json:"html_url"`
	Head    struct {
		Ref  string `json:"ref"`
		SHA  string `json:"sha"`
		Repo struct {
			FullName string `json:"full_name"`
		} `json:"repo"`
	} `json:"head"`
	Base struct {
		Ref string `json:"ref"`
	} `json:"base"`
}

func (c client) findDraft(ctx context.Context, branch, headSHA string) (draftPR, bool, error) {
	var prs []draftPR
	path := "/repos/" + consumerRepo + "/pulls?state=all&head=" + url.QueryEscape("kevinmartin:"+branch) + "&base=main&per_page=100"
	if err := c.get(ctx, path, &prs); err != nil {
		return draftPR{}, false, err
	}
	if len(prs) > 1 {
		return draftPR{}, false, errors.New("multiple fixture PRs for one suite")
	}
	if len(prs) == 0 {
		return draftPR{}, false, nil
	}
	pr := prs[0]
	if pr.Number < 1 || pr.Head.Ref != branch || pr.Head.SHA != headSHA || pr.Head.Repo.FullName != consumerRepo || pr.Base.Ref != "main" || pr.HTMLURL != fmt.Sprintf("https://github.com/%s/pull/%d", consumerRepo, pr.Number) {
		return draftPR{}, false, errors.New("existing fixture PR does not match published candidate")
	}
	if pr.State != "open" || !pr.Draft {
		return draftPR{}, false, errors.New("suite already has a closed or non-draft fixture PR")
	}
	return pr, true, nil
}

func marker(suite string, v validated) string {
	return "sofa-e2e-suite=" + suite + "; candidate=" + v.report.CandidateSHA + "; digest=" + v.bundle.CandidateDigest
}

func (c client) publish(ctx context.Context, p pull, mainSHA string, v validated) (draftPR, error) {
	suite := suiteID(p, mainSHA)
	branch := "sofa-e2e-result/" + suite
	// A closed draft is terminal. Never recreate its result ref, and never
	// treat a human-closed draft as a successful cleanup receipt.
	if found, err := c.closedDraft(ctx, p, mainSHA); err != nil {
		return draftPR{}, err
	} else if found {
		return draftPR{}, errors.New("suite draft is closed; retry trusted cleanup or status job")
	}
	branchSHA, exists, err := c.ref(ctx, branch)
	if err != nil {
		return draftPR{}, err
	}
	if exists {
		if err := c.verifyBranch(ctx, branchSHA, mainSHA, suite, v); err != nil {
			return draftPR{}, err
		}
	} else {
		base, err := c.commit(ctx, mainSHA)
		if err != nil {
			return draftPR{}, err
		}
		var tree struct {
			SHA string `json:"sha"`
		}
		if err := c.post(ctx, "/repos/"+consumerRepo+"/git/trees", map[string]any{
			"base_tree": base.Tree.SHA,
			"tree":      []map[string]any{{"path": fixturePath, "mode": "100644", "type": "blob", "content": string(v.content)}},
		}, &tree); err != nil || !sha40.MatchString(tree.SHA) {
			return draftPR{}, errors.New("cannot create exact fixture tree")
		}
		var made gitCommit
		if err := c.post(ctx, "/repos/"+consumerRepo+"/git/commits", map[string]any{
			"message": marker(suite, v), "tree": tree.SHA, "parents": []string{mainSHA},
		}, &made); err != nil || !sha40.MatchString(made.SHA) {
			return draftPR{}, errors.New("cannot create exact fixture commit")
		}
		latest, ok, err := c.ref(ctx, "main")
		if err != nil || !ok || latest != mainSHA {
			return draftPR{}, errors.New("disposable main changed before publication")
		}
		if err := c.post(ctx, "/repos/"+consumerRepo+"/git/refs", map[string]any{"ref": "refs/heads/" + branch, "sha": made.SHA}, nil); err != nil {
			// A retry can encounter a branch created after the initial read.
			branchSHA, exists, readErr := c.ref(ctx, branch)
			if readErr != nil || !exists {
				return draftPR{}, err
			}
			if err := c.verifyBranch(ctx, branchSHA, mainSHA, suite, v); err != nil {
				return draftPR{}, err
			}
		} else {
			branchSHA = made.SHA
		}
	}
	if pr, found, err := c.findDraft(ctx, branch, branchSHA); err != nil || found {
		return pr, err
	}
	latest, ok, err := c.ref(ctx, "main")
	if err != nil || !ok || latest != mainSHA {
		return draftPR{}, errors.New("disposable main changed before draft PR")
	}
	current, ok, err := c.ref(ctx, branch)
	if err != nil || !ok || current != branchSHA {
		return draftPR{}, errors.New("fixture branch changed before draft PR")
	}
	var created draftPR
	err = c.post(ctx, "/repos/"+consumerRepo+"/pulls", map[string]any{
		"title": "E2E fixture: format greeting for sofa PR #" + strconv.Itoa(p.Number),
		"body":  "Trusted hosted gate result for sofa PR #" + strconv.Itoa(p.Number) + ". Suite `" + suite + "` at exact candidate `" + p.Head.SHA + "` and base `" + p.Base.SHA + "`; the only change is gofmt of fixture/greeting.go.\n\nThe candidate's report was revalidated by trusted disposable code before publication.",
		"head":  branch, "base": "main", "draft": true,
	}, &created)
	if err != nil {
		if pr, found, readErr := c.findDraft(ctx, branch, branchSHA); readErr == nil && found {
			return pr, nil
		}
		return draftPR{}, err
	}
	if created.Number < 1 || !created.Draft || created.State != "open" || created.Head.Ref != branch || created.Head.SHA != branchSHA || created.Head.Repo.FullName != consumerRepo || created.Base.Ref != "main" || created.HTMLURL != fmt.Sprintf("https://github.com/%s/pull/%d", consumerRepo, created.Number) {
		return draftPR{}, errors.New("created fixture PR does not match exact candidate")
	}
	return created, nil
}

func (c client) closedDraft(ctx context.Context, p pull, mainSHA string) (bool, error) {
	suite := suiteID(p, mainSHA)
	branch := "sofa-e2e-result/" + suite
	var prs []draftPR
	path := "/repos/" + consumerRepo + "/pulls?state=all&head=" + url.QueryEscape("kevinmartin:"+branch) + "&base=main&per_page=100"
	if err := c.get(ctx, path, &prs); err != nil {
		return false, err
	}
	if len(prs) > 1 {
		return false, errors.New("multiple fixture PRs for one suite")
	}
	if len(prs) == 0 || prs[0].State == "open" {
		return false, nil
	}
	return true, nil
}

func (c client) observe(ctx context.Context, p pull) error {
	mainSHA, ok, err := c.ref(ctx, "main")
	if err != nil || !ok {
		return errors.New("disposable main unavailable")
	}
	suite := suiteID(p, mainSHA)
	branch := "sofa-e2e/" + suite
	branchSHA, ok, err := c.ref(ctx, branch)
	if err != nil {
		return err
	}
	if !ok {
		return nil // A failed App write retries from its same-run cleaned artifact.
	}
	caller, err := c.content(ctx, workflowPath, branchSHA)
	if err != nil || string(caller) != expectedCaller(p, mainSHA) {
		return nil // The suite was built against a different disposable base.
	}
	producer, r, ready, err := c.completedPair(ctx, branch, branchSHA)
	if err != nil || !ready {
		return err
	}
	scenarios, err := c.scenarioEvidence(ctx, producer, r)
	if err != nil {
		return err
	}
	if err := c.verifyCandidateCommands(ctx, p.Head.SHA, candidateWorkflowHash); err != nil {
		return err
	}
	files, artifactID, err := c.reportArtifact(ctx, r, suite)
	if err != nil {
		return err
	}
	baseContent, err := c.content(ctx, fixturePath, mainSHA)
	if err != nil {
		return err
	}
	v, err := validateArtifactFor(files, p, r, mainSHA, baseContent, suite, 2, producer.ID)
	if err != nil {
		return err
	}
	retained, retainedID, err := c.verifiedArtifact(ctx, producer, suite)
	if err != nil {
		return fmt.Errorf("retained verified candidate: %w", err)
	}
	if err := validateProducerArtifact(retained, files, p, producer, mainSHA, v); err != nil {
		return fmt.Errorf("retained verified candidate: %w", err)
	}
	conflictData, conflictID, err := c.conflictArtifact(ctx, producer, suite)
	if err != nil {
		return fmt.Errorf("branch-conflict artifact: %w", err)
	}
	if err := validateConflictArtifact(conflictData, v); err != nil {
		return fmt.Errorf("branch-conflict artifact: %w", err)
	}
	denials := make([]denialEvidence, 0, 2)
	for _, kind := range []string{"non-ready", "completed-redelivery"} {
		denialSuite := denialSuiteID(p, mainSHA, kind)
		data, id, err := c.denialArtifact(ctx, producer, denialSuite)
		if err != nil {
			return fmt.Errorf("%s denial artifact: %w", kind, err)
		}
		if err := validateDenialArtifact(data, p, producer, mainSHA, kind); err != nil {
			return fmt.Errorf("%s denial artifact: %w", kind, err)
		}
		decision := map[string]string{"non-ready": "admission-denied", "completed-redelivery": "already-completed"}[kind]
		denials = append(denials, denialEvidence{kind, denialSuite, decision, id, fmt.Sprintf("https://github.com/%s/actions/runs/%d/artifacts/%d", consumerRepo, producer.ID, id)})
	}
	current, err := c.currentPR(ctx, p.Number)
	if err != nil || current.Head.SHA != p.Head.SHA || current.Base.SHA != p.Base.SHA {
		return errors.New("sofa PR changed before fixture publication")
	}
	pr, err := c.publish(ctx, p, mainSHA, v)
	if err != nil {
		return err
	}
	if out := os.Getenv("SOFA_GATE_RESULT_PATH"); out != "" {
		durationMS, err := hostedDuration(r)
		if err != nil {
			return err
		}
		// This trusted result carries only bounded GitHub identities, hashes,
		// timestamps, and canonical links. Never copy candidate artifact content,
		// logs, credentials, or environment values into the status handoff.
		result := struct {
			SchemaVersion         int                `json:"schema_version"`
			SofaPR                int                `json:"sofa_pr"`
			CandidateSHA          string             `json:"candidate_sha"`
			PRBaseSHA             string             `json:"pr_base_sha"`
			DisposableBaseSHA     string             `json:"disposable_base_sha"`
			SuiteID               string             `json:"suite_id"`
			CandidateDigest       string             `json:"candidate_digest"`
			ProducerRunID         int64              `json:"producer_run_id"`
			ProducerRunURL        string             `json:"producer_run_url"`
			ProducerDurationMS    int64              `json:"producer_duration_ms"`
			RetainedArtifactID    int64              `json:"retained_artifact_id"`
			ConflictArtifactID    int64              `json:"conflict_artifact_id"`
			ConflictArtifactURL   string             `json:"conflict_artifact_url"`
			ConflictBranchHead    string             `json:"conflict_branch_head"`
			CandidateRunID        int64              `json:"candidate_run_id"`
			CandidateRunAttempt   int                `json:"candidate_run_attempt"`
			CandidateRunURL       string             `json:"candidate_run_url"`
			CandidateRunStartedAt time.Time          `json:"candidate_run_started_at"`
			CandidateRunUpdatedAt time.Time          `json:"candidate_run_updated_at"`
			CandidateDurationMS   int64              `json:"candidate_duration_ms"`
			ReportArtifactID      int64              `json:"report_artifact_id"`
			ReportArtifactURL     string             `json:"report_artifact_url"`
			Denials               []denialEvidence   `json:"denials"`
			Scenarios             []scenarioEvidence `json:"scenarios"`
			DraftPR               int                `json:"draft_pr"`
			DraftPRURL            string             `json:"draft_pr_url"`
			DraftHeadSHA          string             `json:"draft_head_sha"`
			DraftHeadRef          string             `json:"draft_head_ref"`
			DraftBaseRef          string             `json:"draft_base_ref"`
			DraftState            string             `json:"draft_state"`
			DraftIsDraft          bool               `json:"draft_is_draft"`
			OwnedResourceState    string             `json:"owned_resource_cleanup_state"`
		}{
			SchemaVersion: 5, SofaPR: p.Number, CandidateSHA: p.Head.SHA, PRBaseSHA: p.Base.SHA,
			DisposableBaseSHA: mainSHA, SuiteID: suite, CandidateDigest: v.bundle.CandidateDigest,
			ProducerRunID:      producer.ID,
			ProducerRunURL:     fmt.Sprintf("https://github.com/%s/actions/runs/%d", consumerRepo, producer.ID),
			RetainedArtifactID: retainedID, ConflictArtifactID: conflictID,
			ConflictArtifactURL: fmt.Sprintf("https://github.com/%s/actions/runs/%d/artifacts/%d", consumerRepo, producer.ID, conflictID),
			ConflictBranchHead:  strings.Repeat("b", 40),
			CandidateRunID:      r.ID, CandidateRunAttempt: r.RunAttempt,
			CandidateRunURL:       fmt.Sprintf("https://github.com/%s/actions/runs/%d", consumerRepo, r.ID),
			CandidateRunStartedAt: r.StartedAt, CandidateRunUpdatedAt: r.UpdatedAt,
			CandidateDurationMS: durationMS, ReportArtifactID: artifactID, Denials: denials, Scenarios: scenarios,
			ReportArtifactURL: fmt.Sprintf("https://github.com/%s/actions/runs/%d/artifacts/%d", consumerRepo, r.ID, artifactID),
			DraftPR:           pr.Number, DraftPRURL: pr.HTMLURL, DraftHeadSHA: pr.Head.SHA,
			DraftHeadRef: pr.Head.Ref, DraftBaseRef: pr.Base.Ref, DraftState: pr.State,
			DraftIsDraft: pr.Draft, OwnedResourceState: "retained_for_replay",
		}
		result.ProducerDurationMS, err = hostedDuration(producer)
		if err != nil {
			return err
		}
		encoded, err := json.Marshal(result)
		if err != nil {
			return errors.New("cannot encode trusted observer result")
		}
		file, err := os.OpenFile(out, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			return errors.New("cannot open trusted observer result")
		}
		_, writeErr := file.Write(append(encoded, '\n'))
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			return errors.New("cannot write trusted observer result")
		}
	}
	fmt.Printf("suite %s validated hosted run %d and draft disposable PR %d: %s\n", suite, r.ID, pr.Number, pr.HTMLURL)
	return nil
}

func expectedCaller(p pull, consumerBase string) string {
	return fmt.Sprintf(`name: sofa hosted E2E candidate
on:
  workflow_dispatch:
    inputs:
      sofa_pr: {type: string, required: false}
      candidate_sha: {type: string, required: false}
      base_sha: {type: string, required: false}
      source_run_id: {type: string, required: false}
      source_run_attempt: {type: string, required: false}
      mode: {type: string, required: false}
      producer_run_id: {type: string, required: false}
permissions: {}
jobs:
  candidate:
    if: inputs.mode == 'initial'
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
      publish_fault: before-publication
  deny-non-ready:
    if: inputs.mode == 'initial'
    permissions:
      contents: read
      actions: read
    uses: kevinmartin/sofa/.github/workflows/e2e-fake.yml@%s
    with:
      suite_id: %s
      scenario: denied
      denial_kind: non-ready
      candidate_sha: %s
      base_sha: %s
      disposable_base_sha: %s
      reconcile_candidate: false
  deny-completed-redelivery:
    if: inputs.mode == 'initial'
    permissions:
      contents: read
      actions: read
    uses: kevinmartin/sofa/.github/workflows/e2e-fake.yml@%s
    with:
      suite_id: %s
      scenario: denied
      denial_kind: completed-redelivery
      candidate_sha: %s
      base_sha: %s
      disposable_base_sha: %s
      reconcile_candidate: false
  recover:
    if: inputs.mode == 'recovery' && inputs.producer_run_id != ''
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
      reconcile_candidate: true
      producer_run_id: ${{ inputs.producer_run_id }}
      producer_run_attempt: '1'
`, p.Head.SHA, suiteID(p, consumerBase), p.Head.SHA, p.Base.SHA, consumerBase,
		p.Head.SHA, denialSuiteID(p, consumerBase, "non-ready"), p.Head.SHA, p.Base.SHA, consumerBase,
		p.Head.SHA, denialSuiteID(p, consumerBase, "completed-redelivery"), p.Head.SHA, p.Base.SHA, consumerBase,
		p.Head.SHA, suiteID(p, consumerBase), p.Head.SHA, p.Base.SHA, consumerBase)
}

func run(ctx context.Context, c client) error {
	manual := os.Getenv("SOFA_GATE_PR")
	var prs []pull
	if manual != "" {
		n, err := strconv.Atoi(manual)
		if err != nil || n < 1 {
			return errors.New("invalid sofa PR number")
		}
		p, err := c.currentPR(ctx, n)
		if err != nil {
			return err
		}
		prs = []pull{p}
	} else {
		list, err := c.listPRs(ctx)
		if err != nil {
			return err
		}
		prs = list
	}
	for _, listed := range prs {
		p, err := c.currentPR(ctx, listed.Number)
		if err != nil || p.Head.SHA != listed.Head.SHA || p.Base.SHA != listed.Base.SHA {
			return errors.New("sofa PR changed during observation")
		}
		if err := c.observe(ctx, p); err != nil {
			return fmt.Errorf("sofa PR %d: %w", p.Number, err)
		}
	}
	return nil
}

func main() {
	token := os.Getenv("GH_TOKEN")
	if token == "" || os.Getenv("GITHUB_REPOSITORY") != consumerRepo || os.Getenv("GITHUB_REF") != "refs/heads/main" {
		fmt.Fprintln(os.Stderr, "trusted observer identity unavailable")
		os.Exit(1)
	}
	httpClient := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 2 || req.URL.Scheme != "https" || strings.ContainsAny(req.URL.Host, "\r\n") {
			return errors.New("unsafe artifact redirect")
		}
		// The GitHub artifact API controls the redirect destination. Never
		// forward the repository credential to blob storage.
		req.Header.Del("Authorization")
		return nil
	}}
	c := client{http: httpClient, token: token, publisherToken: os.Getenv("SOFA_PUBLISH_TOKEN"), base: "https://api.github.com"}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	if err := run(ctx, c); err != nil {
		fmt.Fprintln(os.Stderr, "hosted gate observer:", err)
		os.Exit(1)
	}
}
