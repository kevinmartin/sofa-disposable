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
	sofaRepo       = "kevinmartin/sofa"
	consumerRepo   = "kevinmartin/sofa-disposable"
	workflowPath   = ".github/workflows/sofa-gate.yml"
	fixturePath    = "fixture/greeting.go"
	maxArtifactZip = 8 << 20
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
	TotalCount int `json:"total_count"`
	Jobs       []struct {
		Name       string `json:"name"`
		Conclusion string `json:"conclusion"`
		Status     string `json:"status"`
		RunAttempt int    `json:"run_attempt"`
	} `json:"jobs"`
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
	want := map[string]string{"candidate / execute": "success", "candidate / verify": "success", "candidate / publish": "success", "candidate / assert-denied": "skipped"}
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

func (c client) downloadZIP(ctx context.Context, artifactID int64, denial bool) (map[string][]byte, error) {
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
	if denial {
		// upload-artifact strips the shared report/ prefix when the upload
		// path names a single file. The hosted archive contains denial.json.
		return unpackZIPExpected(zipBytes, map[string]bool{"denial.json": true})
	}
	return unpackZIP(zipBytes)
}

func unpackZIP(data []byte) (map[string][]byte, error) {
	return unpackZIPExpected(data, map[string]bool{
		"transport/identity.json": true, "transport/manifest.json": true,
		"candidate/execution.json": true, "candidate/bundle.json": true,
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
	SchemaVersion        int    `json:"schema_version"`
	SuiteID              string `json:"suite_id"`
	Scenario             string `json:"scenario"`
	CandidateSHA         string `json:"candidate_sha"`
	PRBaseSHA            string `json:"pr_base_sha"`
	DisposableBaseSHA    string `json:"disposable_base_sha"`
	AttemptID            string `json:"attempt_id"`
	Generation           int64  `json:"generation"`
	BundleGeneration     uint64 `json:"bundle_generation"`
	ProducerRunID        string `json:"producer_run_id"`
	CandidateDigest      string `json:"candidate_digest"`
	FakeAgent            string `json:"fake_agent"`
	FakePromptRequests   int    `json:"fake_prompt_requests"`
	ProviderRequests     int    `json:"provider_requests"`
	ProviderRequestBasis string `json:"provider_request_basis"`
	SimulatedPRNumber    int64  `json:"simulated_pr_number"`
	SimulatedPRURL       string `json:"simulated_pr_url"`
	SimulatedPRPostCount int    `json:"simulated_pr_post_count"`
	VerifiedCheckCount   int    `json:"verified_check_count"`
	RealPublicationOwner string `json:"real_publication_owner"`
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
	suite := suiteID(p, mainSHA)
	if v.id.Version != 1 || v.id.SuiteID != suite || v.id.Scenario != "edit" || v.id.CandidateSHA != p.Head.SHA || v.id.PRBaseSHA != p.Base.SHA || v.id.DisposableBaseSHA != mainSHA || v.id.FakeAgent != "fake-acp" || v.id.Generation != 1 || v.id.ProducerRunID != "" {
		return v, errors.New("hosted identity does not match current exact suite")
	}
	if v.report.SchemaVersion != 1 || v.report.SuiteID != suite || v.report.Scenario != "edit" || v.report.CandidateSHA != p.Head.SHA || v.report.PRBaseSHA != p.Base.SHA || v.report.DisposableBaseSHA != mainSHA || v.report.AttemptID != v.id.AttemptID || v.report.Generation != v.id.Generation || v.report.BundleGeneration != uint64(v.id.Generation) || v.report.ProducerRunID != "" || v.report.FakeAgent != "fake-acp" || v.report.FakePromptRequests != 1 || v.report.ProviderRequests != 0 || v.report.ProviderRequestBasis != "networkless-container-and-fake-peer-without-provider-client" || v.report.SimulatedPRPostCount != 1 || v.report.VerifiedCheckCount != 1 || v.report.RealPublicationOwner != "trusted-disposable-coordinator-only" {
		return v, errors.New("hosted scenario report does not match exact suite")
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
	}
	if err := decodeStrict(files["transport/manifest.json"], &manifest); err != nil {
		return v, err
	}
	if manifest.Version != 1 || manifest.Grant.Repository != consumerRepo || manifest.Grant.BaseSHA != mainSHA || manifest.Fence.AttemptID != v.id.AttemptID || manifest.Fence.Generation != 1 || manifest.Fence.Owner.RunID != strconv.FormatInt(r.ID, 10) || manifest.Fence.Owner.RunAttempt != r.RunAttempt {
		return v, errors.New("hosted manifest does not bind producing run")
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
		return nil // Coordinator has not dispatched this exact suite.
	}
	caller, err := c.content(ctx, workflowPath, branchSHA)
	if err != nil || string(caller) != expectedCaller(p, mainSHA) {
		return nil // The suite was built against a different disposable base.
	}
	r, ready, err := c.completedRun(ctx, branch, branchSHA)
	if err != nil || !ready {
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
	v, err := validateArtifact(files, p, r, mainSHA, baseContent)
	if err != nil {
		return err
	}
	denials := make([]denialEvidence, 0, 2)
	for _, kind := range []string{"non-ready", "completed-redelivery"} {
		denialSuite := denialSuiteID(p, mainSHA, kind)
		data, id, err := c.denialArtifact(ctx, r, denialSuite)
		if err != nil {
			return fmt.Errorf("%s denial artifact: %w", kind, err)
		}
		if err := validateDenialArtifact(data, p, r, mainSHA, kind); err != nil {
			return fmt.Errorf("%s denial artifact: %w", kind, err)
		}
		decision := map[string]string{"non-ready": "admission-denied", "completed-redelivery": "already-completed"}[kind]
		denials = append(denials, denialEvidence{kind, denialSuite, decision, id, fmt.Sprintf("https://github.com/%s/actions/runs/%d/artifacts/%d", consumerRepo, r.ID, id)})
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
			SchemaVersion         int              `json:"schema_version"`
			SofaPR                int              `json:"sofa_pr"`
			CandidateSHA          string           `json:"candidate_sha"`
			PRBaseSHA             string           `json:"pr_base_sha"`
			DisposableBaseSHA     string           `json:"disposable_base_sha"`
			SuiteID               string           `json:"suite_id"`
			CandidateDigest       string           `json:"candidate_digest"`
			CandidateRunID        int64            `json:"candidate_run_id"`
			CandidateRunAttempt   int              `json:"candidate_run_attempt"`
			CandidateRunURL       string           `json:"candidate_run_url"`
			CandidateRunStartedAt time.Time        `json:"candidate_run_started_at"`
			CandidateRunUpdatedAt time.Time        `json:"candidate_run_updated_at"`
			CandidateDurationMS   int64            `json:"candidate_duration_ms"`
			ReportArtifactID      int64            `json:"report_artifact_id"`
			ReportArtifactURL     string           `json:"report_artifact_url"`
			Denials               []denialEvidence `json:"denials"`
			DraftPR               int              `json:"draft_pr"`
			DraftPRURL            string           `json:"draft_pr_url"`
			DraftHeadSHA          string           `json:"draft_head_sha"`
			DraftHeadRef          string           `json:"draft_head_ref"`
			DraftBaseRef          string           `json:"draft_base_ref"`
			DraftState            string           `json:"draft_state"`
			DraftIsDraft          bool             `json:"draft_is_draft"`
			OwnedResourceState    string           `json:"owned_resource_cleanup_state"`
		}{
			SchemaVersion: 3, SofaPR: p.Number, CandidateSHA: p.Head.SHA, PRBaseSHA: p.Base.SHA,
			DisposableBaseSHA: mainSHA, SuiteID: suite, CandidateDigest: v.bundle.CandidateDigest,
			CandidateRunID: r.ID, CandidateRunAttempt: r.RunAttempt,
			CandidateRunURL:       fmt.Sprintf("https://github.com/%s/actions/runs/%d", consumerRepo, r.ID),
			CandidateRunStartedAt: r.StartedAt, CandidateRunUpdatedAt: r.UpdatedAt,
			CandidateDurationMS: durationMS, ReportArtifactID: artifactID, Denials: denials,
			ReportArtifactURL: fmt.Sprintf("https://github.com/%s/actions/runs/%d/artifacts/%d", consumerRepo, r.ID, artifactID),
			DraftPR:           pr.Number, DraftPRURL: pr.HTMLURL, DraftHeadSHA: pr.Head.SHA,
			DraftHeadRef: pr.Head.Ref, DraftBaseRef: pr.Base.Ref, DraftState: pr.State,
			DraftIsDraft: pr.Draft, OwnedResourceState: "retained_for_replay",
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
  deny-non-ready:
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
`, p.Head.SHA, suiteID(p, consumerBase), p.Head.SHA, p.Base.SHA, consumerBase,
		p.Head.SHA, denialSuiteID(p, consumerBase, "non-ready"), p.Head.SHA, p.Base.SHA, consumerBase,
		p.Head.SHA, denialSuiteID(p, consumerBase, "completed-redelivery"), p.Head.SHA, p.Base.SHA, consumerBase)
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
