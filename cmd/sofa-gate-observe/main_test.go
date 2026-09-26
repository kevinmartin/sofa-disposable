package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"go/format"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestCandidateCommandPinRejectsWorkflowDrift(t *testing.T) {
	const content = "name: reviewed candidate workflow\n"
	sha := strings.Repeat("a", 40)
	c := client{token: "read", base: "https://api.github.test", http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != "/repos/kevinmartin/sofa/contents/.github/workflows/e2e-fake.yml" || r.URL.Query().Get("ref") != sha {
			return nil, fmt.Errorf("unexpected candidate workflow request %s", r.URL.String())
		}
		data, _ := json.Marshal(gitContent{Content: base64.StdEncoding.EncodeToString([]byte(content)), Encoding: "base64"})
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(data)), Header: make(http.Header)}, nil
	})}}
	if err := c.verifyCandidateCommands(context.Background(), sha, hash([]byte(content))); err != nil {
		t.Fatal("reviewed command source rejected", err)
	}
	if err := c.verifyCandidateCommands(context.Background(), sha, hash([]byte(content+"changed"))); err == nil {
		t.Fatal("candidate command drift accepted")
	}
	if err := c.verifyCandidateCommands(context.Background(), "main", hash([]byte(content))); err == nil {
		t.Fatal("mutable candidate workflow ref accepted")
	}
}

func testPull() pull {
	var p pull
	p.Number = 2
	p.State = "open"
	p.Head.SHA = strings.Repeat("a", 40)
	p.Head.Repo.FullName = sofaRepo
	p.Base.SHA = strings.Repeat("b", 40)
	return p
}

func TestClosedFixtureDraftCannotRecreateResultRef(t *testing.T) {
	p := testPull()
	mainSHA := strings.Repeat("c", 40)
	requests := 0
	c := client{token: "read", publisherToken: "write", base: "https://api.github.test", http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests++
		if r.Method != http.MethodGet || r.URL.Path != "/repos/"+consumerRepo+"/pulls" || r.URL.Query().Get("state") != "all" {
			return nil, fmt.Errorf("unexpected request after closed fixture draft: %s %s", r.Method, r.URL.String())
		}
		data := []byte(`[{"number":39,"state":"closed"}]`)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(data)), Header: make(http.Header)}, nil
	})}}
	if _, err := c.publish(context.Background(), p, mainSHA, validated{}); err == nil || requests != 1 {
		t.Fatalf("closed draft permitted a result-ref write: requests=%d err=%v", requests, err)
	}
}

func testArtifacts(t *testing.T) (map[string][]byte, pull, workflowRun, string, []byte) {
	t.Helper()
	p := testPull()
	mainSHA := strings.Repeat("c", 40)
	r := workflowRun{ID: 42, RunAttempt: 1}
	base := []byte("package fixture\n\nfunc Greeting() string {\n    return \"Hello\"\n}\n")
	formatted, err := format.Source(base)
	if err != nil {
		t.Fatal(err)
	}
	id := identity{Version: 1, SuiteID: suiteID(p, mainSHA), Scenario: "edit", CandidateSHA: p.Head.SHA, PRBaseSHA: p.Base.SHA, DisposableBaseSHA: mainSHA, AttemptID: strings.Repeat("d", 64), Generation: 1, FakeAgent: "fake-acp"}
	b := bundle{Version: 1, Repository: consumerRepo, AttemptID: id.AttemptID, Generation: 1, BaseSHA: mainSHA, Files: []candidateFile{{Path: fixturePath, Operation: "update", Mode: "100644", BeforeSHA256: hash(base), Content: formatted}}}
	b.CandidateDigest, err = digestBundle(b)
	if err != nil {
		t.Fatal(err)
	}
	report := report{SchemaVersion: 1, SuiteID: id.SuiteID, Scenario: "edit", CandidateSHA: id.CandidateSHA, PRBaseSHA: id.PRBaseSHA, DisposableBaseSHA: mainSHA, AttemptID: id.AttemptID, Generation: 1, BundleGeneration: 1, CandidateDigest: b.CandidateDigest, FakeAgent: "fake-acp", FakePromptRequests: 1, ProviderRequests: 0, ProviderRequestBasis: "networkless-container-and-fake-peer-without-provider-client", SimulatedPRNumber: 1, SimulatedPRPostCount: 1, VerifiedCheckCount: 1, RealPublicationOwner: "trusted-disposable-coordinator-only"}
	marshal := func(v any) []byte {
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	files := map[string][]byte{
		"transport/identity.json": marshal(id),
		"candidate/bundle.json":   marshal(b),
		"report/scenario.json":    marshal(report),
		"transport/manifest.json": marshal(map[string]any{
			"version": 1,
			"grant":   map[string]any{"repository": consumerRepo, "base_sha": mainSHA},
			"fence":   map[string]any{"attempt_id": id.AttemptID, "generation": 1, "owner": map[string]any{"run_id": "42", "run_attempt": 1}},
		}),
		"candidate/execution.json": marshal(map[string]any{"version": 1, "used_agent": true, "prompt_requests": 1, "model_calls": nil, "candidate_digest": b.CandidateDigest}),
		"evidence/checks.json":     marshal([]map[string]any{{"version": 1, "name": "go-test", "candidate_digest": b.CandidateDigest, "passed": true}}),
		"report/publication.json":  marshal(map[string]any{"schema_version": 1, "simulation": "fake-github-transport", "candidate_digest": b.CandidateDigest, "base_sha": mainSHA, "attempt_id": id.AttemptID, "generation": 1, "pr_number": 1, "pr_posts": 1, "provider_requests": 0}),
	}
	return files, p, r, mainSHA, base
}

func TestValidateArtifactRejectsHostileOrStaleData(t *testing.T) {
	files, p, r, mainSHA, base := testArtifacts(t)
	if _, err := validateArtifact(files, p, r, mainSHA, base); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(map[string][]byte)
	}{
		{"duplicate JSON key", func(f map[string][]byte) {
			f["transport/identity.json"] = append(bytes.TrimSuffix(f["transport/identity.json"], []byte("}")), []byte(`,"suite_id":"evil"}`)...)
		}},
		{"stale run owner", func(f map[string][]byte) {
			f["transport/manifest.json"] = bytes.ReplaceAll(f["transport/manifest.json"], []byte(`"run_id":"42"`), []byte(`"run_id":"41"`))
		}},
		{"stale candidate", func(f map[string][]byte) {
			f["transport/identity.json"] = bytes.ReplaceAll(f["transport/identity.json"], []byte(p.Head.SHA), []byte(strings.Repeat("e", 40)))
		}},
		{"wrong fixture path", func(f map[string][]byte) {
			f["candidate/bundle.json"] = bytes.ReplaceAll(f["candidate/bundle.json"], []byte(fixturePath), []byte(".github/workflows/evil.yml"))
		}},
		{"wrong content", func(f map[string][]byte) {
			f["candidate/bundle.json"] = bytes.ReplaceAll(f["candidate/bundle.json"], []byte(base64.StdEncoding.EncodeToString([]byte("package fixture\n\nfunc Greeting() string {\n\treturn \"Hello\"\n}\n"))), []byte(base64.StdEncoding.EncodeToString([]byte("package fixture\n\nfunc Greeting() string {\n\treturn \"evil\"\n}\n"))))
		}},
		{"model calls claimed", func(f map[string][]byte) {
			f["candidate/execution.json"] = bytes.ReplaceAll(f["candidate/execution.json"], []byte(`"model_calls":null`), []byte(`"model_calls":1`))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copyFiles := make(map[string][]byte, len(files))
			for k, v := range files {
				copyFiles[k] = append([]byte(nil), v...)
			}
			tc.mutate(copyFiles)
			if _, err := validateArtifact(copyFiles, p, r, mainSHA, base); err == nil {
				t.Fatal("hostile artifact accepted")
			}
		})
	}
}

func TestValidateDenialArtifactRequiresExactIdentityAndZeroRequests(t *testing.T) {
	p := testPull()
	mainSHA := strings.Repeat("c", 40)
	r := workflowRun{ID: 42, RunAttempt: 1}
	for _, tc := range []struct{ kind, decision string }{{"non-ready", "admission-denied"}, {"completed-redelivery", "already-completed"}} {
		t.Run(tc.kind, func(t *testing.T) {
			d := denialReport{SchemaVersion: 1, SuiteID: denialSuiteID(p, mainSHA, tc.kind), Scenario: "denied", DenialKind: tc.kind, Decision: tc.decision,
				CandidateSHA: p.Head.SHA, PRBaseSHA: p.Base.SHA, DisposableBaseSHA: mainSHA, RunID: "42", RunAttempt: 1,
				SkippedJobs: []string{"execute", "verify", "publish"}}
			encode := func(v denialReport) []byte {
				b, err := json.Marshal(v)
				if err != nil {
					t.Fatal(err)
				}
				return b
			}
			if err := validateDenialArtifact(encode(d), p, r, mainSHA, tc.kind); err != nil {
				t.Fatal(err)
			}
			for _, mutate := range []func(*denialReport){
				func(d *denialReport) { d.SuiteID = suiteID(p, mainSHA) },
				func(d *denialReport) { d.Decision = "allowed" },
				func(d *denialReport) { d.CandidateSHA = strings.Repeat("e", 40) },
				func(d *denialReport) { d.RunID = "41" },
				func(d *denialReport) { d.FakePromptRequests = 1 },
				func(d *denialReport) { d.ProviderRequests = 1 },
				func(d *denialReport) { d.PublicationWrites = 1 },
				func(d *denialReport) { d.WriteCredentials = 1 },
				func(d *denialReport) { d.SkippedJobs = []string{"execute", "verify"} },
			} {
				bad := d
				mutate(&bad)
				if err := validateDenialArtifact(encode(bad), p, r, mainSHA, tc.kind); err == nil {
					t.Fatal("invalid denial accepted", bad)
				}
			}
		})
	}
}

func TestUnpackZIPRequiresExactBoundedEntries(t *testing.T) {
	files, _, _, _, _ := testArtifacts(t)
	makeZIP := func(extra string) []byte {
		var buf bytes.Buffer
		w := zip.NewWriter(&buf)
		for name, content := range files {
			f, err := w.Create(name)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.Write(content); err != nil {
				t.Fatal(err)
			}
		}
		if extra != "" {
			f, err := w.Create(extra)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = f.Write([]byte("bad"))
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	if got, err := unpackZIP(makeZIP("")); err != nil || len(got) != 7 {
		t.Fatalf("valid archive rejected: %v", err)
	}
	for _, extra := range []string{"../outside", "other.json", "candidate/bundle.json"} {
		if _, err := unpackZIP(makeZIP(extra)); err == nil {
			t.Fatalf("accepted extra or duplicate entry %q", extra)
		}
	}
}

func TestDenialZIPUsesHostedSingleFileLayout(t *testing.T) {
	makeZIP := func(name string) []byte {
		var buf bytes.Buffer
		w := zip.NewWriter(&buf)
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(`{"schema_version":1}`)); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	want := map[string]bool{"denial.json": true}
	if files, err := unpackZIPExpected(makeZIP("denial.json"), want); err != nil || len(files) != 1 {
		t.Fatalf("hosted single-file denial rejected: %v", err)
	}
	if _, err := unpackZIPExpected(makeZIP("report/denial.json"), want); err == nil {
		t.Fatal("accepted a denial archive with an unexpected path")
	}
}

func expectedJobs() jobList {
	want := []struct{ name, conclusion string }{
		{"candidate / execute", "success"}, {"candidate / verify", "success"}, {"candidate / publish", "success"}, {"candidate / assert-denied", "skipped"},
	}
	for _, job := range []string{"deny-non-ready", "deny-completed-redelivery"} {
		for _, name := range []string{"execute", "verify", "publish"} {
			want = append(want, struct{ name, conclusion string }{job + " / " + name, "skipped"})
		}
		want = append(want, struct{ name, conclusion string }{job + " / assert-denied", "success"})
	}
	j := jobList{TotalCount: len(want)}
	for _, item := range want {
		j.Jobs = append(j.Jobs, hostedJob{Name: item.name, Conclusion: item.conclusion, Status: "completed", RunAttempt: 1})
	}
	return j
}

func TestScenarioEvidenceRequiresTimedExactJobs(t *testing.T) {
	start := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	fault := expectedJobs()
	for i := range fault.Jobs {
		fault.Jobs[i].StartedAt = start
		fault.Jobs[i].CompletedAt = start.Add(12 * time.Second)
		if fault.Jobs[i].Name == "candidate / publish" {
			fault.Jobs[i].Conclusion = "failure"
		}
	}
	recovery := jobList{TotalCount: 4, Jobs: []hostedJob{
		{Name: "recover / execute", Status: "completed", Conclusion: "skipped", RunAttempt: 1},
		{Name: "recover / verify", Status: "completed", Conclusion: "success", RunAttempt: 1},
		{Name: "recover / publish", Status: "completed", Conclusion: "success", RunAttempt: 1, StartedAt: start, CompletedAt: start.Add(9 * time.Second)},
		{Name: "recover / assert-denied", Status: "completed", Conclusion: "skipped", RunAttempt: 1},
	}}
	serve := func(fault, recovery jobList) client {
		return client{token: "read", base: "https://api.github.test", http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
			var payload jobList
			switch r.URL.Path {
			case "/repos/kevinmartin/sofa-disposable/actions/runs/41/jobs":
				payload = fault
			case "/repos/kevinmartin/sofa-disposable/actions/runs/42/jobs":
				payload = recovery
			default:
				return nil, fmt.Errorf("unexpected jobs path %s", r.URL.Path)
			}
			data, _ := json.Marshal(payload)
			return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(data)), Header: make(http.Header)}, nil
		})}}
	}
	producer, recovered := workflowRun{ID: 41}, workflowRun{ID: 42}
	evidence, err := serve(fault, recovery).scenarioEvidence(context.Background(), producer, recovered)
	if err != nil || len(evidence) != 5 || evidence[0].JobDurationMS != 12000 || evidence[4].JobDurationMS != 9000 || evidence[0].FakePromptRequests != 1 || evidence[4].RunID != 42 {
		t.Fatalf("exact scenario timings unavailable: %+v, %v", evidence, err)
	}
	fault.Jobs[0].CompletedAt = fault.Jobs[0].StartedAt
	if _, err := serve(fault, recovery).scenarioEvidence(context.Background(), producer, recovered); err == nil {
		t.Fatal("untimed hosted scenario accepted")
	}
}

func TestValidJobsRequiresEditAndBothDenials(t *testing.T) {
	j := expectedJobs()
	if !validJobs(j) {
		t.Fatal("valid jobs rejected")
	}
	j.Jobs[1].Conclusion = "skipped"
	if validJobs(j) {
		t.Fatal("skipped verify accepted")
	}
	j.Jobs[1].Conclusion = "success"
	j.Jobs[3].Conclusion = "success"
	if validJobs(j) {
		t.Fatal("unexpectedly executed denial assertion accepted")
	}
	j.Jobs[3].Conclusion = "skipped"
	j.Jobs = j.Jobs[:len(j.Jobs)-1]
	if validJobs(j) {
		t.Fatal("missing completed-redelivery assertion accepted")
	}
	j = expectedJobs()
	j.Jobs[len(j.Jobs)-1].Conclusion = "skipped"
	if validJobs(j) {
		t.Fatal("skipped completed-redelivery assertion accepted")
	}
	j = expectedJobs()
	j.Jobs[7].Conclusion = "failure"
	if validJobs(j) {
		t.Fatal("failed non-ready assertion accepted")
	}
}

func TestCompletedRunSelectsNewestExactSuiteBeforeCheckingOutcome(t *testing.T) {
	branch := "sofa-e2e/p2-test"
	sha := strings.Repeat("a", 40)
	start := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	older := workflowRun{ID: 41, Status: "completed", Conclusion: "success", Event: "workflow_dispatch", Path: workflowPath, HeadBranch: branch, HeadSHA: sha, RunAttempt: 1, CreatedAt: start, StartedAt: start.Add(time.Second), UpdatedAt: start.Add(time.Minute)}
	newer := older
	newer.ID = 42
	newer.CreatedAt = start.Add(time.Minute)
	newer.StartedAt = newer.CreatedAt.Add(time.Second)
	newer.UpdatedAt = newer.CreatedAt.Add(time.Minute)
	for _, tc := range []struct {
		name  string
		runs  []workflowRun
		ready bool
		id    int64
	}{
		{"newer failure after older success", []workflowRun{older, func() workflowRun { r := newer; r.Conclusion = "failure"; return r }()}, false, 0},
		{"newer cancellation before older success", []workflowRun{func() workflowRun { r := newer; r.Conclusion = "cancelled"; return r }(), older}, false, 0},
		{"newer active run after older success", []workflowRun{older, func() workflowRun { r := newer; r.Status = "in_progress"; r.Conclusion = ""; return r }()}, false, 0},
		{"newer rerun after older success", []workflowRun{older, func() workflowRun { r := newer; r.RunAttempt = 2; return r }()}, false, 0},
		{"newer success after older success", []workflowRun{older, newer}, true, newer.ID},
		{"same timestamp chooses higher ID", []workflowRun{older, func() workflowRun { r := newer; r.CreatedAt = start; return r }()}, true, newer.ID},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			listed, err := json.Marshal(runList{TotalCount: len(tc.runs), Runs: tc.runs})
			if err != nil {
				t.Fatal(err)
			}
			c := client{token: "read", base: "https://api.github.test", http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				var body []byte
				switch {
				case strings.HasSuffix(r.URL.Path, "/actions/workflows/sofa-gate.yml/runs"):
					body = listed
				case strings.HasSuffix(r.URL.Path, fmt.Sprintf("/actions/runs/%d/jobs", tc.id)) && tc.ready:
					body, _ = json.Marshal(expectedJobs())
				default:
					t.Errorf("unexpected request %s", r.URL.String())
					return nil, fmt.Errorf("unexpected request")
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header), Request: r}, nil
			})}}
			got, ready, err := c.completedRun(context.Background(), branch, sha)
			if err != nil || ready != tc.ready || (ready && got.ID != tc.id) {
				t.Fatalf("completedRun = (%+v, %t, %v), want ready=%t id=%d", got, ready, err, tc.ready, tc.id)
			}
			wantCalls := 1
			if tc.ready {
				wantCalls = 2
			}
			if calls != wantCalls {
				t.Fatalf("unexpected request count: got %d, want %d", calls, wantCalls)
			}
		})
	}
}

func TestHostedDurationRequiresMeasuredBoundedTimestamps(t *testing.T) {
	start := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	valid := workflowRun{CreatedAt: start, StartedAt: start.Add(time.Second), UpdatedAt: start.Add(91 * time.Second)}
	if got, err := hostedDuration(valid); err != nil || got != 90000 {
		t.Fatalf("valid hosted duration = %d, %v", got, err)
	}
	for _, tc := range []struct {
		name string
		edit func(*workflowRun)
	}{
		{"missing start", func(r *workflowRun) { r.StartedAt = time.Time{} }},
		{"start before creation", func(r *workflowRun) { r.StartedAt = start.Add(-time.Second) }},
		{"zero duration", func(r *workflowRun) { r.UpdatedAt = r.StartedAt }},
		{"reversed duration", func(r *workflowRun) { r.UpdatedAt = r.StartedAt.Add(-time.Second) }},
		{"submillisecond duration", func(r *workflowRun) { r.UpdatedAt = r.StartedAt.Add(time.Microsecond) }},
		{"over six hours", func(r *workflowRun) { r.UpdatedAt = r.StartedAt.Add(6*time.Hour + time.Millisecond) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := valid
			tc.edit(&r)
			if _, err := hostedDuration(r); err == nil {
				t.Fatal("accepted invalid hosted duration")
			}
		})
	}
}

func TestReportArtifactReturnsValidatedSourceID(t *testing.T) {
	files, p, _, mainSHA, _ := testArtifacts(t)
	var zipped bytes.Buffer
	w := zip.NewWriter(&zipped)
	for path, content := range files {
		entry, err := w.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write(content); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	r := workflowRun{ID: 42, RunAttempt: 1}
	for _, sourceID := range []int64{42, 41} {
		t.Run(fmt.Sprint(sourceID), func(t *testing.T) {
			calls := 0
			c := client{token: "read", base: "https://api.github.test", http: &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				var body []byte
				switch {
				case strings.HasSuffix(req.URL.Path, "/artifacts"):
					body = []byte(fmt.Sprintf(`{"total_count":1,"artifacts":[{"id":77,"name":%q,"expired":false,"size_in_bytes":%d,"workflow_run":{"id":%d}}]}`, fmt.Sprintf("sofa-e2e-report-%s-42-1", suiteID(p, mainSHA)), zipped.Len(), sourceID))
				case strings.HasSuffix(req.URL.Path, "/artifacts/77/zip"):
					body = zipped.Bytes()
				default:
					t.Errorf("unexpected request %s", req.URL)
				}
				return &http.Response{StatusCode: 200, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header), Request: req}, nil
			})}}
			got, id, err := c.reportArtifact(context.Background(), r, suiteID(p, mainSHA))
			if sourceID == r.ID {
				if err != nil || id != 77 || len(got) != len(files) || calls != 2 {
					t.Fatalf("valid artifact result: id=%d files=%d calls=%d err=%v", id, len(got), calls, err)
				}
			} else if err == nil || calls != 1 {
				t.Fatalf("wrong source accepted: id=%d calls=%d err=%v", id, calls, err)
			}
		})
	}
}

func TestPublicationWritesUseOnlyPublisherCredential(t *testing.T) {
	requests := 0
	c := client{token: "read-token", publisherToken: "publisher-token", base: "https://api.github.test", http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		requests++
		if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer publisher-token" {
			t.Fatal("publication did not use the isolated publisher credential")
		}
		return &http.Response{StatusCode: http.StatusCreated, Body: io.NopCloser(strings.NewReader(`{}`)), Header: make(http.Header)}, nil
	})}}
	if err := c.post(context.Background(), "/repos/"+consumerRepo+"/git/trees", map[string]string{"path": fixturePath}, nil); err != nil || requests != 1 {
		t.Fatalf("expected one scoped publication write: requests=%d err=%v", requests, err)
	}
	c.publisherToken = ""
	if err := c.post(context.Background(), "/repos/"+consumerRepo+"/git/trees", nil, nil); err == nil || requests != 1 {
		t.Fatalf("missing publisher credential did not fail before write: requests=%d err=%v", requests, err)
	}
}

func TestExistingDraftReconcilesWithoutWrite(t *testing.T) {
	p := testPull()
	mainSHA := strings.Repeat("c", 40)
	branchSHA := strings.Repeat("e", 40)
	branch := "sofa-e2e-result/" + suiteID(p, mainSHA)
	base := []byte("package fixture\n\nfunc Greeting() string {\n    return \"Hello\"\n}\n")
	formatted, _ := format.Source(base)
	v := validated{report: report{CandidateSHA: p.Head.SHA}, bundle: bundle{CandidateDigest: strings.Repeat("f", 64)}, content: formatted}
	posts := 0
	extraFile := false
	httpClient := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.Method == "POST" {
			posts++
			t.Errorf("unexpected write %s", r.URL.Path)
			return nil, fmt.Errorf("unexpected write")
		}
		var body string
		switch {
		case strings.Contains(r.URL.Path, "/git/ref/heads/"):
			body = fmt.Sprintf(`{"object":{"sha":%q}}`, branchSHA)
		case strings.Contains(r.URL.Path, "/git/commits/"):
			if strings.HasSuffix(r.URL.Path, branchSHA) {
				body = fmt.Sprintf(`{"sha":%q,"message":%q,"tree":{"sha":%q},"parents":[{"sha":%q}]}`, branchSHA, marker(suiteID(p, mainSHA), v), strings.Repeat("2", 40), mainSHA)
			} else {
				body = fmt.Sprintf(`{"sha":%q,"tree":{"sha":%q}}`, mainSHA, strings.Repeat("1", 40))
			}
		case strings.Contains(r.URL.Path, "/git/trees/"):
			blob := strings.Repeat("3", 40)
			if strings.HasSuffix(r.URL.Path, strings.Repeat("2", 40)) {
				blob = strings.Repeat("4", 40)
			}
			body = fmt.Sprintf(`{"truncated":false,"tree":[{"path":%q,"mode":"100644","type":"blob","sha":%q}]}`, fixturePath, blob)
			if extraFile && strings.HasSuffix(r.URL.Path, strings.Repeat("2", 40)) {
				body = fmt.Sprintf(`{"truncated":false,"tree":[{"path":%q,"mode":"100644","type":"blob","sha":%q},{"path":"unrelated.txt","mode":"100644","type":"blob","sha":%q}]}`, fixturePath, blob, strings.Repeat("5", 40))
			}
		case strings.Contains(r.URL.Path, "/contents/"):
			body = fmt.Sprintf(`{"encoding":"base64","content":%q}`, base64.StdEncoding.EncodeToString(formatted))
		case strings.Contains(r.URL.Path, "/pulls"):
			if got := r.URL.Query().Get("head"); got != "kevinmartin:"+branch {
				t.Fatalf("draft lookup used invalid GitHub head filter %q", got)
			}
			body = fmt.Sprintf(`[{"number":7,"draft":true,"state":"open","html_url":"https://github.com/%s/pull/7","head":{"ref":%q,"sha":%q,"repo":{"full_name":%q}},"base":{"ref":"main"}}]`, consumerRepo, branch, branchSHA, consumerRepo)
		default:
			t.Errorf("unexpected read %s", r.URL.Path)
			return nil, fmt.Errorf("unexpected read")
		}
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header), Request: r}, nil
	})}
	c := client{http: httpClient, token: "test", publisherToken: "publisher-test", base: "https://api.github.test"}
	pr, err := c.publish(context.Background(), p, mainSHA, v)
	if err != nil || pr.Number != 7 || posts != 0 {
		t.Fatalf("idempotent draft reconciliation failed: pr=%+v err=%v posts=%d", pr, err, posts)
	}
	extraFile = true
	if _, err := c.publish(context.Background(), p, mainSHA, v); err == nil || posts != 0 {
		t.Fatal("existing branch with unrelated file was accepted")
	}
}

func TestPilotArtifactWhenPresent(t *testing.T) {
	root := os.Getenv("SOFA_E2E_PILOT_ARTIFACT")
	if root == "" {
		t.Skip("optional exact hosted pilot artifact path not supplied")
	}
	files := map[string][]byte{}
	for _, path := range []string{"transport/identity.json", "transport/manifest.json", "candidate/execution.json", "candidate/bundle.json", "evidence/checks.json", "report/publication.json", "report/scenario.json"} {
		content, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		files[path] = content
	}
	var id identity
	if err := json.Unmarshal(files["transport/identity.json"], &id); err != nil {
		t.Fatal(err)
	}
	p := testPull()
	p.Head.SHA, p.Base.SHA = id.CandidateSHA, id.PRBaseSHA
	base, err := os.ReadFile("../../fixture/greeting.go")
	if err != nil {
		t.Fatal(err)
	}
	// Historical pilot suites used a two-SHA suite ID. Rebind the expected
	// name in this optional parser probe; current hosted runs use three SHAs.
	id.SuiteID = suiteID(p, id.DisposableBaseSHA)
	files["transport/identity.json"], _ = json.Marshal(id)
	var report report
	_ = json.Unmarshal(files["report/scenario.json"], &report)
	report.SuiteID = id.SuiteID
	files["report/scenario.json"], _ = json.Marshal(report)
	if _, err := validateArtifact(files, p, workflowRun{ID: 36063701681, RunAttempt: 1}, id.DisposableBaseSHA, base); err != nil {
		t.Fatal(err)
	}
}
