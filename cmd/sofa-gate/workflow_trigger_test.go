package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
)

func completionWakeContract(data, wakeup []byte) error {
	text := string(data)
	wake := string(wakeup)
	onStart := strings.Index(text, "\non:\n")
	jobsStart := strings.Index(text, "\njobs:\n")
	if onStart < 0 || jobsStart < onStart {
		return fmt.Errorf("trusted gate workflow trigger or jobs missing")
	}
	triggers := text[onStart:jobsStart]
	for _, required := range []string{
		"  workflow_call:\n",
		"  workflow_dispatch:\n",
		"  schedule:\n",
	} {
		if !strings.Contains(triggers, required) {
			return fmt.Errorf("trusted coordinator missing %q", required)
		}
	}
	if strings.Contains(triggers, "  workflow_run:\n") {
		return fmt.Errorf("completion event must use a separate workflow")
	}
	for _, required := range []string{
		"name: sofa hosted E2E completion wakeup",
		"  workflow_run:\n",
		"    workflows: ['sofa hosted E2E coordinator', 'sofa hosted E2E candidate']",
		"    types: [completed]",
		"    branches: ['sofa-e2e/**']",
		"github.repository == 'kevinmartin/sofa-disposable'",
		"github.ref == 'refs/heads/main'",
		"github.event.repository.fork == false",
		"github.event.workflow_run.name == 'sofa hosted E2E candidate'",
		"github.event.workflow_run.head_repository.full_name == 'kevinmartin/sofa-disposable'",
		"github.event.workflow_run.event == 'workflow_dispatch'",
		"github.event.workflow_run.path == '.github/workflows/sofa-gate.yml'",
		"startsWith(github.event.workflow_run.head_branch, 'sofa-e2e/')",
		"uses: ./.github/workflows/sofa-gate.yml",
		"secrets: inherit",
		"actions: write",
		"issues: write",
	} {
		if !strings.Contains(wake, required) {
			return fmt.Errorf("trusted completion wake missing %q", required)
		}
	}
	if strings.Contains(wake, "actions/checkout@") || strings.Contains(wake, "\n      run:") || strings.Contains(wake, "ref: ${{ github.event.workflow_run") {
		return fmt.Errorf("completion wake executes untrusted candidate data")
	}
	coordinate := strings.Index(text, "\n  coordinate:\n")
	observe := strings.Index(text, "\n  observe:\n")
	if coordinate < jobsStart || observe < coordinate {
		return fmt.Errorf("trusted coordinator or observer job missing")
	}
	for name, job := range map[string]string{
		"coordinate": text[coordinate:observe],
		"observe":    text[observe:],
	} {
		conditionStart := strings.Index(job, "    if: >-\n")
		conditionEnd := strings.Index(job, "    environment:")
		if conditionStart < 0 || conditionEnd < conditionStart {
			return fmt.Errorf("%s has no bounded job condition", name)
		}
		condition := strings.Join(strings.Fields(job[conditionStart:conditionEnd]), " ")
		for _, required := range []string{
			"github.repository == 'kevinmartin/sofa-disposable'",
			"github.ref == 'refs/heads/main'",
			"github.event.repository.fork == false",
			"github.event_name == 'workflow_dispatch'",
			"github.event_name == 'schedule'",
			"github.event_name == 'workflow_run'",
			"github.event.workflow_run.name == 'sofa hosted E2E candidate'",
			"github.event.workflow_run.head_repository.full_name == 'kevinmartin/sofa-disposable'",
			"github.event.workflow_run.event == 'workflow_dispatch'",
			"github.event.workflow_run.path == '.github/workflows/sofa-gate.yml'",
			"startsWith(github.event.workflow_run.head_branch, 'sofa-e2e/')",
		} {
			if !strings.Contains(condition, required) {
				return fmt.Errorf("%s trigger guard missing %q", name, required)
			}
		}
		if !strings.Contains(job, "persist-credentials: false") ||
			strings.Contains(job, "ref: ${{ github.event.workflow_run") ||
			strings.Contains(job, "repository: ${{ github.event.workflow_run") {
			return fmt.Errorf("%s may check out candidate code with trusted credentials", name)
		}
	}
	if candidate := branchWorkflow(testPull(strings.Repeat("a", 40), strings.Repeat("b", 40)), strings.Repeat("c", 40)); strings.Contains(candidate, "workflow_run:") || !strings.Contains(candidate, "name: sofa hosted E2E candidate") {
		return fmt.Errorf("suite-owned candidate caller can trigger itself")
	}
	return nil
}

func TestCompletionWakeUsesTrustedDefaultBranchOnly(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/sofa-gate.yml")
	if err != nil {
		t.Fatal(err)
	}
	wakeup, err := os.ReadFile("../../.github/workflows/sofa-gate-wakeup.yml")
	if err != nil {
		t.Fatal(err)
	}
	if err := completionWakeContract(data, wakeup); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, old, replacement string }{
		{"rerun completion", "types: [completed]", "types: [requested]"},
		{"owned branch", "branches: ['sofa-e2e/**']", "branches: ['**']"},
		{"source repository", "head_repository.full_name == 'kevinmartin/sofa-disposable'", "head_repository.full_name == 'someone/else'"},
		{"trusted ref", "github.ref == 'refs/heads/main'", "github.ref == 'refs/heads/other'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := strings.ReplaceAll(string(wakeup), tc.old, tc.replacement)
			if mutated == string(wakeup) {
				t.Fatal("mutation did not alter workflow")
			}
			if err := completionWakeContract(data, []byte(mutated)); err == nil {
				t.Fatal("unsafe trigger mutation passed")
			}
		})
	}
}

func TestTrustedGateKeepsPublisherProjectAndStatusCredentialsInSeparateJobs(t *testing.T) {
	data, err := os.ReadFile("../../.github/workflows/sofa-gate.yml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	names := []string{"coordinate", "observe", "complete-project", "cleanup-owned", "status"}
	jobs := make(map[string]string, len(names))
	for i, name := range names {
		start := strings.Index(text, "\n  "+name+":\n")
		if start < 0 {
			t.Fatalf("trusted %s job missing", name)
		}
		end := len(text)
		if i+1 < len(names) {
			end = strings.Index(text, "\n  "+names[i+1]+":\n")
		}
		if end <= start {
			t.Fatalf("trusted %s job boundary invalid", name)
		}
		jobs[name] = text[start:end]
	}
	if !strings.Contains(jobs["observe"], "SOFA_PUBLISH_TOKEN: ${{ secrets.SOFA_PUBLISH_TOKEN }}") || !strings.Contains(jobs["complete-project"], "SOFA_PROJECTS_TOKEN: ${{ secrets.SOFA_PROJECTS_TOKEN }}") || !strings.Contains(jobs["cleanup-owned"], "SOFA_PUBLISH_TOKEN: ${{ secrets.SOFA_PUBLISH_TOKEN }}") || !strings.Contains(jobs["status"], "SOFA_GATE_APP_PRIVATE_KEY: ${{ secrets.SOFA_GATE_APP_PRIVATE_KEY }}") {
		t.Fatal("trusted credential owner job missing")
	}
	for _, tc := range []struct {
		name      string
		forbidden []string
	}{
		{"observe", []string{"SOFA_PROJECTS_TOKEN", "SOFA_GATE_APP_PRIVATE_KEY", "issues: write"}},
		{"complete-project", []string{"SOFA_PUBLISH_TOKEN", "SOFA_GATE_APP_PRIVATE_KEY"}},
		{"cleanup-owned", []string{"SOFA_PROJECTS_TOKEN", "SOFA_GATE_APP_PRIVATE_KEY", "issues: write"}},
		{"status", []string{"SOFA_PUBLISH_TOKEN", "SOFA_PROJECTS_TOKEN", "issues: write"}},
	} {
		for _, secret := range tc.forbidden {
			if strings.Contains(jobs[tc.name], secret) {
				t.Fatalf("%s job gained %s", tc.name, secret)
			}
		}
	}
	if !strings.Contains(jobs["complete-project"], "needs: observe") || !strings.Contains(jobs["cleanup-owned"], "needs: complete-project") || !strings.Contains(jobs["status"], "needs: cleanup-owned") || !strings.Contains(jobs["status"], "SOFA_GATE_RESULT_PATH: gate-results-cleaned.jsonl") {
		t.Fatal("owned resource cleanup no longer precedes App success")
	}
	for _, artifact := range []string{"observed", "complete", "cleaned"} {
		name := "sofa-e2e-" + artifact + "-${{ github.run_id }}"
		if strings.Count(text, name) != 2 || strings.Contains(text, name+"-${{ github.run_attempt }}") {
			t.Fatalf("trusted %s artifact is not stable across failed-job retries", artifact)
		}
	}
	if strings.Count(text, "overwrite: true") != 3 {
		t.Fatal("trusted artifact rerun overwrite is not explicit")
	}
}

func TestCompletionWakeDiscoversLivePRsInsteadOfUsingEventIdentity(t *testing.T) {
	t.Setenv("GITHUB_EVENT_NAME", "workflow_run")
	t.Setenv("GITHUB_EVENT_PATH", t.TempDir()+"/absent-event.json")
	t.Setenv("SOFA_GATE_PR", "")
	t.Setenv("SOFA_GATE_HEAD", "")
	t.Setenv("SOFA_GATE_BASE", "")
	reads := 0
	a := api{token: "read-token", http: &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		reads++
		if r.Method != http.MethodGet || r.URL.Path != "/repos/"+sofaRepo+"/pulls" || r.URL.RawQuery != "state=open&per_page=100" {
			t.Fatalf("wake made an unexpected API call: %s %s", r.Method, r.URL.String())
		}
		return testResponse(http.StatusOK, "[]"), nil
	})}}
	if err := run(context.Background(), a); err != nil || reads != 1 {
		t.Fatalf("completion wake did not scan live PRs: reads=%d err=%v", reads, err)
	}
}
