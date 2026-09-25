package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
)

func completionWakeContract(data []byte) error {
	text := string(data)
	onStart := strings.Index(text, "\non:\n")
	jobsStart := strings.Index(text, "\njobs:\n")
	if onStart < 0 || jobsStart < onStart {
		return fmt.Errorf("trusted gate workflow trigger or jobs missing")
	}
	triggers := text[onStart:jobsStart]
	for _, required := range []string{
		"  workflow_dispatch:\n",
		"  schedule:\n",
		"  workflow_run:\n",
		"    workflows: ['sofa hosted E2E candidate']",
		"    types: [completed]",
		"    branches: ['sofa-e2e/**']",
	} {
		if !strings.Contains(triggers, required) {
			return fmt.Errorf("trusted completion wake missing %q", required)
		}
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
	if err := completionWakeContract(data); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, old, replacement string }{
		{"rerun completion", "types: [completed]", "types: [requested]"},
		{"owned branch", "branches: ['sofa-e2e/**']", "branches: ['**']"},
		{"source repository", "head_repository.full_name == 'kevinmartin/sofa-disposable'", "head_repository.full_name == 'someone/else'"},
		{"trusted ref", "github.ref == 'refs/heads/main'", "github.ref == 'refs/heads/other'"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := strings.ReplaceAll(string(data), tc.old, tc.replacement)
			if mutated == string(data) {
				t.Fatal("mutation did not alter workflow")
			}
			if err := completionWakeContract([]byte(mutated)); err == nil {
				t.Fatal("unsafe trigger mutation passed")
			}
		})
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
