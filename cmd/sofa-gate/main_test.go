package main

import (
	"strings"
	"testing"
)

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
	id := suiteID(p)
	if len(id) > 40 || id != suiteID(p) || id == suiteID(testPull(head, strings.Repeat("c", 40))) {
		t.Fatalf("suite ID is not stable and base-bound: %q", id)
	}
	workflow := branchWorkflow(p, strings.Repeat("d", 40))
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
