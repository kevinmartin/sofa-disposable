// Package gatecaller creates the fixed, suite-owned hosted workflow content.
package gatecaller

import (
	"crypto/sha256"
	"fmt"
)

type Pull struct {
	Number           int
	HeadSHA, BaseSHA string
}

func SuiteID(p Pull, consumerBase string) string {
	digest := sha256.Sum256([]byte(p.HeadSHA + ":" + p.BaseSHA + ":" + consumerBase))
	return fmt.Sprintf("p%d-%x", p.Number, digest[:12])
}

func denialSuiteID(p Pull, consumerBase, kind string) string {
	digest := sha256.Sum256([]byte(SuiteID(p, consumerBase) + ":denied:" + kind))
	return fmt.Sprintf("p%d-%x", p.Number, digest[:12])
}

func BranchWorkflow(p Pull, consumerBase string) string {
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
`, p.HeadSHA, SuiteID(p, consumerBase), p.HeadSHA, p.BaseSHA, consumerBase,
		p.HeadSHA, denialSuiteID(p, consumerBase, "non-ready"), p.HeadSHA, p.BaseSHA, consumerBase,
		p.HeadSHA, denialSuiteID(p, consumerBase, "completed-redelivery"), p.HeadSHA, p.BaseSHA, consumerBase,
		p.HeadSHA, SuiteID(p, consumerBase), p.HeadSHA, p.BaseSHA, consumerBase)
}
