package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/kevinmartin/sofa-disposable/internal/gatestatus"
)

func TestTrustedStatusInputIsBoundedAndFailClosed(t *testing.T) {
	if results, err := parseResults(nil); err != nil || len(results) != 0 {
		t.Fatal("empty observer result should publish no status", err)
	}
	if err := run(context.Background(), nil, gatestatus.Writer{}); err != nil {
		t.Fatal("pending suite should not require an App credential", err)
	}
	r := observed{SchemaVersion: 1, SofaPR: 2, CandidateSHA: strings.Repeat("a", 40), PRBaseSHA: strings.Repeat("b", 40), DisposableBaseSHA: strings.Repeat("c", 40), CandidateDigest: strings.Repeat("e", 64), CandidateRunID: 42, CandidateRunAttempt: 1, DraftPR: 7, DraftPRURL: "https://github.com/kevinmartin/sofa-disposable/pull/7", DraftHeadSHA: strings.Repeat("f", 40)}
	suiteDigest := sha256.Sum256([]byte(r.CandidateSHA + ":" + r.PRBaseSHA + ":" + r.DisposableBaseSHA))
	r.SuiteID = fmt.Sprintf("p%d-%x", r.SofaPR, suiteDigest[:12])
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if results, err := parseResults(append(data, '\n')); err != nil || len(results) != 1 || results[0] != r {
		t.Fatalf("valid trusted result rejected: %+v, %v", results, err)
	}
	for _, invalid := range [][]byte{
		[]byte(`{"schema_version":2}`),
		[]byte(strings.Replace(string(data), r.SuiteID, "p2-"+strings.Repeat("d", 24), 1)),
		[]byte(strings.Replace(string(data), "https://github.com/kevinmartin/sofa-disposable/pull/7", "https://example.com/pull/7", 1)),
		append(append([]byte{}, data...), []byte(`{"other":true}`)...),
		[]byte(strings.Repeat("x", 100<<10+1)),
	} {
		if _, err := parseResults(invalid); err == nil {
			t.Fatal("accepted invalid trusted status input")
		}
	}
	if err := run(context.Background(), append(data, '\n'), gatestatus.Writer{}); err == nil {
		t.Fatal("validated result gained a green status without App credential")
	}
}
