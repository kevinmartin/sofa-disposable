package gatefailure

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFailureRecordIsBoundedAndIdentityOnly(t *testing.T) {
	r := Record{SchemaVersion: 1, SofaPR: 12, HeadSHA: strings.Repeat("a", 40), BaseSHA: strings.Repeat("b", 40), RunID: 43, Reason: PinChanged}
	data, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(data)
	if err != nil || len(got) != 1 || got[0] != r {
		t.Fatalf("trusted failure rejected: %+v, %v", got, err)
	}
	for _, invalid := range [][]byte{
		[]byte(`{"schema_version":1}`),
		[]byte(strings.Replace(string(data), r.HeadSHA, "main", 1)),
		[]byte(strings.Replace(string(data), string(PinChanged), "success", 1)),
		[]byte(strings.Replace(string(data), `"run_id":43`, `"run_id":0`, 1)),
		append(append([]byte{}, data...), []byte(`{"other":true}`)...),
		[]byte(strings.Replace(string(data), `"reason":`, `"candidate_artifact":"untrusted","reason":`, 1)),
		[]byte(strings.Repeat("x", 16<<10+1)),
	} {
		if _, err := Parse(invalid); err == nil {
			t.Fatalf("invalid or untrusted failure accepted: %q", invalid[:min(len(invalid), 120)])
		}
	}
}
