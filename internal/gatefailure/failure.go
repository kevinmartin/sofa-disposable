// Package gatefailure carries a bounded, trusted observer failure to the
// credential-isolated status job. It never contains candidate artifact data.
package gatefailure

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
)

var sha40 = regexp.MustCompile(`^[0-9a-f]{40}$`)

type Reason string

const (
	PinChanged        Reason = "candidate_workflow_pin_changed"
	ObservationFailed Reason = "observation_failed"
)

type Record struct {
	SchemaVersion int    `json:"schema_version"`
	SofaPR        int    `json:"sofa_pr"`
	HeadSHA       string `json:"head_sha"`
	BaseSHA       string `json:"base_sha"`
	RunID         int64  `json:"run_id"`
	Reason        Reason `json:"reason"`
}

func (r Record) Validate() error {
	if r.SchemaVersion != 1 || r.SofaPR < 1 || !sha40.MatchString(r.HeadSHA) ||
		!sha40.MatchString(r.BaseSHA) || r.RunID < 1 ||
		(r.Reason != PinChanged && r.Reason != ObservationFailed) {
		return errors.New("invalid trusted gate failure record")
	}
	return nil
}

func Parse(data []byte) ([]Record, error) {
	if len(data) > 16<<10 {
		return nil, errors.New("trusted gate failures exceed limit")
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte{'\n'})
	if len(lines) > 99 {
		return nil, errors.New("too many trusted gate failures")
	}
	records := make([]Record, 0, len(lines))
	for _, line := range lines {
		var r Record
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&r); err != nil || decoder.Decode(new(any)) != io.EOF || r.Validate() != nil {
			return nil, errors.New("invalid trusted gate failure record")
		}
		records = append(records, r)
	}
	return records, nil
}
