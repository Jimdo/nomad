package api

import (
	"testing"
)

func assertQueryMeta(t *testing.T, qm *QueryMeta) {
	if qm.LastIndex == 0 {
		t.Fatalf("bad index: %d", qm.LastIndex)
	}
	if qm.RequestTime == 0 {
		t.Fatalf("bad request time: %d", qm.RequestTime)
	}
	if !qm.KnownLeader {
		t.Fatalf("expected known leader, got none")
	}
}

func assertWriteMeta(t *testing.T, wm *WriteMeta) {
	if wm.LastIndex == 0 {
		t.Fatalf("bad index: %d", wm.LastIndex)
	}
	if wm.RequestTime == 0 {
		t.Fatalf("bad request time: %d", wm.RequestTime)
	}
}

func testJob() *Job {
	return &Job{
		ID:       "job1",
		Name:     "redis",
		Type:     "service",
		Priority: 1,
	}
}
