package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/mishraprayash/macsweep/internal/testutil"
)

func TestAppendOnly(t *testing.T) {
	s := testutil.NewSandbox(t)
	path := DefaultPath(s.Home)
	s.RequireInside(t, path)
	clock := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	for run := 0; run < 2; run++ {
		l, err := Open(path, func() time.Time { return clock })
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 2; i++ {
			if err := l.Append(Record{Action: "trash", Path: "/x", Size: 10, RuleID: "r", Tier: "SAFE", Result: ResultOK}); err != nil {
				t.Fatal(err)
			}
		}
		if err := l.Close(); err != nil {
			t.Fatal(err)
		}
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var recs []Record
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var r Record
		if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
			t.Fatalf("bad line %q: %v", sc.Text(), err)
		}
		recs = append(recs, r)
	}
	if len(recs) != 4 {
		t.Fatalf("got %d records, want 4 (two sessions appended, nothing truncated)", len(recs))
	}
	if recs[0].Session == "" || recs[0].Session != recs[1].Session || recs[1].Session == recs[2].Session {
		t.Errorf("sessions not grouped per run: %v %v %v", recs[0].Session, recs[1].Session, recs[2].Session)
	}
	if !recs[0].Time.Equal(clock) {
		t.Errorf("time = %v", recs[0].Time)
	}
	fi, _ := os.Stat(path)
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("log mode %v, want 0600", fi.Mode().Perm())
	}
}
