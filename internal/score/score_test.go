package score

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/Shotafry/talos/internal/engine"
)

type vectorFile struct {
	Vectors []struct {
		Name     string
		Verdicts []struct {
			Category, Status, Reason string
			Points, Earned           int
		}
		Expected struct {
			Index      int
			Band       string
			Categories map[string]struct {
				Index int
				Band  string
			}
			Counts   Counts
			Excluded Excluded
		}
	}
}

func TestScoreVectors(t *testing.T) {
	b, err := os.ReadFile("testdata/score-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vf vectorFile
	if err := json.Unmarshal(b, &vf); err != nil {
		t.Fatal(err)
	}
	if len(vf.Vectors) == 0 {
		t.Fatal("sin vectores")
	}
	for _, vec := range vf.Vectors {
		var vs []engine.Verdict
		for _, v := range vec.Verdicts {
			vs = append(vs, engine.Verdict{
				Category: v.Category, Status: v.Status,
				Points: v.Points, Earned: v.Earned, Reason: v.Reason,
			})
		}
		got := Compute(vs)
		if got.Index != vec.Expected.Index {
			t.Errorf("%s: index %d want %d", vec.Name, got.Index, vec.Expected.Index)
		}
		if got.Band != vec.Expected.Band {
			t.Errorf("%s: band %q want %q", vec.Name, got.Band, vec.Expected.Band)
		}
		if got.Counts != vec.Expected.Counts {
			t.Errorf("%s: counts %+v want %+v", vec.Name, got.Counts, vec.Expected.Counts)
		}
		if got.Excluded != vec.Expected.Excluded {
			t.Errorf("%s: excluded %+v want %+v", vec.Name, got.Excluded, vec.Expected.Excluded)
		}
		catIdx := map[string]CategoryScore{}
		for _, c := range got.Categories {
			catIdx[c.Category] = c
		}
		for name, exp := range vec.Expected.Categories {
			c := catIdx[name]
			if c.Index != exp.Index || c.Band != exp.Band {
				t.Errorf("%s/%s: %d/%q want %d/%q", vec.Name, name, c.Index, c.Band, exp.Index, exp.Band)
			}
		}
	}
}
