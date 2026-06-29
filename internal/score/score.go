// Package score agrega veredictos en un indice de hardening (0-100) + bandas + rollup
// por categoria. PURO. Los NA quedan fuera del numerador y del denominador (no penalizan).
// Misma metodologia que re-puntua Argos (vectores compartidos en testdata/score-vectors.json).
package score

import (
	"math"
	"strings"

	"github.com/Shotafry/talos/internal/engine"
)

type Counts struct {
	Pass int `json:"pass"`
	Warn int `json:"warn"`
	Fail int `json:"fail"`
	NA   int `json:"na"`
}

type CategoryScore struct {
	Category string `json:"category"`
	Earned   int    `json:"earned"`
	Max      int    `json:"max"`
	Index    int    `json:"index"`
	Band     string `json:"band"`
	Counts   Counts `json:"counts"`
}

type Excluded struct {
	NA          int `json:"na"`
	NoPrivilege int `json:"noPrivilege"`
}

type Score struct {
	Index      int             `json:"index"`
	Band       string          `json:"band"`
	Categories []CategoryScore `json:"categories"`
	Counts     Counts          `json:"counts"`
	Excluded   Excluded        `json:"excluded"`
}

// Band: <50 rojo, 50-79 amarillo, >=80 verde.
func Band(index int) string {
	switch {
	case index < 50:
		return "rojo"
	case index < 80:
		return "amarillo"
	default:
		return "verde"
	}
}

// Compute calcula el indice global y por categoria. Categoria toda-NA -> Max 0, index 0,
// banda "n/d" (no rojo) y fuera del indice global.
func Compute(verdicts []engine.Verdict) Score {
	type agg struct {
		earned, max int
		c           Counts
	}
	cats := map[string]*agg{}
	var order []string
	var totalEarned, totalMax, naCount, noPriv int
	var counts Counts

	for _, v := range verdicts {
		a := cats[v.Category]
		if a == nil {
			a = &agg{}
			cats[v.Category] = a
			order = append(order, v.Category)
		}
		switch v.Status {
		case "PASS":
			counts.Pass++
			a.c.Pass++
		case "WARN":
			counts.Warn++
			a.c.Warn++
		case "FAIL":
			counts.Fail++
			a.c.Fail++
		case "NA":
			counts.NA++
			a.c.NA++
			naCount++
			if strings.Contains(v.Reason, "requiere privilegios de root") {
				noPriv++
			}
		}
		if v.Status != "NA" {
			a.earned += v.Earned
			a.max += v.Points
			totalEarned += v.Earned
			totalMax += v.Points
		}
	}

	var catScores []CategoryScore
	for _, cat := range order {
		a := cats[cat]
		idx, band := 0, "n/d"
		if a.max > 0 {
			idx = roundPct(a.earned, a.max)
			band = Band(idx)
		}
		catScores = append(catScores, CategoryScore{
			Category: cat, Earned: a.earned, Max: a.max, Index: idx, Band: band, Counts: a.c,
		})
	}

	idx, band := 0, "n/d"
	if totalMax > 0 {
		idx = roundPct(totalEarned, totalMax)
		band = Band(idx)
	}
	return Score{
		Index: idx, Band: band, Categories: catScores, Counts: counts,
		Excluded: Excluded{NA: naCount, NoPrivilege: noPriv},
	}
}

func roundPct(earned, max int) int {
	if max == 0 {
		return 0
	}
	pct := int(math.Round(float64(earned) * 100 / float64(max)))
	if pct > 100 { // defensivo: earned nunca deberia superar max, pero acotamos el indice a 0-100
		return 100
	}
	if pct < 0 {
		return 0
	}
	return pct
}
