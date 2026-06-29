// Package engine evalua un check del catalogo contra una lectura cruda y produce
// un veredicto PASS/WARN/FAIL/NA. Es PURO: sin red ni IO (recibe el RawRead ya capturado).
package engine

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/Shotafry/talos/internal/catalog"
	"github.com/Shotafry/talos/internal/engine/typed"
)

// matchBand resuelve la banda (good|medium|weak|"") para un valor leido.
// Prueba good, luego medium, luego weak; el primero que casa fija la banda.
func matchBand(comparator string, exp catalog.Expected, value string) string {
	if exp.Good != nil && matchOne(comparator, exp.Good, value) {
		return "good"
	}
	if exp.Medium != nil && matchOne(comparator, exp.Medium, value) {
		return "medium"
	}
	if exp.Weak != nil && matchOne(comparator, exp.Weak, value) {
		return "weak"
	}
	return ""
}

// matchOne aplica el comparador a un valor esperado (escalar o lista). Si el esperado
// es una lista, se evalua como pertenencia aunque el comparator base sea otro (spec).
func matchOne(comparator string, expected any, value string) bool {
	if list, ok := toStringList(expected); ok {
		for _, e := range list {
			if eqNorm(e, value) {
				return true
			}
		}
		return false
	}
	exp := toStr(expected)
	switch comparator {
	case "eq":
		return eqNorm(exp, value)
	case "ne":
		return !eqNorm(exp, value)
	case "lt", "gt", "le", "ge":
		return numCompare(comparator, exp, value)
	case "in":
		return eqNorm(exp, value) // 'in' con escalar: equivale a eq
	case "regex":
		re, err := regexp.Compile(exp) // RE2: lineal, sin lookahead/backreferences
		if err != nil {
			return false
		}
		return re.MatchString(value)
	case "nregex":
		re, err := regexp.Compile(exp) // PASS (casa good) si el patron NO aparece
		if err != nil {
			return false
		}
		return !re.MatchString(value)
	case "vge", "vgt", "vle", "vlt":
		c := typed.DebianVersionCompare(value, exp)
		switch comparator {
		case "vge":
			return c >= 0
		case "vgt":
			return c > 0
		case "vle":
			return c <= 0
		default: // vlt
			return c < 0
		}
	case "exists":
		return eqNorm(exp, value) // value normalizado a "true"/"false" por el motor
	case "range":
		return inRange(exp, value)
	default:
		return false
	}
}

func norm(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// canonBool mapea sinonimos booleanos a "true"/"false". El segundo retorno indica
// si el string ERA una forma booleana reconocida.
func canonBool(s string) (string, bool) {
	switch norm(s) {
	case "yes", "true", "1", "on", "enabled":
		return "true", true
	case "no", "false", "0", "off", "disabled":
		return "false", true
	}
	return "", false
}

// eqNorm compara dos strings normalizados; si ambos son formas booleanas, compara el bool.
func eqNorm(a, b string) bool {
	if ca, oka := canonBool(a); oka {
		if cb, okb := canonBool(b); okb {
			return ca == cb
		}
	}
	return norm(a) == norm(b)
}

// numCompare exige que ambos lados sean numericos; un valor no numerico -> false (FAIL).
func numCompare(op, exp, value string) bool {
	ev, err1 := strconv.ParseFloat(strings.TrimSpace(exp), 64)
	vv, err2 := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err1 != nil || err2 != nil {
		return false
	}
	switch op {
	case "lt":
		return vv < ev
	case "gt":
		return vv > ev
	case "le":
		return vv <= ev
	case "ge":
		return vv >= ev
	}
	return false
}

// inRange soporta "[lo,hi]" (inclusivo).
func inRange(exp, value string) bool {
	vv, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil {
		return false
	}
	s := strings.TrimSpace(exp)
	if strings.HasPrefix(s, "[") && strings.HasSuffix(s, "]") {
		parts := strings.Split(s[1:len(s)-1], ",")
		if len(parts) != 2 {
			return false
		}
		lo, e1 := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
		hi, e2 := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
		if e1 != nil || e2 != nil {
			return false
		}
		return vv >= lo && vv <= hi
	}
	return false
}

func toStringList(v any) ([]string, bool) {
	switch t := v.(type) {
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			out = append(out, toStr(e))
		}
		return out, true
	case []string:
		return t, true
	}
	return nil, false
}

func toStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case int:
		return strconv.Itoa(t)
	case float64:
		return strconv.FormatFloat(t, 'g', -1, 64)
	default:
		return fmt.Sprintf("%v", t)
	}
}
