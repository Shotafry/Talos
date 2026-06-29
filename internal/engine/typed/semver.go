package typed

import (
	"strconv"
	"strings"
)

// parseVersionParts extrae los componentes numericos de la version UPSTREAM (hasta el
// primer '-'), tolerando sufijos de distro: 5.15.0-89-generic -> [5,15,0]; 1.1.1w -> [1,1,1].
// NOTA: la comparacion fina de versiones de PAQUETE Debian/RPM (epoch, +deb11uN) se delega
// a `dpkg --compare-versions` / `rpmvercmp` en el runner del pack (no es responsabilidad pura).
func parseVersionParts(v string) []int {
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, '-'); i >= 0 {
		v = v[:i]
	}
	var parts []int
	for _, tok := range strings.Split(v, ".") {
		num := numericPrefix(tok)
		if num == "" {
			continue
		}
		if n, err := strconv.Atoi(num); err == nil {
			parts = append(parts, n)
		}
	}
	return parts
}

func numericPrefix(s string) string {
	i := 0
	for i < len(s) && s[i] >= '0' && s[i] <= '9' {
		i++
	}
	return s[:i]
}

// CompareVersions devuelve -1, 0, 1 (a<b, a==b, a>b) sobre la version upstream.
func CompareVersions(a, b string) int {
	pa, pb := parseVersionParts(a), parseVersionParts(b)
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		va, vb := 0, 0
		if i < len(pa) {
			va = pa[i]
		}
		if i < len(pb) {
			vb = pb[i]
		}
		if va < vb {
			return -1
		}
		if va > vb {
			return 1
		}
	}
	return 0
}

// KernelInRange evalua ">=5.10", "<6.1", ">=5.4 <6.1" o "[5.4,5.15]" contra una version.
func KernelInRange(version, rangeExpr string) (bool, error) {
	rangeExpr = strings.TrimSpace(rangeExpr)
	if strings.HasPrefix(rangeExpr, "[") && strings.HasSuffix(rangeExpr, "]") {
		lohi := strings.Split(rangeExpr[1:len(rangeExpr)-1], ",")
		if len(lohi) != 2 {
			return false, &rangeError{rangeExpr}
		}
		lo, hi := strings.TrimSpace(lohi[0]), strings.TrimSpace(lohi[1])
		return CompareVersions(version, lo) >= 0 && CompareVersions(version, hi) <= 0, nil
	}
	for _, clause := range strings.Fields(rangeExpr) {
		op, ver := splitOp(clause)
		if ver == "" {
			return false, &rangeError{rangeExpr}
		}
		cmp := CompareVersions(version, ver)
		ok := false
		switch op {
		case ">=":
			ok = cmp >= 0
		case "<=":
			ok = cmp <= 0
		case ">":
			ok = cmp > 0
		case "<":
			ok = cmp < 0
		case "==", "=":
			ok = cmp == 0
		default:
			return false, &rangeError{rangeExpr}
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

func splitOp(s string) (string, string) {
	for _, op := range []string{">=", "<=", "==", ">", "<", "="} {
		if strings.HasPrefix(s, op) {
			return op, strings.TrimSpace(s[len(op):])
		}
	}
	return "", ""
}

type rangeError struct{ expr string }

func (e *rangeError) Error() string { return "rango de version invalido: " + e.expr }
