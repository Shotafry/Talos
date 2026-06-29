package typed

import "strings"

// DebianVersionCompare compara dos versiones Debian (formato [epoch:]upstream[-revision])
// segun el algoritmo estandar de dpkg (deb-version(7)): devuelve -1 si a<b, 0 si igual, 1 si a>b.
// Reimplementacion limpia del algoritmo PUBLICO (no copia codigo de ninguna fuente).
// Usado por el pack de vulns criticas para decidir "version instalada >= version corregida".
func DebianVersionCompare(a, b string) int {
	ea, ua, ra := splitDebVersion(a)
	eb, ub, rb := splitDebVersion(b)
	if ea != eb {
		return sign(ea - eb)
	}
	if c := verrevcmp(ua, ub); c != 0 {
		return c
	}
	return verrevcmp(ra, rb)
}

func splitDebVersion(v string) (epoch int, upstream, revision string) {
	v = strings.TrimSpace(v)
	if i := strings.IndexByte(v, ':'); i >= 0 {
		e, ok := 0, true
		for k := 0; k < i; k++ {
			c := v[k]
			if c < '0' || c > '9' {
				ok = false
				break
			}
			e = e*10 + int(c-'0')
		}
		if ok {
			epoch = e
			v = v[i+1:]
		}
	}
	if i := strings.LastIndexByte(v, '-'); i >= 0 {
		return epoch, v[:i], v[i+1:]
	}
	return epoch, v, ""
}

// debOrder define el orden de caracteres de dpkg: '~' antes que el fin de cadena,
// los digitos aparte, las letras por su valor, el resto despues de las letras.
func debOrder(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return 0
	case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
		return int(c)
	case c == '~':
		return -1
	case c == 0:
		return 0
	default:
		return int(c) + 256
	}
}

func verrevcmp(a, b string) int {
	ia, ib, la, lb := 0, 0, len(a), len(b)
	at := func(s string, i, n int) byte {
		if i < n {
			return s[i]
		}
		return 0
	}
	isDig := func(c byte) bool { return c >= '0' && c <= '9' }
	for ia < la || ib < lb {
		for (ia < la && !isDig(a[ia])) || (ib < lb && !isDig(b[ib])) {
			ac := debOrder(at(a, ia, la))
			bc := debOrder(at(b, ib, lb))
			if ac != bc {
				return sign(ac - bc)
			}
			ia++
			ib++
		}
		for ia < la && a[ia] == '0' {
			ia++
		}
		for ib < lb && b[ib] == '0' {
			ib++
		}
		firstDiff := 0
		for ia < la && ib < lb && isDig(a[ia]) && isDig(b[ib]) {
			if firstDiff == 0 {
				firstDiff = int(a[ia]) - int(b[ib])
			}
			ia++
			ib++
		}
		if ia < la && isDig(a[ia]) {
			return 1
		}
		if ib < lb && isDig(b[ib]) {
			return -1
		}
		if firstDiff != 0 {
			return sign(firstDiff)
		}
	}
	return 0
}

func sign(x int) int {
	switch {
	case x < 0:
		return -1
	case x > 0:
		return 1
	default:
		return 0
	}
}
