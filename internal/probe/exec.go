package probe

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"
)

// ErrNotAllowed se devuelve cuando argv[0] no esta en la lista blanca.
var ErrNotAllowed = errors.New("comando no permitido")

// ErrPkgAbsent indica que el paquete consultado no esta instalado (vuln no aplicable).
var ErrPkgAbsent = errors.New("paquete no instalado")

// pkgVersion devuelve la version instalada de un paquete (Debian via dpkg-query, RHEL via rpm).
// Si no esta instalado, devuelve Err=ErrPkgAbsent (el motor lo marca NA: la vuln no aplica).
func pkgVersion(pkg string, allow map[string]bool, timeoutMs int) RawRead {
	r := runExec([]string{"dpkg-query", "-W", "-f", "${Version}", pkg}, allow, timeoutMs)
	if r.Err == nil && r.Exit == 0 {
		if v := strings.TrimSpace(r.Stdout); v != "" {
			return RawRead{Value: v, Exists: true}
		}
	}
	r = runExec([]string{"rpm", "-q", "--qf", "%{VERSION}-%{RELEASE}", pkg}, allow, timeoutMs)
	if r.Err == nil && r.Exit == 0 {
		if v := strings.TrimSpace(r.Stdout); v != "" && !strings.Contains(v, "not installed") {
			return RawRead{Value: v, Exists: true}
		}
	}
	return RawRead{Exists: false, Err: ErrPkgAbsent}
}

func runExec(argv []string, allow map[string]bool, timeoutMs int) RawRead {
	if len(argv) == 0 {
		return RawRead{Err: errors.New("argv vacio")}
	}
	if allow != nil && !allow[argv[0]] {
		return RawRead{Err: ErrNotAllowed}
	}
	if timeoutMs <= 0 {
		timeoutMs = 5000
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMs)*time.Millisecond)
	defer cancel()

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...) // sin shell: argv directo, sin inyeccion
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()

	rr := RawRead{Stdout: out.String(), Stderr: errb.String()}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			rr.Exit = ee.ExitCode() // salio con codigo != 0: no es error de probe
		} else {
			rr.Err = err // no se pudo ejecutar (no existe, timeout): el motor -> NA
		}
	}
	return rr
}
