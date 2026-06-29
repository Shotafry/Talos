package typed

import (
	"strconv"
	"strings"
)

// RegistryValue extrae el dato de un valor del registro de la salida de `reg query <clave> /v <nombre>`.
// Formato de la linea de valor: "<nombre>  <REG_TIPO>  <dato...>". DWORD/QWORD (0x..) se normaliza a
// decimal para que las fichas comparen numeros; el resto se devuelve como cadena. "" si no aparece.
// La clave ausente no llega aqui: el probe la senala con Exists=false (el motor la traduce a "absent").
func RegistryValue(stdout, name string) string {
	for _, line := range strings.Split(stdout, "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && strings.EqualFold(f[0], name) {
			typ, data := f[1], strings.Join(f[2:], " ")
			if strings.HasPrefix(typ, "REG_DWORD") || strings.HasPrefix(typ, "REG_QWORD") {
				if n, err := strconv.ParseInt(strings.TrimPrefix(strings.ToLower(data), "0x"), 16, 64); err == nil {
					return strconv.FormatInt(n, 10)
				}
			}
			return data
		}
	}
	return ""
}
