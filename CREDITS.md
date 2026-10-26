# Créditos y procedencia

Talos es un motor de auditoría de bastionado escrito desde cero. No incorpora código de otros
proyectos más allá de las dos dependencias que se indican abajo.

## Procedencia del catálogo de comprobaciones

Cada comprobación verifica un **hecho técnico público**: por ejemplo, que el acceso remoto como
`root` impide saber quién actuó, o que un `/tmp` con permiso de ejecución facilita un ataque. Esos
hechos forman parte del conocimiento común de la disciplina del bastionado. La redacción de cada
comprobación, su identificador, su agrupación y su implementación son propias de Talos.

Los valores concretos se toman de la documentación oficial de cada fabricante o proyecto:

- **Windows**: claves de registro y directivas, de la documentación de Microsoft.
- **Linux**: parámetros del núcleo (`sysctl`), de la documentación del núcleo de Linux.
- **Servicios** (SSH, cortafuegos, registro de auditoría y otros): de la documentación de cada
  servicio.
- **Vulnerabilidades por versión**: la versión corregida de cada paquete, de los avisos de
  seguridad públicos de cada distribución.

Talos también aplica dos prácticas habituales del sector, implementadas de forma propia: resumir
la postura de un equipo en un índice numérico y tratar las comprobaciones como datos versionados
en lugar de como código.

## Guías de configuración de terceros

Talos no reproduce el texto, la numeración, la estructura ni la marca de ninguna guía de
configuración segura publicada por terceros. En particular, **no reproduce contenido de los CIS
Benchmarks**, que se distribuyen bajo la licencia CC BY-NC-SA 4.0, incompatible con un producto
comercial. Una comprobación de Talos puede verificar el mismo hecho técnico que una de esas guías,
porque el hecho es público, pero lo describe y lo identifica con sus propios términos.

## Dependencias de software

| Componente | Licencia | Uso |
| --- | --- | --- |
| Go y su biblioteca estándar | BSD-3-Clause | Lenguaje y entorno de ejecución |
| `gopkg.in/yaml.v3` | MIT y Apache-2.0 | Lectura del catálogo |

La comparación de versiones de paquetes al estilo de `dpkg` (época, versiones preliminares y
segmentos alfanuméricos) es una implementación propia del algoritmo público documentado, probada
contra salida real.

## Nombre

Talos toma su nombre del autómata de bronce de la mitología griega que custodiaba Creta.
