# Creditos e inspiracion

Talos es una implementacion **propia y desde cero**. No reutiliza ni copia codigo
de ningun otro proyecto. Lo que aprovecha es **conocimiento publico** de la
disciplina de bastionado de sistemas:

- **Metodologia de bastionado del sector.** Guias publicas de configuracion segura
  de servidores y estaciones (lineas base de hardening), de donde provienen los
  *hechos* que cada check verifica (no su implementacion).
- **Documentacion oficial de los fabricantes.** Claves de registro y directivas de
  Microsoft, parametros del kernel de Linux (`sysctl`), opciones de servicios
  (SSH, cortafuegos, etc.) tomadas de su documentacion oficial.
- **Repositorios publicos de seguimiento de vulnerabilidades.** Para el pack de
  vulnerabilidades por version, las versiones corregidas por distribucion y
  release se toman de los *security trackers* publicos de las distribuciones.
- **Patrones consolidados de la disciplina.** Resumir la postura en un **indice**
  numerico y tratar las comprobaciones como **datos versionables** son ideas
  ampliamente usadas en herramientas de auditoria; Talos las reimplementa a su
  manera.

## Dependencias de software

- **Go** (biblioteca estandar) - lenguaje y runtime.
- **gopkg.in/yaml.v3** - parseo del catalogo YAML.

El algoritmo de comparacion de versiones estilo `dpkg` (deb-version) es una
reimplementacion limpia del algoritmo **publico** documentado, no una copia de
codigo.

## Marca

"Talos" toma el nombre del automata de bronce de la mitologia griega, guardian
de Creta. Talos forma parte de una plataforma de seguridad mayor (*by argos*).
