# Créditos y procedencia

Talos es una implementación propia y escrita desde cero. No reutiliza ni copia código de ningún
otro proyecto. Lo que sí aprovecha, porque sería absurdo no hacerlo, es el conocimiento público de
la disciplina del bastionado de sistemas.

De la **metodología del sector** vienen los *hechos* que cada comprobación verifica: que el
acceso remoto como root deja el sistema sin trazabilidad, que un `/tmp` ejecutable es media cadena
de ataque. Son las guías públicas de configuración segura de servidores y estaciones, las líneas
base que circulan desde hace veinte años. Vienen los hechos, no la redacción ni la
implementación, que son de Talos.

Los **valores concretos** salen de la documentación oficial de quien hace el software. Las claves
de registro y las directivas las publica Microsoft, y los parámetros del kernel (`sysctl`), la
documentación de Linux. Las opciones de cada servicio (SSH, el cortafuegos, el registro de
auditoría) salen de la documentación de ese servicio.

Para las comprobaciones de **vulnerabilidades por versión**, la versión corregida de cada paquete
en cada distribución y release se toma de los *security trackers* públicos de las propias
distribuciones, que es el único sitio donde ese dato está bien.

Y hay dos **patrones consolidados** que Talos reimplementa a su manera porque son de todos:
resumir la postura de una máquina en un índice numérico, y tratar las comprobaciones como datos
versionables en lugar de como código.

## Dependencias de software

Solo dos, las dos deliberadamente aburridas:

- **Go**, con su biblioteca estándar, como lenguaje y como runtime.
- **gopkg.in/yaml.v3** para leer el catálogo.

El algoritmo de comparación de versiones estilo `dpkg` es una reimplementación limpia del
algoritmo público documentado, no una copia de código. Maneja epoch, pre-release y segmentos
alfanuméricos, y tiene sus pruebas contra salida real.

## Marca

Talos toma el nombre del autómata de bronce de la mitología griega, el guardián de Creta. Forma
parte de una plataforma de seguridad mayor (*by argos*).
