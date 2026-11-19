# Plan de PAVAROTTI

## Objetivo

Construir una estación OSINT para equipos Blue Team. El flujo principal parte de artefactos aportados por el analista, conserva su procedencia, normaliza observaciones, correlaciona indicadores y entrega un expediente que otro analista pueda reproducir y auditar. La interfaz, la terminal y los agentes leen la misma base de evidencia.

## Hitos y criterios de cierre

| Hito | Alcance | Prueba de cierre |
| --- | --- | --- |
| 1. Expediente fiable | CLI, almacenamiento local y PostgreSQL, migración, historial de notas, triaje, proxy de un destino, ejecución en Docker y binarios | Importar desde la terminal, editar desde la interfaz, reiniciar y volver a consultar. Repetir migración con los mismos IDs y detectar un conflicto sin cambios parciales. |
| 2. Ingesta OSINT | Importadores versionados para indicadores, registros DNS exportados, observaciones RDAP y STIX 2.1. Contar rechazados, duplicados e importados | Cargar archivos representativos y corruptos. Verificar procedencia, codificaciones, deduplicación y cambios de esquema con archivos de prueba controlados. |
| 3. Correlación y revisión | Relaciones entre registros, cronología por fecha de observación, listas de seguimiento locales y navegación directa a cada evidencia. Exportación STIX y CSV para analistas | Un caso con dominios, IP y huellas muestra coincidencias justificadas y permite volver desde el informe al registro correcto. Probar que el informe conserva las diferencias de alcance y fecha. |
| 4. Agentes persistentes | Cola de análisis en PostgreSQL, estado visible, cancelación y reintentos acotados. Incluir versión del agente, huella de entrada y referencia a cada resultado | Interrumpir el servicio durante una tarea, recuperarla en un arranque posterior y confirmar un único informe. Probar prioridades, cancelación y aislamiento por expediente. |
| 5. Revisión de código | Reglas estáticas ampliadas, reportes de dependencias y clasificación de resultados con revisión humana. Entradas locales por archivo o directorio seleccionado | Casos positivos y negativos con posiciones reproducibles, sin ejecutar los artefactos. Verificar límites de CPU y memoria con entradas grandes y malformadas. |
| 6. Operación compartida | Autenticación, roles, auditoría, retención, exportación y restauración. Separar secretos de configuración y documentar despliegue con TLS | Probar acceso cruzado entre expedientes, vencimiento de sesiones, respaldo y restauración en una base nueva. Publicar solo tras verificar integridad de registros y revisiones. |
| 7. Entrega y mantenimiento | Paquetes nativos, manifiesto de dependencias, verificación de huellas y matriz de regresión | Probar cada etiqueta en Windows, Kali y Arch, además de Compose. Registrar versión del compilador y hash del ejecutable. |

## Configuraciones que se prueban

| Configuración | Cobertura mínima |
| --- | --- |
| Windows x64 y Linux x86-64 con almacén local | Arranque del binario, CLI, importación, análisis, edición y persistencia después de cerrar y abrir. |
| PostgreSQL | Inicio de esquema, credenciales inválidas, aislamiento por expediente, edición concurrente, migración idempotente e historial. |
| Docker Compose | Puerto alterno en loopback, espera de salud, registro por CLI y persistencia después de reiniciar. |
| Proxy y HAR | Destino fijo local, redirecciones, captura de metadatos, protección de datos sensibles y distinción entre fallo de conexión y señales de cabeceras. |
| Navegador | Selección e inspector, búsqueda, historial, carga de reportes y uso con ancho móvil. |

`go test -count=1 ./...` ejecuta la suite local. Para incluir PostgreSQL, configura `PAVAROTTI_TEST_POSTGRES` con un servidor de pruebas separado. `go vet ./...` completa la revisión estática. CI construye y prueba las configuraciones de la matriz y comprueba avisos de dependencias con `govulncheck`.

## Hallazgos de la revisión de 0.3

- Una conexión fallida del proxy generaba un aviso de HSTS aun cuando no se había recibido ninguna cabecera. Una prueba de regresión comprueba que el incidente queda registrado como fallo de conexión.
- El historial podía mezclar la versión seleccionada en pantalla con otra lectura del expediente. La vista muestra ahora las versiones anteriores que devolvió el almacén y el inspector muestra la revisión seleccionada.
- El primer chequeo de persistencia de Compose falló en CI después del reinicio. La verificación ahora espera a la aplicación y compara JSON estructurado.
- La revisión de dependencias encontró avisos para el controlador de PostgreSQL y dos módulos de Go. Se actualizó a versiones con las correcciones y se fijó Go 1.26.11 en la compilación de CI y Docker.
- El análisis admite hasta 10,000 registros por ejecución. Desde 0.3.1, el panel consulta 50 registros por página y carga la evidencia completa al seleccionarla. PostgreSQL filtra antes de entregar resultados. El almacén local recorre los lotes y mantiene en memoria la página candidata. Ambos almacenes aún recorren los datos para responder búsquedas amplias.
- La aplicación aún funciona como estación local. Para uso compartido quedan pendientes los controles de acceso y la auditoría descritos en el hito 6.

## Orden de implementación

1. **Consulta del expediente.** Paginación, búsqueda e inspector bajo demanda. La prueba de cierre comprueba que fechas iguales y notas editadas no duplican ni ocultan resultados al cambiar de página.
2. **Entrada de análisis acotada.** La interfaz y el CLI preparan la misma instantánea con los campos que usan los agentes y los IDs y revisiones de evidencia. El informe incluye su SHA-256 y la versión de los agentes. La lectura se detiene al exceder 10,000 registros o 32 MiB de metadatos. Las pruebas cubren el exceso de registros, la cancelación y un cambio de revisión.
3. **Cola persistente.** Desde 0.3.2, PostgreSQL guarda instantáneas, estados y resultados por expediente. Dos ejecutores pueden compartir una cola con prioridades, cancelación y hasta tres intentos. La prueba interrumpe un proceso después de que obtiene la asignación y verifica que otro recupera la misma tarea y guarda un único informe.
4. **Ingesta y correlación.** 0.3.3 incorpora archivos de respuestas DNS JSON. Cada registro conserva su posición y huella, y el inventario usa los nombres y destinos aportados. Quedan RDAP, STIX, los enlaces directos al inspector y la verificación de procedencia en exportaciones.
5. **Revisión y operación compartida.** Extender las reglas estáticas. Añadir autenticación, permisos, auditoría y restauración antes de abrir el acceso a otros equipos.
6. **Paquetes y capacidad.** Medir latencia y memoria con expedientes de distintos tamaños, añadir índices donde las mediciones lo justifiquen y verificar los binarios y sus huellas en cada etiqueta.

## Flujo de trabajo OSINT

1. **Incorporar.** Un expediente reúne indicadores, capturas HTTP, binarios y respuestas DNS aportadas. Los importadores RDAP y STIX añadirán observaciones con sus referencias y fechas de origen.
2. **Examinar.** La mesa de trabajo conserva la lista central, el inspector y las tareas. El historial HTTP reúne proxy y HAR y filtra sus respuestas por clase de estado. Queda enlazar la cronología y las coincidencias con la evidencia concreta.
3. **Correlacionar.** Los agentes agrupan la evidencia por activo, respuesta HTTP e indicador. Los resultados quedan asociados a la versión del agente y a la huella de entrada.
4. **Entregar.** El analista verifica coincidencias, añade notas y exporta el expediente. Los créditos del binario quedan accesibles en su panel propio.

## Ramas y commits

Usa ramas `blue-team/<capacidad>` para cambios que puedan revisarse por separado. Integra a `main` con la matriz verde. Los mensajes siguen `commit #N` y el número avanza para cada cambio comprobable. Una funcionalidad, una regresión, una mejora de configuración y su documentación pueden merecer commits separados cuando cada uno tiene un motivo propio. La meta de 1,000 commits se mide con `git rev-list --count main`.
