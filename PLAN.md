# Plan de PAVAROTTI

## Objetivo

Construir una estación OSINT para equipos Blue Team. El flujo principal parte de artefactos aportados por el analista, conserva su procedencia, normaliza observaciones, correlaciona indicadores y entrega un expediente que otro analista pueda reproducir y auditar. La interfaz, la terminal y los agentes leen la misma base de evidencia.

## Hitos y criterios de cierre

| Hito | Alcance | Prueba de cierre |
| --- | --- | --- |
| 1. Expediente fiable | CLI, almacenamiento local y PostgreSQL, migración, historial de notas, triaje, proxy de un destino, ejecución en Docker y binarios | Importar desde la terminal, editar desde la interfaz, reiniciar y volver a consultar. Repetir migración con los mismos IDs y detectar un conflicto sin cambios parciales. |
| 2. Ingesta OSINT | Importadores versionados para indicadores, registros DNS exportados, observaciones RDAP y STIX 2.1. Contar rechazados, duplicados e importados | Cargar archivos representativos y corruptos. Verificar procedencia, codificaciones, deduplicación y cambios de esquema con archivos de prueba controlados. |
| 3. Correlación y revisión | Relaciones entre registros y activos, cronología por fecha de observación, listas de seguimiento por expediente y navegación directa a cada evidencia. Exportación STIX y CSV para analistas | Un caso con dominios, IP y huellas muestra coincidencias justificadas y permite volver desde el informe al registro correcto. Probar que el informe conserva las diferencias de alcance y fecha y que las listas y relaciones mantienen sus citas tras migrar el expediente. |
| 4. Agentes persistentes | Cola de análisis en PostgreSQL, estado visible, cancelación y reintentos acotados. Incluir versión del agente, huella de entrada y referencia a cada resultado | Interrumpir el servicio durante una tarea, recuperarla en un arranque posterior y confirmar un único informe. Probar prioridades, cancelación y aislamiento por expediente. |
| 5. Revisión de código | Reglas estáticas ampliadas, reportes de dependencias y clasificación de resultados con revisión humana. Entradas locales por archivo o directorio seleccionado | Casos positivos y negativos con posiciones reproducibles, sin ejecutar los artefactos. Verificar límites de CPU y memoria con entradas grandes y malformadas. |
| 6. Operación compartida | Autenticación, roles, auditoría, retención, exportación y restauración. Separar secretos de configuración y documentar despliegue con TLS | Probar acceso cruzado entre expedientes, vencimiento de sesiones, respaldo y restauración en una base nueva. Publicar solo tras verificar integridad de registros y revisiones. |
| 7. Entrega y mantenimiento | Instaladores `.deb` y `.pkg.tar.xz`, archivos portátiles, manifiesto de dependencias, huellas y matriz de regresión | Verificar la versión y el SHA-256 de los paquetes. Instalar y retirar los paquetes en Kali y Arch conservando el expediente. Abrir un expediente desde el ZIP de Windows. Ejecutar la matriz al publicar una etiqueta. |

## Configuraciones que se prueban

| Configuración | Cobertura mínima |
| --- | --- |
| Windows x64 y Linux x86-64 con almacén local | Arranque del binario, CLI, importación, análisis, edición y persistencia después de cerrar y abrir. Ejecutar el flujo RDAP y STIX con cruces de SHA-256 y red y reimportar el paquete exportado dentro de Kali y Arch en CI. |
| PostgreSQL | Inicio de esquema, credenciales inválidas, aislamiento por expediente, edición concurrente, migración idempotente, historial, vencimiento y revocación de sesiones. |
| Docker Compose | Puerto alterno en loopback, espera de salud, registro por CLI y persistencia después de reiniciar. En HTTPS se ejercitan el certificado, la sesión, los roles y el origen de las escrituras. |
| Proxy y HAR | Destino fijo local, redirecciones, filtros combinados de captura, método, fecha, clase de respuesta y regla, y distinción entre fallo de conexión y señales de cabeceras. Verificar las citas de reglas sin guardar valores de cookies ni URLs completas. |
| Navegador | Selección e inspector, búsqueda, historial, carga de informes y uso con ancho móvil. Abrir una cita de un informe guardado tras editar la evidencia y comprobar su revisión. Desde una ficha de activo, abrir fuentes DNS, HTTP, RDAP y STIX. |
| Revisión estática y dependencias | Localizar Go por línea y columna físicas. Consultar dependencias por versión y posición. Revisar un directorio, abrir la cita y conservar dos decisiones de triaje tras reiniciar y migrar a PostgreSQL. |

`go test -count=1 ./...` ejecuta la suite local. Para incluir PostgreSQL, configura `PAVAROTTI_TEST_POSTGRES` con un servidor de pruebas separado. `go vet ./...` completa la revisión estática. CI construye y prueba las configuraciones de la matriz y comprueba avisos de dependencias con `govulncheck`.

## Arquitectura del repositorio

| Ruta | Responsabilidad |
| --- | --- |
| `main.go` | Opciones de arranque, selección del almacén, empaquetado de recursos y ciclo de vida del servidor. |
| `internal/mesa` y `ui` | Servidor HTTP, sesiones y permisos en `internal/mesa`. HTML, estilos y comportamiento de la interfaz en `ui`. |
| `internal/terminal` | Comandos, argumentos y formatos de salida. Usa los mismos servicios que la mesa. |
| `internal/caso` y `internal/config` | Evidencia, revisiones, autenticación, cola y auditoría en `internal/caso`. Lectura de secretos en `internal/config`. |
| `internal/analisis` | Preparación de instantáneas, correlación, agentes e informes. |
| `internal/ingesta`, `internal/trafico`, `internal/triaje` y `internal/revision` | Importación de artefactos, observación HTTP, inspección de binarios y revisión de código y dependencias, respectivamente. |
| `packaging` | Instaladores y archivos portátiles x64, entrada de escritorio y verificación de sumas. |

## Cobertura defensiva de la mesa

| Flujo | Disponible | Trabajo pendiente y prueba de cierre |
| --- | --- | --- |
| Expedientes, terminal y agentes | Evidencia con procedencia, inventario y fichas por página en expedientes de 50,000 observaciones, relaciones y listas de seguimiento con citas, cobertura por periodo, cola persistente, revisión de código Go y exportación STIX. | Reducir el trabajo por página en fichas cuyos activos aparecen en pocos lotes y medir consultas concurrentes. |
| Inspección estática de binarios | PE, ELF y Mach-O con ventanas verificadas, referencias por símbolo e imagen y comparación de informes y secciones con citas de ambos lados. | Medir tiempo y memoria en comparaciones de archivos e informes cercanos a sus límites. |
| Observación HTTP | Proxy local de destino fijo, importación HAR, cronología, filtros, reglas pasivas y comparación de hasta 50,000 observaciones con citas a la revisión exacta. | Medir latencia y memoria con varias comparaciones simultáneas y verificar la cancelación de las consultas. |
| Operación compartida | Instalación nativa, Docker Compose local y HTTPS con roles, auditoría y restauración. Se prueban la apertura y la edición de otros expedientes durante una restauración. | Medir la latencia de escritura con carga sostenida y distintos almacenamientos del registro de escritura anticipada de PostgreSQL (WAL). |

## Hallazgos de la revisión de 0.3

- Una conexión fallida del proxy generaba un aviso de HSTS aun cuando no se había recibido ninguna cabecera. Una prueba de regresión comprueba que el incidente queda registrado como fallo de conexión.
- El historial podía mezclar la versión seleccionada en pantalla con otra lectura del expediente. La vista muestra ahora las versiones anteriores que devolvió el almacén y el inspector muestra la revisión seleccionada.
- El primer chequeo de persistencia de Compose falló en CI después del reinicio. La verificación ahora espera a la aplicación y compara JSON estructurado.
- La revisión de dependencias encontró avisos para el controlador de PostgreSQL y dos módulos de Go. Se actualizó a versiones con las correcciones y se fijó Go 1.26.11 en la compilación de CI y Docker.
- El análisis admite hasta 10,000 registros por ejecución. Desde 0.3.1, el panel consulta 50 registros por página y carga la evidencia completa al seleccionarla. PostgreSQL filtra antes de entregar resultados. El almacén local recorre los lotes y mantiene en memoria la página candidata. Ambos almacenes aún recorren los datos para responder búsquedas amplias.
- La configuración compartida usa PostgreSQL y HTTPS con cuentas de lectura y análisis por expediente. Desde la 0.4.2, las operaciones nuevas generan eventos de auditoría. La 0.4.3 añade respaldos verificables y restauración en un expediente vacío. La 0.4.4 incorpora el despliegue HTTPS con archivos de secretos y la retención de actividad a partir de una copia comprobada.

## Orden de implementación

1. **Consulta del expediente.** Paginación, búsqueda e inspector bajo demanda. La prueba de cierre comprueba que fechas iguales y notas editadas no duplican ni ocultan resultados al cambiar de página.
2. **Entrada de análisis acotada.** La interfaz y el CLI preparan la misma instantánea con los campos que usan los agentes y los IDs y revisiones de evidencia. El informe incluye su SHA-256 y la versión de los agentes. La lectura se detiene al exceder 10,000 registros o 32 MiB de metadatos. Las pruebas cubren el exceso de registros, la cancelación y un cambio de revisión.
3. **Cola persistente.** Desde 0.3.2, PostgreSQL guarda instantáneas, estados y resultados por expediente. Dos ejecutores pueden compartir una cola con prioridades, cancelación y hasta tres intentos. La prueba interrumpe un proceso después de que obtiene la asignación y verifica que otro recupera la misma tarea y guarda un único informe.
4. **Ingesta y citas.** 0.3.4 importa DNS, RDAP y STIX 2.1 desde archivos, cruza indicadores STIX con dominios e IP observados y abre las revisiones citadas desde informes locales y guardados. El inspector conserva la posición y huella del archivo. La cobertura actual de STIX se limita a metadatos y comparaciones literales.
5. **Inventario de activos.** 0.3.5 añade fichas navegables en la mesa y el comando `activos` del CLI. Las fichas de huella enlazan muestras e indicadores SHA-256. Las fichas de IP muestran cobertura por rango RDAP o prefijo STIX y conservan el recuento de observaciones directas. La consulta recorre hasta 10,000 registros y pagina resultados.
6. **Relaciones e informes.** 0.3.6 permite navegar las referencias STIX desde el inspector, conserva sus alternativas de procedencia y muestra los objetos pendientes de importar. Los informes nuevos citan los cruces SHA-256 y la cobertura de IP observadas por DNS o HTTP. El ejecutor admite las versiones 1 y 2 del análisis y conserva la huella de entrada de cada tarea.
7. **Intercambio STIX.** 0.3.7 exporta observaciones, huellas, indicadores y relaciones compatibles con citas al ID, revisión y huella del expediente de origen. La prueba reimporta el paquete en otro expediente y vuelve a cargar el mismo archivo para comprobar la deduplicación. La exportación admite hasta 5,000 objetos y 32 MiB. La terminal puede acotar por tipo o búsqueda.
8. **Revisión estática e inventario.** 0.3.8 amplía la revisión Go y lee `go.mod` y `package-lock.json` v2 y v3. Guarda reglas, líneas, columnas, versiones declaradas, reemplazos y huellas. Los informes del agente 3 abren la señal o dependencia citada. La prueba comprueba la recuperación de tareas pendientes del agente 2 y los límites de 250 señales guardadas y 5,000 entradas de manifiesto.
9. **Flujo de revisión humana.** 0.3.9 revisa directorios desde la mesa y el CLI, conserva las rutas relativas y presenta el resultado de cada archivo. Guarda el estado, fecha y justificación de cada señal con revisiones de triaje. Las pruebas verifican la recuperación tras reiniciar, la migración a PostgreSQL y el rechazo de escrituras con una revisión obsoleta.
10. **Mesa de investigación compartida.** 0.4.0 añade acceso HTTPS con roles por expediente, filtros combinados sobre el historial HTTP y un inspector de binarios que abre cadenas desde una sección y conecta la huella con los activos. La prueba comprueba cada flujo desde el navegador con un lector y un analista.
11. **Símbolos y citas de binarios.** 0.4.1 guarda símbolos definidos de tablas ELF, COFF y Mach-O. La mesa exporta una cita JSON con la huella del archivo, la huella del análisis, el ID, la revisión y el desplazamiento. Al reabrirla, verifica esos datos y señala la fila citada. Las revisiones previas siguen mostrando los metadatos que guardaron.
12. **Auditoría de operaciones.** La 0.4.2 registra incorporaciones, ediciones, triaje, migraciones y cambios de la cola en la misma transacción. La mesa abre la revisión de evidencia o tarea del evento. Las pruebas cubren conflictos concurrentes, retroceso cuando falla la auditoría y separación de expedientes.
13. **Respaldo y restauración.** La 0.4.3 guarda evidencia, revisiones, triaje, tareas y actividad en una copia verificable por SHA-256. Restaura en un expediente vacío con sus referencias. Las pruebas cubren la edición concurrente al respaldar, la exclusión de otras escrituras al restaurar, las copias truncadas y las referencias inválidas.
14. **Retención y despliegue compartido.** La 0.4.4 permite previsualizar la retención por fecha y aplicarla cuando la copia contiene los eventos seleccionados. La prueba restaura la actividad archivada y abre las revisiones conservadas. CI prueba HTTPS con Docker Compose, roles y persistencia tras reiniciar. El archivo queda bajo custodia del operador.
15. **Reglas pasivas HTTP.** La 0.4.5 añade reglas de cabeceras, filtros por código en la mesa y la terminal, y citas en el informe de agentes 4. Las instantáneas anteriores siguen siendo legibles por sus respectivas versiones. El criterio de cierre comprueba que la regla abre la respuesta guardada y resalta su motivo.
16. **Comparación de capturas HTTP.** La 0.4.6 compara orígenes, tipos de captura y fechas UTC inclusivas en la mesa y la terminal. El JSON conserva la huella de entrada, los criterios y las citas aunque el expediente reciba capturas después. Las pruebas distinguen un fallo del proxy de una respuesta 502, comprueban los límites UTC y abren reglas de la revisión citada.
17. **Exportaciones e imágenes binarias.** La 0.4.7 añade exportaciones PE por nombre y ordinal y lee contenedores FAT y FAT64 de Mach-O universal. Verifica que una cita a una imagen abra su arquitectura y el desplazamiento absoluto guardado, incluso cuando dos imágenes tengan el mismo símbolo en la misma dirección virtual.
18. **Cobertura de activos por periodo.** La 0.4.8 permite navegar desde una red hacia las IP observadas en DNS y HTTP. La mesa y el CLI generan el mismo informe con fechas UTC inclusivas y citas de origen. La prueba reabre el JSON en un expediente restaurado y confirma la huella y las revisiones.
19. **Consultas por ventanas.** Desde 0.4.9 PostgreSQL descarta las fechas ajenas antes de entregar registros al análisis. El almacén local conserva en memoria los límites de fecha de los lotes ya leídos. La comparación y la cobertura acotan los registros que coinciden. Las pruebas conservan los nanosegundos, las fechas con desfase y las revisiones citadas.
20. **Paginación de expedientes.** Desde 0.4.10 el almacén local reutiliza un resumen de los lotes para la navegación sin búsqueda de texto. PostgreSQL mantiene un índice derivado de las capturas HTTP, rellena los lotes antiguos por partes y reconstruye el índice al restaurar. Las pruebas comprueban el orden, los cursores y las citas durante la actualización y después de restaurar.
21. **Búsqueda literal de expedientes.** Desde 0.4.11 el almacén local comparte texto normalizado entre registros del mismo lote. PostgreSQL genera documentos de búsqueda, aprovecha `pg_trgm` cuando está disponible y prepara expedientes antiguos en segundo plano desde la mesa. Las pruebas comprueban coincidencias literales, señales, dependencias, textos extensos y la revisión vigente de las notas.
22. **Restauración de expedientes grandes.** La 0.4.12 inserta por lotes y prepara los índices de búsqueda e historial HTTP después de restaurar. Las pruebas comprueban que una copia truncada revierte todos los lotes y que las consultas conservan las citas durante la preparación de los índices.
23. **Expedientes concurrentes.** La 0.4.13 consulta si los índices de tareas y sesiones están instalados antes de enviar DDL. La prueba detiene una restauración con tareas ya insertadas y verifica que se puede abrir y editar otro expediente antes de confirmar la copia.
24. **Navegación de instrucciones.** La 0.4.14 lista secciones ejecutables compatibles de PE, ELF y Mach-O. La mesa filtra por imagen y sección y sigue destinos directos a instrucciones guardadas. Las pruebas comparan bytes, direcciones, desplazamientos y citas. Un análisis nuevo del mismo archivo conserva las referencias anteriores.
25. **Ventanas desde puntos de entrada y símbolos.** La 0.4.15 verifica el archivo original contra la revisión del expediente y abre hasta 64 instrucciones desde la ubicación. La mesa y la terminal comparan la huella al volver a abrir citas. Las pruebas incluyen una ubicación ELF y PE más allá del listado inicial y un Mach-O universal con dos imágenes.
26. **Navegación entre ventanas.** La 0.4.16 sigue destinos directos dentro de la misma imagen, comprueba la sección ejecutable y permite volver a la instrucción de origen. Las citas reproducen hasta 32 saltos. Las pruebas cruzan secciones, reabren un recorrido y rechazan destinos ambiguos o de otra imagen.
27. **Referencias entrantes observadas.** La 0.4.17 reúne el listado guardado y las últimas 64 ventanas verificadas del inspector. Agrupa referencias por imagen y deduplica por dirección y desplazamiento. Reabre cada origen con la cita de su ventana o la instrucción guardada. Al reabrir una cita de recorrido incorpora el último salto verificado.
28. **Informes de referencias portátiles.** La 0.4.18 exporta el destino seleccionado con los orígenes observados. La mesa y el CLI verifican el informe con el expediente y el archivo original. Las pruebas recuperan dos ventanas de origen en una copia del expediente y rechazan informes o archivos alterados.
29. **Referencias por símbolo.** La 0.4.19 filtra símbolos con referencias observadas y abre el panel de su instrucción de entrada. Los alias comparten referencias cuando coinciden imagen, dirección y desplazamiento. Las pruebas comprueban el recuento, el salto al origen y el rechazo de destinos ambiguos.
30. **Comparación de informes de referencias.** La 0.4.20 verifica dos informes del mismo binario, imagen y destino. Distingue orígenes comunes, agregados y ausentes del informe actual, conserva sus citas y abre los orígenes desde la mesa. Las pruebas comprueban informes con anclas distintas, el rechazo de alteraciones y la coincidencia entre la API y el CLI.
31. **Activos en expedientes grandes.** La 0.4.21 pagina el inventario y las fichas con recuentos completos, y conserva en memoria las filas de la página más una para detectar la siguiente. Las fichas mantienen su orden por fecha e ID y verifican que el cursor siga perteneciendo al activo. Las búsquedas de red aprovechan el tipo solicitado para omitir la extracción de dominios.
32. **Seguimiento de activos.** La 0.4.22 guarda listas por expediente en archivos y PostgreSQL. La mesa y el CLI revisan sus activos contra la evidencia almacenada y conservan la última cita, incluidas las fuentes de cobertura de una IP. Las pruebas verifican cambios concurrentes, permisos, migración idempotente, restauración y validación del respaldo.
33. **Comparaciones HTTP amplias.** La 0.4.23 admite 50,000 observaciones distintas con el límite de 32 MiB. Conserva la huella y el formato de las comparaciones de hasta 10,000 observaciones y abre informes de ambos formatos. PostgreSQL reutiliza el índice del historial para localizar lotes de ventanas que suman hasta siete días. Las pruebas cubren periodos superpuestos, lotes por indexar y fechas con desfase UTC.
34. **Paquetes nativos y portátiles.** La 0.4.24 genera paquetes para Kali, Arch y uso portátil en Windows y Linux. El manifiesto registra el commit, los módulos de Go y la huella de cada binario. La matriz comprueba las sumas, instala y retira los paquetes nativos y vuelve a abrir el expediente creado por el ZIP de Windows.
35. **Relaciones de activos.** La 0.4.25 abre relaciones de DNS, RDAP, redes y huellas STIX desde el inspector y desde el CLI. El informe ordena por registros de soporte, conserva las citas y permite acotar por las fechas guardadas. Las pruebas cubren la dirección del vínculo, el orden de las citas, los nombres de servicio DNS, las relaciones omitidas y la paridad tras migrar a PostgreSQL.
36. **Comparación de secciones binarias.** La 0.4.26 confronta los inventarios completos de dos originales verificados contra las revisiones guardadas. Distingue movimiento, cambios de bytes y tamaño, altas, ausencias y coincidencias ambiguas. La mesa abre ambas secciones y exporta el mismo resultado que el CLI. Las pruebas incluyen archivos invertidos, inspecciones alteradas y reordenamiento de imágenes Mach-O universales.
37. **Capacidad de escritura.** Repetir la prueba con carga sostenida y medir el efecto del almacenamiento del WAL.

## Medición de consultas por fecha

Se midieron expedientes de 1,000, 10,000 y 50,000 registros en Windows x64 con almacén local y PostgreSQL 17.12. Cada muestra es la mediana de siete peticiones al servidor después de una petición de calentamiento. Las capturas tenían 1,000 registros por día, guardados en un lote por día. La comparación por origen tenía una observación coincidente.

| Consulta con 50,000 registros | Local 0.4.8 | Local 0.4.9 | PostgreSQL 0.4.8 | PostgreSQL 0.4.9 |
| --- | --- | --- | --- | --- |
| Comparación por origen | 706 ms | 30 ms | 859 ms | 128 ms |
| Comparación de dos días | 718 ms | 60 ms | 909 ms | 139 ms |
| Cobertura de activos de un día | 422 por límite | 23 ms | 422 por límite | 94 ms |

Las 34 respuestas exitosas de la versión anterior coincidieron byte a byte con la nueva versión. En el expediente mayor el pico de memoria del ejecutable fue de 39.9 MiB con archivos y 38.1 MiB con PostgreSQL. La medida corresponde al proceso de la aplicación. El historial HTTP sin acotar tomó unos 690 ms con archivos y 208 ms con PostgreSQL en la misma prueba.

Repite la medición local de los informes con `go test ./internal/analisis -run '^$' -bench '^BenchmarkEvidenceWindows$' -benchtime=5x -benchmem`.

## Medición de comparaciones HTTP amplias

Se probaron 1,000, 10,000 y 50,000 observaciones sintéticas de HAR y proxy con ocho orígenes en Windows x64 y PostgreSQL 17.12 local. Cada valor es el promedio de siete operaciones tras una de calentamiento. En el expediente mayor, la consulta acotada selecciona 125 observaciones de un origen por periodo. La consulta amplia abarca las 50,000 observaciones repartidas entre ambos tipos de captura. La memoria asignada por operación se mide con `-benchmem`.

| Consulta con 50,000 observaciones disponibles | Local 0.4.22 | Local 0.4.23 | PostgreSQL 0.4.22 | PostgreSQL 0.4.23 |
| --- | --- | --- | --- | --- |
| Dos ventanas de un día | 11.5 ms | 11.0 ms · 3.9 MiB | 75.0 ms | 40.0 ms · 3.7 MiB |
| Ambos tipos de captura durante 50 días | Límite de 10,000 | 500 ms · 214.6 MiB | Límite de 10,000 | 575 ms · 210.9 MiB |

Una prueba con 12,000 entradas HAR y dos observaciones del proxy comparó el JSON de la mesa y del CLI antes y después de migrar a PostgreSQL. Los informes de formato 1 coincidieron byte a byte con la 0.4.22. La mesa reabrió el informe de formato 2 y saltó a la cabecera de la respuesta citada.

Repite la medición con `go test ./internal/analisis -run '^$' -bench '^BenchmarkHTTPComparisonScale$' -benchtime=7x -benchmem`. Usa una base de pruebas con `PAVAROTTI_TEST_POSTGRES` para incluir PostgreSQL.

## Medición del historial HTTP

Se probaron los mismos tamaños y se compararon 24 respuestas completas entre 0.4.9 y 0.4.10. Cada mediana usa siete peticiones después de una inicial. PostgreSQL recibió los lotes desde la versión anterior antes de instalar el índice.

| Expediente de 50,000 registros | Local 0.4.9 | Local 0.4.10 | PostgreSQL 0.4.9 | PostgreSQL 0.4.10 |
| --- | --- | --- | --- | --- |
| Primera página después de cargar el índice | 674 ms | 0.70 ms | 201 ms | 1.29 ms |
| Segunda página | 672 ms | 0.83 ms | 243 ms | 1.34 ms |
| Fecha y regla HTTP | 677 ms | 7.16 ms | 76 ms | 2.34 ms |

La primera apertura local creó la caché en 589 ms y el pico de memoria del proceso llegó a 58 MiB. La primera consulta del expediente anterior en PostgreSQL tardó 2.9 s al rellenar el índice. La búsqueda de texto tardó unos 942 ms con la 0.4.10.

Repite la medición local de paginación con `go test ./internal/caso -run '^$' -bench '^BenchmarkHistoryPages$' -benchtime=5x -benchmem`.

## Medición de la búsqueda literal

La prueba usó 1,000, 10,000 y 50,000 capturas más dos registros de notas y dependencias por expediente. Las respuestas paginadas coincidieron con 0.4.10. Cada valor de la tabla es la mediana de cinco peticiones con la caché o el índice preparado.

| Consulta con 50,000 capturas | Local 0.4.10 | Local 0.4.11 | PostgreSQL 0.4.10 | PostgreSQL 0.4.11 |
| --- | --- | --- | --- | --- |
| Origen HTTP | 788 ms | 10 ms | 972 ms | 14 ms |
| Dependencia de reemplazo | 783 ms | 9 ms | 958 ms | 2.4 ms |
| Fragmento literal con `%` y `_` | 785 ms | 10 ms | 974 ms | 1.9 ms |

La caché local del expediente mayor elevó el pico del proceso a 57 MiB. En PostgreSQL el índice y su tabla ocuparon 91 MiB. La preparación del expediente existente tardó 43 s en segundo plano. Durante ese tiempo, la primera consulta tardó 1.0 s. También se comprobó la búsqueda en PostgreSQL con una cuenta de esquema que carecía de permisos para instalar `pg_trgm`.

Para repetir la medición local de texto usa `go test ./internal/caso -run '^$' -bench 'BenchmarkHistoryPages/.*/texto_origen' -benchtime=5x -benchmem`.

## Medición del respaldo y la restauración

Se midió una ejecución del CLI por operación y tamaño en Windows x64 con PostgreSQL 17.12 local. Los expedientes sintéticos tenían 1,000, 10,000 o 50,000 capturas HTTP y el mismo número de eventos de auditoría, además de una nota con dos revisiones. La copia mayor pesó 30.3 MiB.

| Operación con 50,000 capturas y 50,000 eventos | 0.4.11 | 0.4.12 |
| --- | --- | --- |
| Crear respaldo | 0.99 s | 2.32 s |
| Verificar SHA-256 y recuentos | 0.42 s | 0.42 s |
| Restaurar en un expediente vacío | 46.26 s | 3.75 s |
| Aplicar retención | 1.06 s | 1.15 s |

Con 1,000 capturas la restauración pasó de 0.58 a 0.10 s y con 10,000 de 9.53 a 0.58 s. Con la copia mayor, el pico del proceso restaurador en 0.4.12 fue de 27.1 MiB. La medición termina al confirmar la evidencia y deja fuera la preparación posterior de los índices. Se conservaron el SHA-256 y los recuentos de la copia, se abrieron ambas revisiones en el destino y la retención retiró los 40,000 eventos previstos en el origen.

## Medición entre expedientes concurrentes

En PostgreSQL 17.12 local, una copia de 23.4 MiB contenía 50,000 capturas HTTP, 50,000 eventos de auditoría y una tarea. En otro expediente con 10,000 capturas, la mesa consultó páginas de historial y guardó notas. Cuatro procesos nuevos ejecutaron `actividad --limite 1` al detectar que la restauración había empezado a insertar tareas. La tabla muestra la mediana de esos cuatro comandos de terminal.

| Restauraciones simultáneas | 0.4.12 | 0.4.13 |
| --- | --- | --- |
| Sin restauración, muestra de control | 90 ms | |
| Una restauración | 1,930 ms | 101 ms |
| Dos restauraciones | 3,543 ms | 268 ms |

PostgreSQL registró esperas de bloqueo en `CREATE UNIQUE INDEX IF NOT EXISTS` con 0.4.12. Esa espera desapareció con 0.4.13. Con dos restauraciones, la mediana de lectura desde la mesa fue de 15 ms en la segunda pasada. El guardado de notas alcanzó un máximo de 0.94 s en esa pasada y de 2.54 s en la primera. PostgreSQL siguió registrando esperas de escritura y sincronización del WAL. Las restauraciones conservaron la huella y los recuentos de la copia.

## Medición del inventario de activos

Se midieron 1,000 y 50,000 observaciones DNS sintéticas en Windows x64 con almacén local y PostgreSQL 17.12. Cada expediente incluye una IP con evidencia DNS y un indicador, un rango RDAP y un prefijo STIX. La tabla muestra el promedio de siete operaciones con 50,000 observaciones y la memoria asignada por operación según `-benchmem`. Los informes de cobertura consultan un día UTC con 1,000 observaciones y las cinco fuentes de control.

| Operación | Local | PostgreSQL |
| --- | --- | --- |
| Primera página del inventario | 187 ms · 82.5 MiB | 198 ms · 91.6 MiB |
| Ficha de IP | 204 ms · 82.5 MiB | 208 ms · 91.7 MiB |
| Ficha de rango RDAP | 135 ms · 71.0 MiB | 188 ms · 80.2 MiB |
| Ficha de prefijo STIX | 133 ms · 71.0 MiB | 157 ms · 80.2 MiB |
| Cobertura de IP por día | 4.12 ms · 1.70 MiB | 47.3 ms · 1.46 MiB |
| Cobertura RDAP por día | 3.42 ms · 1.49 MiB | 48.6 ms · 1.27 MiB |
| Cobertura STIX por día | 3.26 ms · 1.51 MiB | 49.2 ms · 1.27 MiB |

La 0.4.20 rechazaba el inventario y las fichas tras recorrer 10,000 registros. La 0.4.21 recorre los lotes del expediente y conserva los resultados de la página. En una prueba con 12,004 registros, el CLI y la mesa devolvieron las mismas fichas y citas tras la migración a PostgreSQL. Los tres informes de cobertura coincidieron byte a byte entre ambas versiones y almacenes. El informe de cobertura conserva su límite de 10,000 registros coincidentes por periodo y de 32 MiB de entrada.

Repite la medición con `go test ./internal/analisis -run '^$' -bench '^BenchmarkAssetScale$' -benchtime=7x -benchmem`. Con `PAVAROTTI_TEST_POSTGRES` configurado, usa una base de pruebas para los expedientes que crea el benchmark.

## Flujo de trabajo OSINT

1. **Incorporar.** Un expediente reúne indicadores, capturas HTTP, binarios, DNS, RDAP y paquetes STIX aportados por el analista. Las entradas conservan su huella y sus referencias de origen cuando el formato las proporciona.
2. **Examinar.** La mesa de trabajo conserva la lista central, el inspector y las tareas. El historial HTTP reúne proxy y HAR y filtra sus respuestas por clase de estado. Las referencias de la cronología, señales y coincidencias abren la revisión citada en el inspector.
3. **Correlacionar.** Los agentes agrupan la evidencia por activo, respuesta HTTP e indicador. Los resultados quedan asociados a la versión del agente y a la huella de entrada.
4. **Entregar.** El analista verifica coincidencias, añade notas y prepara un paquete STIX 2.1 para intercambiar metadatos con referencias al expediente. Los créditos del binario quedan accesibles en su panel propio.

## Próximas vistas de la mesa

| Vista | Trabajo pendiente | Criterio de cierre |
| --- | --- | --- |
| Activos y fuentes | Reducir el tiempo de consulta al navegar entre activos de expedientes grandes | Medir fichas con pocas coincidencias durante consultas concurrentes y comprobar orden, recuentos y revisiones tras importar evidencia o editar una nota. |
| Triaje de binarios | Medir comparaciones de referencias de gran tamaño | Registrar duración y memoria al verificar informes de varios tamaños y comprobar que la mesa filtra y pagina sus orígenes. |
| Historial HTTP | Medir comparaciones simultáneas sobre un expediente grande | Registrar latencia y memoria con ventanas acotadas y amplias simultáneas y confirmar que cancelar una consulta libera sus recursos. |

## Ramas y commits

Usa ramas `blue-team/<capacidad>` para cambios que puedan revisarse por separado. Integra a `main` con la matriz verde. Escribe cada título en inglés sencillo, en cuatro o cinco palabras que describan el cambio. La meta de 1,000 commits se mide con `git rev-list --count main`.
