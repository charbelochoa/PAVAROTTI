# PAVAROTTI

```text
    .:--==:.    .:------------:.    .:----:.
    .:::-=++=::::------------==-::--=-::.
     -::...-==-:-==+===++=++=-------:...:
      -:--:.:::-+++**++++**++=+=---:::-.
       ::.:::-=*#*++*#***-+*#+==:::::.
         :::-+:+*+#+=#***=###+-+-::
          :--=-:...:-:+*+**+--::..:=-
          ---==--:-::-+++++*=:-=-:=+=
          ---+++*++==+==-=++*+=+++**=
          --=+++**+++=----==++++*+**=
          :--=====+=::..::::-=++**+==:
          ::---:-+=::...::.:.:-++*+==:
           ::-==-:==::..::::::::+*++*-
           :::-----=-:::::::::-=++++=
            ::----==----::---=+++=-
             :-----------=====-:
               :::---------:::
```

PAVAROTTI es la estación de investigación Blue Team del colectivo. Gestiona evidencia local y permite revisar tráfico web, hallazgos y binarios desde el mismo expediente.

La mesa de trabajo mantiene el expediente a la izquierda, los registros al centro y el inspector de evidencia a la derecha. La selección permanece visible al actualizar el expediente.

Usa **Anterior** y **Siguiente** para recorrer los resultados de 50 en 50. La búsqueda y el filtro se aplican al expediente completo. El inspector carga los detalles al seleccionar un registro y los mantiene visibles al cambiar de página.

El historial HTTP usa un índice de PostgreSQL para la navegación y los filtros estructurados. En los expedientes existentes, el índice se rellena por lotes al abrir el historial. El almacén local conserva en memoria las filas resumidas que ya leyó, con un presupuesto de caché de 32 MiB.

El buscador encuentra fragmentos literales, incluidos los caracteres `%` y `_`, en títulos, orígenes, detalles y datos de dependencias. La mesa prepara el índice de texto de PostgreSQL en segundo plano y admite búsquedas durante la preparación. PostgreSQL aprovecha `pg_trgm` cuando la instalación permite habilitarlo.

**Historial HTTP** reúne el proxy y los archivos HAR. Muestra método, estado, fecha, origen, tipo MIME, latencia y número de señales. Combina filtros por captura, método, clase de respuesta, fechas UTC y regla pasiva. El inspector muestra la cabecera observada y el motivo de cada señal. Desde un informe puedes abrir la respuesta citada y ver resaltada su regla.

En **Comparar capturas**, define el origen, el tipo de captura y las fechas UTC inclusivas de cada periodo. La tabla usa los registros guardados y muestra recuentos y diferencias por clase de respuesta, fallo del proxy y señal. **Con evaluación confirmada** cuenta las respuestas cuyo registro identifica la aplicación de reglas. Las señales históricas siguen visibles aunque falte ese dato. Cada fila admite hasta cinco citas por periodo a la revisión original. El informe admite hasta 10,000 observaciones distintas, 32 MiB de entrada y 100 filas de resultados.

Usa **Exportar JSON** para conservar los criterios, resultados, citas y la huella de entrada. **Abrir informe JSON** recupera ese resultado guardado con sus criterios, incluso si el expediente ya incorporó capturas nuevas. Abre las citas desde el expediente que contiene la evidencia.

La comparación HTTP y la cobertura por periodo admiten expedientes de más de 10,000 registros cuando los criterios seleccionan hasta 10,000 entradas de evidencia y 32 MiB de metadatos. Las ventanas usan la fecha UTC de cada registro.

- **Tráfico.** Proxy inverso HTTP(S) de un solo destino e importación de HAR. Las reglas pasivas comprueban tipo MIME, `nosniff`, controles de marcos, `Referrer-Policy`, `max-age` de HSTS, redirecciones a HTTP y atributos de cookies. El expediente guarda los recuentos de cookies, el origen y el motivo de cada señal.
- **Evidencia.** Importación de hallazgos JSON con huella SHA-256 del archivo y búsqueda por texto, origen, ID o huella. También puedes registrar notas manuales.
- **Binarios.** Triaje estático de cabeceras PE, ELF y Mach-O. Consulta hasta 256 secciones, 128 vistas previas de cadenas ASCII y 2,048 símbolos definidos por archivo. El inspector busca símbolos en las tablas ELF, COFF y Mach-O y muestra su desplazamiento cuando la sección tiene respaldo físico. La huella SHA-256 abre la ficha del activo.
- **Citas de binarios.** Usa **Exportar cita** desde una sección, cadena o símbolo con desplazamiento. En **Binarios → Abrir cita JSON**, la mesa verifica la huella del archivo, la huella del análisis guardado y la revisión, y señala la ubicación exacta. Una cita incluye referencias y desplazamientos.
- **Símbolos PE y Mach-O.** Los binarios PE muestran las exportaciones por nombre y ordinal, incluidos sus reenvíos. Un reenvío indica otro símbolo y aparece sin cita de bytes locales. En Mach-O universal, **Imagen Mach-O** filtra secciones, cadenas y símbolos por arquitectura y subtipo. Las citas conservan el desplazamiento dentro del archivo universal y seleccionan la imagen correspondiente al abrirse. Las inspecciones guardadas en versiones anteriores conservan sus metadatos y citas.
- **Indicadores.** Importa dominios, direcciones IP y huellas desde un archivo de texto, un valor por línea. El informe correlaciona dominios e IP con los activos que ya constan en el expediente y cita los registros que justifican cada coincidencia.
- **DNS.** Carga una respuesta DNS en JSON o un arreglo de respuestas con `Status`, `Question` y `Answer`. La vista **DNS** conserva valores, TTL, respuestas negativas y huella del archivo. Los destinos de A, AAAA, CNAME, NS, PTR, MX y SRV entran en el inventario de activos del expediente.
- **RDAP.** Importa archivos JSON de dominio, resultados de búsqueda de dominios y rangos IP. El inspector conserva la posición en el archivo, su huella, servidores de nombre, estados y fechas del registro. La importación omite las fichas de contacto y los enlaces del archivo.
- **STIX 2.1.** Importa paquetes JSON con dominios, direcciones, prefijos IP, relaciones y periodos de observación. Reconoce indicadores por igualdad simple de dominio, IP o huella. El informe cruza dominios y direcciones exactas con el expediente. Los patrones complejos se conservan por ID para revisión en el archivo de origen.
- **Activos.** Busca dominios, direcciones, redes y huellas. Cada ficha muestra las fechas y distingue observaciones de tráfico o DNS, registros RDAP, declaraciones STIX, indicadores y referencias manuales. Las fichas de IP muestran los rangos RDAP y prefijos STIX que las cubren. Abre desde la ficha la revisión de evidencia que sustenta cada fuente.
- **Cobertura por periodo.** Desde una ficha de red, abre **IP observadas** para navegar las direcciones registradas en respuestas DNS o HTTP, en orden numérico y con sus citas. **Cobertura por periodo** usa las fechas guardadas en el expediente y guarda las fuentes, las coincidencias y la huella de entrada en un informe JSON. Las fechas UTC son inclusivas. Puedes reabrir el informe en el expediente original o en su restauración. El informe muestra hasta 100 fuentes, 100 direcciones y cinco citas por dirección e indica cuántas filas adicionales existen.
- **Relaciones STIX.** El inspector recorre enlaces entrantes y salientes de relaciones, observaciones y observables importados. La referencia indica si procede del mismo paquete, de otro paquete del expediente o si falta importar el objeto.
- **Intercambio STIX 2.1.** Usa **Exportar STIX** para descargar observaciones DNS y HTTP, dominios, IP, prefijos, huellas, indicadores literales y relaciones compatibles con citas de origen. El resultado indica cuántos registros representa. La importación muestra cuántos registros guardó y cuántos pertenecían a un archivo ya registrado.
- **Análisis.** Los agentes de inventario, señales HTTP, cronología y correlación trabajan en paralelo sobre la evidencia del expediente. El revisor de código Go añade señales con línea y columna sin compilar ni ejecutar la fuente.
- **Revisión estática.** Incorpora archivos Go para revisar configuraciones TLS, plazos HTTP, invocación de procesos y HMAC heredado. Las señales se abren desde el informe en sus líneas y columnas físicas. El inspector muestra hasta 250 señales por archivo, con su total separado.
- **Revisión por directorio.** Selecciona un directorio en la mesa o usa `revisar`. Admite archivos Go, `go.mod` y `package-lock.json`, conserva sus rutas relativas y muestra el resultado de cada archivo. Omite `.git`, `node_modules` y `vendor`. La terminal también omite enlaces simbólicos. Se pueden revisar hasta 200 archivos compatibles y 32 MiB por selección.
- **Triaje de señales.** Desde el inspector puedes registrar una señal como pendiente, confirmada o descartada. Cada decisión guarda su justificación, hora y revisión. El historial queda asociado a la línea y columna de la evidencia y se conserva al migrar un expediente a PostgreSQL.
- **Dependencias.** Incorpora `go.mod` o `package-lock.json` v2 y v3 para consultar versiones declaradas, alcance, reemplazos y la posición de cada entrada. El inventario usa solo el contenido del manifiesto y se puede buscar por nombre, versión o reemplazo. Cada manifiesto admite hasta 4 MiB y 5,000 entradas.
- **Cruces en el informe.** Los informes incluyen coincidencias SHA-256 entre muestras e indicadores y cobertura de IP observadas por DNS o HTTP dentro de rangos RDAP y prefijos STIX. Cada cruce lleva citas a las revisiones del expediente.
- **Trazabilidad.** Cada análisis identifica la versión de sus agentes y la huella de su instantánea. En **Referencias de evidencia**, elige una sección y abre en el inspector la revisión citada. Puedes consultar esa revisión después de editar una nota y saltar de nuevo a la versión vigente.
- **Tareas de análisis.** Con PostgreSQL puedes encolar informes por prioridad, cancelar tareas y abrir los resultados incluso después de reiniciar la aplicación.
- **Actividad.** Con PostgreSQL, la mesa y la terminal consultan incorporaciones de evidencia, notas, triaje, migraciones y cambios de estado de la cola. Cada evento se guarda con la operación y muestra su hora, el operador y la revisión o tarea correspondiente.
- **Edición.** Las notas conservan su historial. Una edición requiere la revisión vigente para evitar sobrescribir cambios. Los hallazgos importados conservan su huella y procedencia.

## Uso

En Windows abre `PAVAROTTI.exe`. En Kali o Arch, copia el ejecutable a un volumen con permisos de ejecución y ábrelo con `./PAVAROTTI-Kali-x64`. Si la copia perdió el permiso, usa `chmod +x PAVAROTTI-Kali-x64`. El programa abre el navegador en una dirección de tu equipo y muestra esa misma URL en la terminal. Elige **Créditos** para consultar la atribución.

Para guardar un expediente en una ruta específica y observar un servicio que administras, ejecuta el binario con estas opciones. En Windows, usa el nombre del archivo `.exe`.

```sh
./PAVAROTTI-Kali-x64 -datos ./expediente -destino http://127.0.0.1:8080
```

En la interfaz, selecciona **Abrir el destino mediante el proxy**. El proxy se activa únicamente al indicar `-destino`. Para observar un servicio HTTPS conserva la verificación TLS de la conexión saliente. Si la aplicación depende de cookies `Secure` o de su origen original, importa un HAR desde el navegador. El expediente registra metadatos de tráfico y señales. Las notas y hallazgos JSON conservan el texto que decidas incorporar.

## Terminal

Usa el nombre del ejecutable de tu plataforma en lugar de `pavarotti` en estos ejemplos. Coloca las opciones globales como `-datos`, `-postgres` y `-expediente` antes del comando.

```sh
pavarotti ayuda
pavarotti -datos ./expediente importar indicadores indicadores.txt
pavarotti -datos ./expediente importar dns observaciones.json
pavarotti -datos ./expediente importar rdap registro-dominio.json
pavarotti -datos ./expediente importar stix indicadores-stix.json
pavarotti -datos ./expediente listar --tipo har --regla-http hsts-ausente --json
pavarotti -datos ./expediente comparar-http --origen-a https://example.invalid --captura-a har --desde-a 2026-11-01 --hasta-a 2026-11-07 --origen-b https://example.invalid --captura-b har --desde-b 2026-11-08 --hasta-b 2026-11-14 --salida comparacion.json
pavarotti -datos ./expediente importar codigo revision.go
pavarotti -datos ./expediente citar-binario --id ID --revision 1 --tipo cadena --indice 0 --salida cita.json
pavarotti -datos ./expediente importar gomod go.mod
pavarotti -datos ./expediente importar npmlock package-lock.json
pavarotti -datos ./expediente revisar --json ./proyecto
pavarotti -datos ./expediente triaje --id ID --regla http-cliente-timeout --linea 3 --columna 9
pavarotti -datos ./expediente nota --titulo "Turno de revisión" --texto "Validación manual pendiente"
pavarotti -datos ./expediente listar --buscar "validación" --json
pavarotti -datos ./expediente activos --tipo dominio --buscar example.invalid
pavarotti -datos ./expediente activos --tipo ipv4 --valor 192.0.2.17 --json
pavarotti -datos ./expediente activos --tipo red --valor 192.0.2.0/24 --observadas --json
pavarotti -datos ./expediente cobertura-activo --tipo red --valor 192.0.2.0/24 --desde 2026-11-01 --hasta 2026-11-30 --salida cobertura.json
pavarotti -datos ./expediente analizar --json
pavarotti -datos ./expediente exportar --formato csv --salida expediente.csv
pavarotti -datos ./expediente exportar --formato stix --salida expediente-stix.json
pavarotti -datos ./expediente-destino importar stix expediente-stix.json
```

Usa `editar --id ID --revision N --texto "Nueva observación"` con el ID y la revisión de `listar`. Consulta versiones previas con `historial --id ID`.

## PostgreSQL y Docker

El ejecutable usa almacenamiento local por defecto. Para compartir un expediente entre la interfaz y el CLI, configura `PAVAROTTI_POSTGRES` con la URL de conexión o pasa `-postgres`. Ambos leen y guardan los mismos registros cuando usan la misma base de datos y el mismo nombre en `-expediente`. El usuario de PostgreSQL necesita permisos de creación de tablas para inicializar el esquema.

La actividad empieza al instalar la 0.4.2. Las operaciones del modo HTTPS se atribuyen a la cuenta de la sesión. La terminal, la instancia local y el ejecutor figuran con el rol de PostgreSQL que aplicó el cambio. El registro incluye metadatos y referencias de evidencia. En la terminal, `actividad --limite 50 --salida actividad.json` guarda una página. Pasa su campo `next` a `--antes` para consultar eventos anteriores.

### Respaldar y restaurar un expediente

La terminal guarda una instantánea de PostgreSQL con los lotes de evidencia, las revisiones de notas y triaje, las tareas con sus informes y la actividad. Los comandos muestran el expediente de origen, la fecha, la huella SHA-256 del contenido y el recuento por tipo de fila. `verificar-respaldo` comprueba el formato y la huella registrada al final de la copia. Funciona sin conexión a PostgreSQL.

```sh
PAVAROTTI_POSTGRES="$PG_ORIGEN" pavarotti -expediente incidente respaldar --salida incidente.jsonl
pavarotti verificar-respaldo --archivo incidente.jsonl
PAVAROTTI_POSTGRES="$PG_DESTINO" pavarotti -expediente incidente-restaurado restaurar --archivo incidente.jsonl
```

El destino debe ser un expediente vacío. La restauración conserva IDs, revisiones y citas y registra la huella del respaldo en **Actividad**. Las tareas que estaban en ejecución vuelven a la cola con los intentos disponibles. Si agotaron sus intentos, quedan registradas como fallidas. Aprovisiona las cuentas de acceso en el destino con `usuarios`.

La restauración valida la copia completa y guarda la evidencia en una sola transacción. La mesa reconstruye en segundo plano los índices de búsqueda e historial HTTP al consultarlos por primera vez en el destino. Las consultas pueden abrir la evidencia durante la reconstrucción.

Guarda la copia en el almacenamiento privado del expediente. El archivo contiene la evidencia y el historial de operaciones.

### Retener actividad

`retener-actividad` muestra cuántos eventos de auditoría son anteriores a una fecha. El corte es a las 00:00 UTC y conserva los eventos con la hora exacta del corte. Para aplicar la política, usa una copia del mismo expediente que incluya esos eventos.

```sh
pavarotti -expediente incidente retener-actividad --antes 2026-10-01
pavarotti -expediente incidente respaldar --salida antes-de-retener.jsonl
pavarotti -expediente incidente retener-actividad --antes 2026-10-01 \
  --aplicar --respaldo antes-de-retener.jsonl
```

La operación conserva la evidencia, sus IDs, las revisiones y las tareas. **Actividad** registra cuántos eventos se retiraron, la fecha de corte y la huella de la copia. Puedes restaurar esa copia en un expediente vacío para recuperar la actividad archivada. El operador conserva el archivo durante el plazo de custodia del expediente.

### Acceso al expediente por HTTPS

Con PostgreSQL, un operador puede crear cuentas desde la terminal. `lector` consulta evidencia, historial e informes y exporta STIX. `analista` también incorpora archivos, registra notas, clasifica señales y gestiona tareas. La cuenta pertenece al expediente indicado en `-expediente`. Cambiar el rol o la contraseña cierra las sesiones vigentes de esa cuenta.

```sh
pavarotti -expediente incidente-01 usuarios guardar --nombre investigacion --rol analista --clave-archivo /ruta/privada/clave
pavarotti -expediente incidente-01 usuarios listar
pavarotti -expediente incidente-01 usuarios rol --nombre investigacion --rol lector
pavarotti -expediente incidente-01 usuarios revocar --nombre investigacion
```

Configura `PAVAROTTI_POSTGRES` con la URL de PostgreSQL. Para leer su contraseña desde un archivo, indica `PAVAROTTI_DB_PASSWORD_FILE` con la ruta y usa una URL de conexión con el nombre de usuario. Inicia el servidor con un certificado válido para el host indicado en `-origen-publico`. La escucha se queda en `127.0.0.1` salvo que inicies con `-escuchar` y una dirección IPv4 explícita.

```sh
pavarotti servir -expediente incidente-01 -compartido -sin-navegador \
  -puerto-app 8443 -origen-publico https://127.0.0.1:8443 \
  -tls-certificado /ruta/certificado.pem -tls-clave /ruta/privada/tls.key
```

Ejecuta el proxy inverso en una instancia local. El acceso directo a PostgreSQL y los comandos de administración quedan a cargo del operador.

Con la conexión configurada, usa `pavarotti -expediente guardia migrar-local ./expediente` para copiar los registros y el historial local a PostgreSQL con los mismos IDs. Repetir la operación evita duplicados. Si el destino tiene una versión distinta del mismo registro, la transacción se cancela.

Con Docker Compose, define `PAVAROTTI_DB_PASSWORD` con una contraseña propia en `.env` y ejecuta:

```sh
docker compose up --build --wait
docker compose exec app pavarotti listar
docker compose exec app pavarotti analizar --json
```

La interfaz queda en `http://127.0.0.1:8080`. Define `PAVAROTTI_WEB_PORT` si ocupas otro puerto. PostgreSQL guarda el expediente en un volumen. Puedes parar los servicios con `docker compose down` y volver a abrirlos con el mismo expediente.

### Docker Compose con HTTPS

`compose.https.yaml` usa un volumen propio y publica HTTPS en `127.0.0.1` de forma predeterminada. Define en `.env` el origen que usará el navegador y las rutas de los archivos montados como secretos.

```dotenv
PAVAROTTI_EXPEDIENTE=incidente-01
PAVAROTTI_HTTPS_ORIGIN=https://127.0.0.1:8443
PAVAROTTI_DB_PASSWORD_FILE=/ruta/privada/postgres.password
PAVAROTTI_TLS_CERT_FILE=/ruta/privada/certificado.pem
PAVAROTTI_TLS_KEY_FILE=/ruta/privada/tls.key
```

El certificado PEM y su clave identifican el host del origen. El navegador debe confiar en la autoridad emisora. Escribe la contraseña de PostgreSQL en una sola línea UTF-8, con final LF o sin salto de línea. La imagen lee los secretos como `65532:65532`. En Linux puedes asignar el grupo numérico `65532` a los tres archivos y darles permisos `0640`. El puerto exterior se configura con `PAVAROTTI_HTTPS_PORT` y la IP del anfitrión con `PAVAROTTI_HTTPS_BIND`.

```sh
docker compose -f compose.https.yaml up --build --wait
docker compose -f compose.https.yaml exec -T app pavarotti -expediente incidente-01 \
  usuarios guardar --nombre investigacion --rol analista --clave-archivo - < /ruta/privada/analista.password
```

Abre `PAVAROTTI_HTTPS_ORIGIN` con la cuenta del expediente. El servicio PostgreSQL se comunica con la aplicación por la red de Compose. Para trasladar un expediente, monta su copia con permisos de lectura para `65532:65532` y restáurala en el volumen HTTPS.

```sh
docker compose -f compose.https.yaml run --rm \
  -v /ruta/privada/copia.jsonl:/respaldo.jsonl:ro app \
  -expediente incidente-01 restaurar --archivo /respaldo.jsonl
```

Con PostgreSQL, **Encolar análisis** guarda una instantánea del expediente. La sección **Tareas de análisis** muestra el estado, los intentos y el enlace al informe terminado. Una asignación abandonada vence a los 15 segundos desde la última renovación y puede recuperarse hasta completar tres intentos. La misma huella y versión reutilizan la tarea activa o el informe que ya existe. Si trabajas con un expediente en archivos locales, **Analizar expediente** sigue ejecutando el informe directamente.

```sh
pavarotti encolar --prioridad 2
pavarotti tareas
pavarotti informe ID
pavarotti cancelar ID
```

Conecta ambos procesos al mismo nombre de expediente si deseas separarlos. Inicia la aplicación con `-sin-ejecutor` y usa `pavarotti ejecutor` en el otro proceso. El analizador consume instantáneas preparadas con su misma versión de agentes.

## Compilar

Se requiere Go 1.25 o posterior. CI y el paquete Docker usan Go 1.26.11. Desde la raíz del repositorio:

```sh
go test ./...
go build -o PAVAROTTI .
```

En Windows, usa `-o PAVAROTTI.exe`. La interfaz y los créditos se incluyen en el ejecutable.

Consulta el [plan de evolución y la matriz de pruebas](PLAN.md).
