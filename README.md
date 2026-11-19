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

**Historial HTTP** reúne el proxy y los archivos HAR. Muestra método, estado, origen, tipo MIME, latencia y número de señales. Filtra por clase de respuesta y selecciona una fila para examinar sus señales sin salir de la mesa de trabajo.

- **Tráfico.** Proxy inverso HTTP(S) de un solo destino e importación de HAR. El expediente registra origen, estado HTTP, tipo MIME, latencia y señales de configuración. Las señales sirven para priorizar la revisión manual.
- **Evidencia.** Importación de hallazgos JSON con huella SHA-256 del archivo y búsqueda por texto, origen, ID o huella. También puedes registrar notas manuales.
- **Binarios.** Triaje estático de cabeceras y secciones PE, ELF y Mach-O con SHA-256.
- **Indicadores.** Importa dominios, direcciones IP y huellas desde un archivo de texto, un valor por línea. El informe correlaciona dominios e IP con los activos que ya constan en el expediente y cita los registros que justifican cada coincidencia.
- **DNS.** Carga una respuesta DNS en JSON o un arreglo de respuestas con `Status`, `Question` y `Answer`. La vista **DNS** conserva valores, TTL, respuestas negativas y huella del archivo. Los destinos de A, AAAA, CNAME, NS, PTR, MX y SRV entran en el inventario de activos del expediente.
- **RDAP.** Importa archivos JSON de dominio, resultados de búsqueda de dominios y rangos IP. El inspector conserva la posición en el archivo, su huella, servidores de nombre, estados y fechas del registro. La importación omite las fichas de contacto y los enlaces del archivo.
- **STIX 2.1.** Importa paquetes JSON con dominios, direcciones, prefijos IP, relaciones y periodos de observación. Reconoce indicadores por igualdad simple de dominio, IP o huella. El informe cruza dominios y direcciones exactas con el expediente. Los patrones complejos se conservan por ID para revisión en el archivo de origen.
- **Activos.** Busca dominios, direcciones, redes y huellas. Cada ficha muestra las fechas y distingue observaciones de tráfico o DNS, registros RDAP, declaraciones STIX, indicadores y referencias manuales. Las fichas de IP muestran los rangos RDAP y prefijos STIX que las cubren. Abre desde la ficha la revisión de evidencia que sustenta cada fuente.
- **Análisis.** Tres agentes locales de inventario, señales HTTP y cronología trabajan en paralelo sobre la evidencia del expediente. El revisor de código Go añade señales con línea y columna sin compilar ni ejecutar la fuente.
- **Trazabilidad.** Cada análisis identifica la versión de sus agentes y la huella de su instantánea. En **Referencias de evidencia**, elige una sección y abre en el inspector la revisión citada. Puedes consultar esa revisión después de editar una nota y saltar de nuevo a la versión vigente.
- **Tareas de análisis.** Con PostgreSQL puedes encolar informes por prioridad, cancelar tareas y abrir los resultados incluso después de reiniciar la aplicación.
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
pavarotti -datos ./expediente importar codigo revision.go
pavarotti -datos ./expediente nota --titulo "Turno de revisión" --texto "Validación manual pendiente"
pavarotti -datos ./expediente listar --buscar "validación" --json
pavarotti -datos ./expediente analizar --json
pavarotti -datos ./expediente exportar --formato csv --salida expediente.csv
```

Usa `editar --id ID --revision N --texto "Nueva observación"` con el ID y la revisión de `listar`. Consulta versiones previas con `historial --id ID`.

## PostgreSQL y Docker

El ejecutable usa almacenamiento local por defecto. Para compartir un expediente entre la interfaz y el CLI, configura `PAVAROTTI_POSTGRES` con la URL de conexión o pasa `-postgres`. Ambos leen y guardan los mismos registros cuando usan la misma base de datos y el mismo nombre en `-expediente`. El usuario de PostgreSQL necesita permisos de creación de tablas para inicializar el esquema.

Con la conexión configurada, usa `pavarotti -expediente guardia migrar-local ./expediente` para copiar los registros y el historial local a PostgreSQL con los mismos IDs. Repetir la operación evita duplicados. Si el destino tiene una versión distinta del mismo registro, la transacción se cancela.

Con Docker Compose, define `PAVAROTTI_DB_PASSWORD` con una contraseña propia en `.env` y ejecuta:

```sh
docker compose up --build --wait
docker compose exec app pavarotti listar
docker compose exec app pavarotti analizar --json
```

La interfaz queda en `http://127.0.0.1:8080`. Define `PAVAROTTI_WEB_PORT` si ocupas otro puerto. PostgreSQL guarda el expediente en un volumen. Puedes parar los servicios con `docker compose down` y volver a abrirlos con el mismo expediente.

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
