# PAVAROTTI

Estación de trabajo local para investigar fuentes abiertas y contrastar hallazgos de ARTEX con binarios en Ghidra. La interfaz es el CodeBrowser de Ghidra, con sus ventanas de listado y decompilación y un panel acoplable en español para las evidencias.

## Arquitectura

| Componente | Función |
| --- | --- |
| Distribución de Ghidra 12.2 | Gestiona proyectos, programas, direcciones y marcadores. |
| Extensión PAVAROTTI | Lee la exportación JSON de **Findings → Export** de ARTEX. Presenta activos, hallazgos, estado de verificación y evidencias relacionadas. |
| Archivo de fuentes | Conserva cada exportación con su SHA-256 junto al proyecto. El marcador de una dirección identifica la fuente y el hallazgo. |
| Lanzador | Arranca la interfaz con el JDK incluido. Windows 10 x64 usa un ejecutable PE. Kali y Arch x86-64 comparten un ejecutable ELF. |

La integración de ARTEX es de lectura local. El operador elige los documentos, revisa las atribuciones de la fuente y decide qué dirección vincular. El motor autónomo de pentesting de ARTEX queda fuera de esta edición.

## Abrir PAVAROTTI

| Sistema | Paquete de `dist/` | Inicio |
| --- | --- | --- |
| Windows 10 x64 | `PAVAROTTI-windows-x64.zip` | Extrae el ZIP completo en una ruta corta y abre `PAVAROTTI.exe`. |
| Kali Linux o Arch Linux x86-64 | `PAVAROTTI-linux-x64.tar.gz` | En tu sesión gráfica, ejecuta `tar -xzf PAVAROTTI-linux-x64.tar.gz` y luego `./PAVAROTTI/PAVAROTTI`. |

Mantén el lanzador junto a las carpetas `ghidra` y `runtime`. El escritorio de Linux necesita X11 o XWayland y las bibliotecas habituales de fuentes, GTK y X11. Para comprobar la instalación desde una terminal, ejecuta el lanzador con `--check`. También admite la ruta a un proyecto `.gpr`.

1. En el gestor de proyectos de Ghidra elige **File → New Project → Non-Shared Project** y selecciona una carpeta local. Abre **CodeBrowser** desde el **Tool Chest**.
2. En el panel **PAVAROTTI**, selecciona **Importar ARTEX…**. Usa el JSON de **Findings → Export → JSON** o prueba con `ejemplos/hallazgos.json`. **Registrar fuente…** permite anotar una URL, un título y una cita observada. El registro es local y la aplicación guarda la URL tal como la introduces.
3. Selecciona un hallazgo para ver evidencia, activos y procedencia. **Buscar** filtra la tabla y **Actualizar** relee las fuentes del proyecto.
4. Para asociar un hallazgo a un binario, importa el archivo en Ghidra y ábrelo en el mismo CodeBrowser. Selecciona una dirección en **Listing**, elige el hallazgo y pulsa **Vincular dirección**. Guarda el programa. **Window → Bookmarks** permite volver a esa dirección. La categoría del marcador incluye el SHA-256 y el ID de la fuente.

Para respaldar el trabajo, conserva juntos `<proyecto>.gpr`, `<proyecto>.rep/` y `<proyecto>.pavarotti/`. La última carpeta contiene los documentos originales. Las importaciones admiten hasta 16 MiB por archivo y se deduplican por contenido. El estado «Verificado» reproduce el valor declarado por ARTEX.

## Compilar

En Windows o Linux x86-64 se necesitan Python 3.12 o posterior, Go 1.22 o posterior y conexión para la primera descarga. Desde la raíz del repositorio ejecuta:

```sh
python scripts/build.py
```

El script verifica las huellas de Ghidra y Temurin, compila la extensión, ejecuta las pruebas del importador y genera los dos paquetes y sus archivos `.sha256` en `dist/`. Usa `--target windows` o `--target linux` para compilar uno. En Linux puedes verificar el paquete con `sha256sum -c PAVAROTTI-linux-x64.tar.gz.sha256` desde `dist/`. En Windows compara `Get-FileHash .\PAVAROTTI-windows-x64.zip` con el archivo `.sha256` adyacente.

## Procedencia

- Ghidra es un proyecto de la National Security Agency publicado bajo Apache-2.0. [Repositorio de Ghidra](https://github.com/NationalSecurityAgency/ghidra/tree/Ghidra_12.2_build)
- El repositorio de BaaRai se identifica como traducción del proyecto de Autumn-27 bajo AGPL-3.0. La integración toma el contrato de exportación y adapta sus reglas de presentación. [Revisión de ARTEX](https://github.com/BaaRai/ARTEX/tree/d89cf781b790ec9a1d071bee7e79de489ed05252)
- El retrato «Detalle» y el sello pertenecen a la identidad de Pavarotti en el sitio de Charbel Ochoa. [Retrato ASCII original](https://charbelochoa.com/assets/identity/signal.svg) · [Sello](https://charbelochoa.com/favicon.png)
