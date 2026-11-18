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

## Procedencia

- Ghidra es un proyecto de la National Security Agency publicado bajo Apache-2.0. [Repositorio de Ghidra](https://github.com/NationalSecurityAgency/ghidra/tree/Ghidra_12.2_build)
- El repositorio de BaaRai se identifica como traducción del proyecto de Autumn-27 bajo AGPL-3.0. La integración toma el contrato de exportación y adapta sus reglas de presentación. [Revisión de ARTEX](https://github.com/BaaRai/ARTEX/tree/d89cf781b790ec9a1d071bee7e79de489ed05252)
- El retrato «Detalle» y el sello pertenecen a la identidad de Pavarotti en el sitio de Charbel Ochoa. [Retrato ASCII original](https://charbelochoa.com/assets/identity/signal.svg) · [Sello](https://charbelochoa.com/favicon.png)
