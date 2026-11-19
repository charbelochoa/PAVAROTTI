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

- **Tráfico.** Proxy inverso HTTP(S) de un solo destino e importación de HAR. El expediente registra origen, estado HTTP, tipo MIME, latencia y señales de configuración. Las señales sirven para priorizar la revisión manual.
- **Evidencia.** Importación de hallazgos JSON con huella SHA-256 del archivo y búsqueda por texto, origen, ID o huella. También puedes registrar notas manuales.
- **Binarios.** Triaje estático de cabeceras y secciones PE, ELF y Mach-O con SHA-256.

## Uso

En Windows abre `PAVAROTTI.exe`. En Kali o Arch, copia el ejecutable a un volumen con permisos de ejecución y ábrelo con `./PAVAROTTI-Kali-x64`. Si la copia perdió el permiso, usa `chmod +x PAVAROTTI-Kali-x64`. El programa abre el navegador en una dirección de tu equipo y muestra esa misma URL en la terminal. Elige **Créditos** para consultar la atribución.

Para guardar un expediente en una ruta específica y observar un servicio que administras, ejecuta el binario con estas opciones. En Windows, usa el nombre del archivo `.exe`.

```sh
./PAVAROTTI-Kali-x64 -datos ./expediente -destino http://127.0.0.1:8080
```

En la interfaz, selecciona **Abrir el destino mediante el proxy**. El proxy se activa únicamente al indicar `-destino`. Para observar un servicio HTTPS conserva la verificación TLS de la conexión saliente. Si la aplicación depende de cookies `Secure` o de su origen original, importa un HAR desde el navegador. El expediente registra metadatos de tráfico y señales. Las notas y hallazgos JSON conservan el texto que decidas incorporar.

## Compilar

Se requiere Go 1.24 o posterior. Desde la raíz del repositorio:

```sh
go test ./...
go build -o PAVAROTTI .
```

En Windows, usa `-o PAVAROTTI.exe`. La interfaz y los créditos se incluyen en el ejecutable.
