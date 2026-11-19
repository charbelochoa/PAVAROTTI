package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"pavarotti/internal/analisis"
	"pavarotti/internal/caso"
	"pavarotti/internal/config"
	"pavarotti/internal/mesa"
	"pavarotti/internal/terminal"
	"pavarotti/internal/trafico"
)

const version = "0.4.16"

//go:embed ui/* licenses/*
var resources embed.FS

func main() {
	directory := flag.String("datos", "", "carpeta del expediente local")
	postgres := flag.String("postgres", os.Getenv("PAVAROTTI_POSTGRES"), "DSN PostgreSQL")
	caseName := flag.String("expediente", "principal", "nombre del expediente en PostgreSQL")
	publishPort := flag.Int("publicar-local", 0, "puerto del host para la interfaz en Docker")
	upstream := flag.String("destino", "", "origen HTTP(S) del proxy inverso")
	proxyPort := flag.Int("puerto-proxy", 0, "puerto local del proxy")
	uiPort := flag.Int("puerto-app", 0, "puerto local de la interfaz")
	noBrowser := flag.Bool("sin-navegador", false, "muestra la URL local en la terminal")
	noWorker := flag.Bool("sin-ejecutor", false, "separa el servidor web del ejecutor de análisis")
	shared := flag.Bool("compartido", false, "habilita cuentas y permisos del expediente por HTTPS")
	webBind := flag.String("escuchar", "", "dirección IPv4 para el modo compartido")
	public := flag.String("origen-publico", "", "URL HTTPS externa del modo compartido")
	certificate := flag.String("tls-certificado", "", "archivo PEM del certificado TLS")
	certificateKey := flag.String("tls-clave", "", "archivo PEM de la clave TLS")
	showVersion := flag.Bool("version", false, "muestra la versión")
	args := os.Args[1:]
	if len(args) > 0 && args[0] == "servir" {
		args = args[1:]
	}
	if err := flag.CommandLine.Parse(args); err != nil {
		log.Fatal(err)
	}
	if *showVersion {
		fmt.Println("PAVAROTTI " + version)
		return
	}
	openStore := func() (*caso.Store, error) {
		if *postgres != "" {
			password, err := databasePassword()
			if err != nil {
				return nil, err
			}
			dsn, err := databaseURL(*postgres, password)
			if err != nil {
				return nil, err
			}
			ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
			defer cancel()
			return caso.OpenPostgres(ctx, dsn, *caseName)
		}
		if *directory != "" {
			return caso.Open(*directory)
		}
		config, err := os.UserConfigDir()
		if err != nil {
			return nil, err
		}
		return caso.Open(filepath.Join(config, "PAVAROTTI", "expediente"))
	}
	if args := flag.Args(); len(args) > 0 && args[0] != "servir" {
		handled, err := terminal.Run(args, os.Stdout, os.Stderr, openStore)
		if err != nil {
			log.Fatal(err)
		}
		if !handled {
			log.Fatal("comando desconocido. Consulta pavarotti ayuda")
		}
		return
	} else if len(args) > 1 {
		log.Fatal("coloca las opciones de servir antes del comando")
	}
	transport, err := mesa.PrepareSharedTransport(*shared, *webBind, *public, *certificate, *certificateKey, *uiPort, *publishPort, *postgres != "", *upstream != "")
	if err != nil {
		log.Fatal(err)
	}
	store, err := openStore()
	if err != nil {
		log.Fatal(err)
	}
	err = run(store, *upstream, *uiPort, *proxyPort, *publishPort, !*noBrowser, !*noWorker, transport)
	if err := errors.Join(err, store.Close()); err != nil {
		log.Fatal(err)
	}
}

func databaseURL(dsn, password string) (string, error) {
	if password == "" {
		return dsn, nil
	}
	parsed, err := url.Parse(dsn)
	if err != nil || parsed.User == nil || parsed.User.Username() == "" ||
		(parsed.Scheme != "postgresql" && parsed.Scheme != "postgres") {
		return "", errors.New("la conexión con contraseña de entorno requiere una URL PostgreSQL con usuario")
	}
	parsed.User = url.UserPassword(parsed.User.Username(), password)
	return parsed.String(), nil
}

func run(store *caso.Store, upstream string, uiPort, proxyPort, publishPort int, browser, worker bool, shared *mesa.SharedTransport) error {
	var target *url.URL
	if upstream != "" {
		var err error
		target, err = trafico.Target(upstream)
		if err != nil {
			return err
		}
	}
	bind := "127.0.0.1"
	if publishPort != 0 {
		if publishPort < 1 || publishPort > 65535 || uiPort == 0 {
			return errors.New("la publicación local requiere puertos válidos y un puerto de aplicación fijo")
		}
		bind = "0.0.0.0"
	}
	if shared != nil {
		bind = shared.Address
	}
	app, err := listen(bind, uiPort)
	if err != nil {
		return err
	}
	defer app.Close()
	appAddress := app.Addr().String()
	if publishPort != 0 {
		appAddress = net.JoinHostPort("127.0.0.1", strconv.Itoa(publishPort))
	}
	settings := mesa.Settings{Version: version, AnalysisQueue: store.HasAnalysisQueue()}
	scheme := "http://"
	if shared != nil {
		appAddress, scheme = shared.Host, "https://"
		settings.Shared = true
	}
	servers := make(map[net.Listener]*http.Server)
	if target != nil {
		proxy, err := listen("127.0.0.1", proxyPort)
		if err != nil {
			return err
		}
		defer proxy.Close()
		proxyAddress := proxy.Addr().String()
		if target.Host == proxyAddress || target.Host == appAddress {
			return errors.New("el destino coincide con un puerto local de PAVAROTTI")
		}
		settings.Proxy, settings.Target = "http://"+proxyAddress, caso.Origin(target.String())
		servers[proxy] = newServer(trafico.Reverse(target, proxyAddress, store))
	}
	servers[app] = newServer(mesa.Handler(appAddress, settings, store, resources))
	if shared != nil {
		servers[app].TLSConfig = shared.TLS
		servers[app].ReadTimeout = 2 * time.Minute
		servers[app].WriteTimeout = 2 * time.Minute
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if worker && settings.AnalysisQueue {
		workerDone := make(chan struct{})
		go func() {
			defer close(workerDone)
			if err := analisis.RunQueue(ctx, store); err != nil {
				log.Printf("Ejecutor de análisis: %v", err)
			}
		}()
		defer func() {
			stop()
			<-workerDone
		}()
	}
	completed := make(chan error, len(servers))
	for listener, server := range servers {
		go func() {
			if server.TLSConfig != nil {
				completed <- server.ServeTLS(listener, "", "")
				return
			}
			completed <- server.Serve(listener)
		}()
	}
	localURL := scheme + appAddress
	fmt.Println("PAVAROTTI", localURL)
	if settings.Proxy != "" {
		fmt.Println("Proxy", settings.Proxy, "→", settings.Target)
	}
	if browser {
		open(localURL)
	}
	select {
	case <-ctx.Done():
		timeout, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		for _, server := range servers {
			_ = server.Shutdown(timeout)
		}
		return nil
	case err := <-completed:
		return err
	}
}

func listen(bind string, port int) (net.Listener, error) {
	return net.Listen("tcp4", net.JoinHostPort(bind, strconv.Itoa(port)))
}

func newServer(handler http.Handler) *http.Server {
	return &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 45 * time.Second}
}

func open(address string) {
	command := exec.Command("xdg-open", address)
	if runtime.GOOS == "windows" {
		command = exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", address)
	}
	go func() { _ = command.Run() }()
}

func databasePassword() (string, error) {
	value, path := os.Getenv("PAVAROTTI_DB_PASSWORD"), os.Getenv("PAVAROTTI_DB_PASSWORD_FILE")
	if path == "" {
		return value, nil
	}
	if value != "" || path == "-" {
		return "", errors.New("configura la contraseña de PostgreSQL mediante una variable o un archivo de secretos")
	}
	return config.ReadSecret(path, nil, 4096)
}
