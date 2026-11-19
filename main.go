package main

import (
	"context"
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

	"pavarotti/internal/caso"
	"pavarotti/internal/trafico"
)

const version = "0.2.0"

func main() {
	directory := flag.String("datos", "", "carpeta del expediente local")
	upstream := flag.String("destino", "", "origen HTTP(S) del proxy inverso")
	proxyPort := flag.Int("puerto-proxy", 0, "puerto local del proxy")
	uiPort := flag.Int("puerto-app", 0, "puerto local de la interfaz")
	noBrowser := flag.Bool("sin-navegador", false, "muestra la URL local en la terminal")
	showVersion := flag.Bool("version", false, "muestra la versión")
	flag.Parse()
	if *showVersion {
		fmt.Println("PAVAROTTI " + version)
		return
	}
	if *directory == "" {
		config, err := os.UserConfigDir()
		if err != nil {
			log.Fatal(err)
		}
		*directory = filepath.Join(config, "PAVAROTTI", "expediente")
	}
	if err := run(*directory, *upstream, *uiPort, *proxyPort, !*noBrowser); err != nil {
		log.Fatal(err)
	}
}

func run(directory, upstream string, uiPort, proxyPort int, browser bool) error {
	var target *url.URL
	if upstream != "" {
		var err error
		target, err = trafico.Target(upstream)
		if err != nil {
			return err
		}
	}
	store, err := caso.Open(directory)
	if err != nil {
		return err
	}
	app, err := listen(uiPort)
	if err != nil {
		return err
	}
	defer app.Close()
	appAddress := app.Addr().String()
	config := settings{Version: version}
	servers := make(map[net.Listener]*http.Server)
	if target != nil {
		proxy, err := listen(proxyPort)
		if err != nil {
			return err
		}
		defer proxy.Close()
		proxyAddress := proxy.Addr().String()
		if target.Host == proxyAddress || target.Host == appAddress {
			return errors.New("el destino coincide con un puerto local de PAVAROTTI")
		}
		config.Proxy, config.Target = "http://"+proxyAddress, caso.Origin(target.String())
		servers[proxy] = newServer(trafico.Reverse(target, proxyAddress, store))
	}
	servers[app] = newServer(dashboard(appAddress, config, store))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	completed := make(chan error, len(servers))
	for listener, server := range servers {
		go func() { completed <- server.Serve(listener) }()
	}
	localURL := "http://" + appAddress
	fmt.Println("PAVAROTTI", localURL)
	if config.Proxy != "" {
		fmt.Println("Proxy", config.Proxy, "→", config.Target)
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

func listen(port int) (net.Listener, error) {
	return net.Listen("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
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
