package mesa

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

type SharedTransport struct {
	Address string
	Host    string
	TLS     *tls.Config
}

func PrepareSharedTransport(enabled bool, address, origin, certificate, key string, uiPort, publishPort int, postgres, proxy bool) (*SharedTransport, error) {
	if !enabled {
		if address != "" || origin != "" || certificate != "" || key != "" {
			return nil, errors.New("las opciones HTTPS y de escucha requieren -compartido")
		}
		return nil, nil
	}
	if !postgres || uiPort < 1 || uiPort > 65535 || certificate == "" || key == "" {
		return nil, errors.New("el modo compartido requiere PostgreSQL, un puerto de aplicación fijo y un certificado con su clave TLS")
	}
	if publishPort != 0 || proxy {
		return nil, errors.New("usa una instancia local separada para el proxy inverso y publica HTTPS mediante -escuchar y -puerto-app")
	}
	if address == "" {
		address = "127.0.0.1"
	}
	if ip, err := netip.ParseAddr(address); err != nil || !ip.Is4() {
		return nil, errors.New("-escuchar requiere una dirección IPv4")
	}
	publicHost, hostname, err := sharedOrigin(origin)
	if err != nil {
		return nil, err
	}
	pair, err := tls.LoadX509KeyPair(certificate, key)
	if err != nil {
		return nil, fmt.Errorf("cargar certificado TLS: %w", err)
	}
	if pair.Leaf == nil {
		pair.Leaf, err = x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("leer certificado TLS: %w", err)
		}
	}
	if err := pair.Leaf.VerifyHostname(hostname); err != nil {
		return nil, fmt.Errorf("el certificado no corresponde al origen compartido: %w", err)
	}
	return &SharedTransport{Address: address, Host: publicHost,
		TLS: &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}}}, nil
}

func sharedOrigin(origin string) (string, string, error) {
	invalid := errors.New("-origen-publico requiere una URL HTTPS con el host externo y su puerto, cuando corresponda")
	uri, err := url.Parse(origin)
	if err != nil || uri.Scheme != "https" || uri.Host == "" || uri.User != nil || uri.Fragment != "" ||
		uri.ForceQuery || uri.RawQuery != "" || uri.RawPath != "" || (uri.Path != "" && uri.Path != "/") {
		return "", "", invalid
	}
	hostname := strings.ToLower(uri.Hostname())
	if hostname == "" || strings.ContainsAny(hostname, `:[]%\`) || strings.HasSuffix(uri.Host, ":") {
		return "", "", invalid
	}
	if port := uri.Port(); port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return "", "", invalid
		}
		if number != 443 {
			return net.JoinHostPort(hostname, strconv.Itoa(number)), hostname, nil
		}
	}
	return hostname, hostname, nil
}
