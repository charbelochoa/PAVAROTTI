package trafico

import (
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"

	"pavarotti/internal/caso"
)

type startKey struct{}

func Target(raw string) (*url.URL, error) {
	target, err := url.Parse(raw)
	if err != nil || caso.Origin(raw) == "" || target.User != nil ||
		(target.Path != "" && target.Path != "/") || target.RawQuery != "" || target.ForceQuery || target.Fragment != "" {
		return nil, errors.New("el destino debe ser un origen HTTP(S), por ejemplo http://127.0.0.1:8080")
	}
	return target, nil
}

func Reverse(target *url.URL, listener string, store *caso.Store) http.Handler {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.ResponseHeaderTimeout = 25 * time.Second
	origin := caso.Origin(target.String())
	record := func(req *http.Request, status int, headers http.Header) {
		start, _ := req.Context().Value(startKey{}).(time.Time)
		entry := Observe(origin, req.Method, status, time.Since(start), headers)
		if err := store.Save([]caso.Record{entry}); err != nil {
			log.Printf("Registro de tráfico: %v", err)
		}
	}
	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(req *httputil.ProxyRequest) {
			req.SetURL(target)
		},
		ModifyResponse: func(resp *http.Response) error {
			if location, err := url.Parse(resp.Header.Get("Location")); err == nil && location.IsAbs() &&
				location.Host == target.Host && location.Scheme == target.Scheme {
				location.Host, location.Scheme = listener, "http"
				resp.Header.Set("Location", location.String())
			}
			record(resp.Request, resp.StatusCode, resp.Header)
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, req *http.Request, _ error) {
			record(req, http.StatusBadGateway, nil)
			http.Error(w, "El destino no respondió", http.StatusBadGateway)
		},
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host != listener || r.URL.IsAbs() || r.Method == http.MethodConnect || r.Method == http.MethodTrace ||
			r.Header.Get("Upgrade") != "" || r.Header.Get("Sec-Fetch-Site") == "cross-site" {
			http.Error(w, "Solicitud fuera del alcance del proxy", http.StatusForbidden)
			return
		}
		if site := r.Header.Get("Origin"); site != "" && site != "http://"+listener {
			http.Error(w, "Origen fuera del alcance del proxy", http.StatusForbidden)
			return
		}
		proxy.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), startKey{}, time.Now())))
	})
}
