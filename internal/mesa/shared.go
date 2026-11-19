package mesa

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"sync"
	"time"

	"pavarotti/internal/caso"
)

type sharedAccountKey struct{}

type loginWindow struct {
	until time.Time
	count int
}

type loginLimiter struct {
	mu      sync.Mutex
	windows map[string]loginWindow
	slots   chan struct{}
}

func (limit *loginLimiter) admit(address string, now time.Time) bool {
	ip, _, err := net.SplitHostPort(address)
	if err != nil {
		ip = address
	}
	limit.mu.Lock()
	defer limit.mu.Unlock()
	window := limit.windows[ip]
	if !now.Before(window.until) {
		if len(limit.windows) >= 1024 {
			for key, old := range limit.windows {
				if !now.Before(old.until) {
					delete(limit.windows, key)
				}
			}
			if len(limit.windows) >= 1024 {
				return false
			}
		}
		window = loginWindow{until: now.Add(time.Minute)}
	}
	if window.count >= 8 {
		return false
	}
	select {
	case limit.slots <- struct{}{}:
		window.count++
		limit.windows[ip] = window
		return true
	default:
		return false
	}
}

func sharedDashboard(mux *http.ServeMux, store *caso.Store, origin string, resources fs.FS) http.Handler {
	cookieName := "__Host-pavarotti-" + caso.Hash([]byte(origin + "\n" + store.SharedCase()))[:16]
	limiter := loginLimiter{windows: make(map[string]loginWindow), slots: make(chan struct{}, 4)}
	setCookie := func(w http.ResponseWriter, value string, expires time.Time, maxAge int) {
		http.SetCookie(w, &http.Cookie{Name: cookieName, Value: value, Expires: expires, MaxAge: maxAge,
			Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	}
	token := func(r *http.Request) string {
		cookie, err := r.Cookie(cookieName)
		if err != nil {
			return ""
		}
		return cookie.Value
	}
	mux.HandleFunc("GET /ingresar", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, resources, "ui/ingresar.html")
	})
	mux.HandleFunc("GET /acceso.js", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, resources, "ui/acceso.js")
	})
	mux.HandleFunc("POST /api/acceso/ingresar", func(w http.ResponseWriter, r *http.Request) {
		if !limiter.admit(r.RemoteAddr, time.Now()) {
			w.Header().Set("Retry-After", "60")
			http.Error(w, "Demasiados intentos. Espera un minuto y vuelve a intentarlo.", http.StatusTooManyRequests)
			return
		}
		defer func() { <-limiter.slots }()
		var credentials struct {
			Name     string `json:"name"`
			Password string `json:"password"`
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if decoder.Decode(&credentials) != nil || decoder.Decode(new(any)) != io.EOF {
			http.Error(w, "Solicitud de acceso inválida", http.StatusBadRequest)
			return
		}
		value, expires, err := store.OpenSharedSession(r.Context(), credentials.Name, credentials.Password)
		if errors.Is(err, caso.ErrSharedCredentials) {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}
		if err != nil {
			http.Error(w, "No se pudo iniciar sesión", http.StatusServiceUnavailable)
			return
		}
		setCookie(w, value, expires, 0)
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /api/acceso/salir", func(w http.ResponseWriter, r *http.Request) {
		if err := store.CloseSharedSession(r.Context(), token(r)); err != nil {
			http.Error(w, "No se pudo cerrar sesión", http.StatusServiceUnavailable)
			return
		}
		setCookie(w, "", time.Unix(0, 0).UTC(), -1)
		w.WriteHeader(http.StatusNoContent)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if sharedPublicRoute(r.Method, r.URL.Path) {
			mux.ServeHTTP(w, r)
			return
		}
		account, err := store.SharedSession(r.Context(), token(r))
		if errors.Is(err, caso.ErrSharedSession) {
			if r.URL.Path == "/" && !dashboardMutation(r.Method) {
				http.Redirect(w, r, "/ingresar", http.StatusSeeOther)
				return
			}
			http.Error(w, "Inicia sesión en este expediente", http.StatusUnauthorized)
			return
		}
		if err != nil {
			http.Error(w, "No se pudo verificar la sesión", http.StatusServiceUnavailable)
			return
		}
		if dashboardMutation(r.Method) && account.Role != caso.SharedAnalyst {
			if _, pattern := mux.Handler(r); pattern != binaryWindowPattern && pattern != binaryReferencePattern && pattern != binaryReferenceComparisonPattern {
				http.Error(w, "Este expediente requiere permisos de analista para guardar cambios", http.StatusForbidden)
				return
			}
		}
		ctx := context.WithValue(r.Context(), sharedAccountKey{}, account)
		mux.ServeHTTP(w, r.WithContext(store.AuditContext(ctx, account)))
	})
}

func sharedPublicRoute(method, path string) bool {
	if method == http.MethodPost {
		return path == "/api/acceso/ingresar" || path == "/api/acceso/salir"
	}
	if method == http.MethodGet || method == http.MethodHead {
		switch path {
		case "/ingresar", "/acceso.js", "/app.css", "/icono.png", "/mascara.svg":
			return true
		}
	}
	return false
}
