package mesa

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"pavarotti/internal/caso"
)

func TestSharedOrigin(t *testing.T) {
	for raw, expected := range map[string]string{
		"https://ESTACION.example:443/": "estacion.example",
		"https://127.0.0.1:8443":        "127.0.0.1:8443",
		"http://localhost":              "",
		"https://localhost:65536":       "",
		"https://localhost/path":        "",
		"https://localhost?":            "",
		"https://name@localhost":        "",
	} {
		host, _, err := sharedOrigin(raw)
		if host != expected || (err != nil) != (expected == "") {
			t.Errorf("origen %q: %q, %v", raw, host, err)
		}
	}
}

func TestSharedDashboard(t *testing.T) {
	dsn := os.Getenv("PAVAROTTI_TEST_POSTGRES")
	if dsn == "" {
		t.Skip("PAVAROTTI_TEST_POSTGRES no configurado")
	}
	var nonce [16]byte
	rand.Read(nonce[:])
	name := "test-web-" + hex.EncodeToString(nonce[:])
	store, err := caso.OpenPostgres(t.Context(), dsn, name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		defer store.Close()
		db, err := sql.Open("pgx", dsn)
		if err != nil {
			t.Error(err)
			return
		}
		defer db.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		for _, statement := range []string{
			"DELETE FROM pavarotti_audit_events WHERE expediente = $1",
			"DELETE FROM pavarotti_audit_heads WHERE expediente = $1",
			"DELETE FROM pavarotti_case_members WHERE expediente = $1",
			"DELETE FROM pavarotti_note_revisions WHERE expediente = $1",
			"DELETE FROM pavarotti_evidence_batches WHERE expediente = $1",
		} {
			if _, err := db.ExecContext(ctx, statement, name); err != nil {
				t.Error(err)
			}
		}
	})
	const password = "contraseña sintética de prueba web"
	for _, role := range []string{caso.SharedReader, caso.SharedAnalyst} {
		if _, err := store.SaveSharedAccount(t.Context(), role, role, password); err != nil {
			t.Fatal(err)
		}
	}
	const host = "127.0.0.1:8443"
	const origin = "https://" + host
	handler := Handler(host, Settings{Version: "version-de-prueba", Shared: true}, store, testResources)
	call := func(method, target, requestOrigin, body string, cookie *http.Cookie, status int) *httptest.ResponseRecorder {
		t.Helper()
		if strings.HasPrefix(target, "/") {
			target = origin + target
		}
		request := httptest.NewRequest(method, target, strings.NewReader(body))
		if requestOrigin != "" {
			request.Header.Set("Origin", requestOrigin)
		}
		if cookie != nil {
			request.AddCookie(cookie)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != status {
			t.Fatalf("%s %s: estado %d, esperado %d, respuesta %s", method, target, response.Code, status, response.Body)
		}
		return response
	}
	redirect := call("GET", "/", "", "", nil, 303)
	if redirect.Header().Get("Location") != "/ingresar" {
		t.Fatal("destino de acceso incorrecto")
	}
	call("GET", "/ingresar", "", "", nil, 200)
	call("GET", "/api/app", "", "", nil, 401)
	call("GET", "/api/exportar/stix", "", "", nil, 401)
	call("GET", "/api/actividad", "", "", nil, 401)
	call("GET", "/api/registro/"+strings.Repeat("a", 64)+"-1/cita-binaria?revision=1&tipo=cadena&indice=0", "", "", nil, 401)
	call("GET", "http://"+host+"/ingresar", "", "", nil, 403)
	call("POST", "/api/acceso/ingresar", "https://otro.invalid", "{}", nil, 403)
	call("POST", "/api/acceso/ingresar", "", "{}", nil, 403)
	call("POST", "/api/acceso/ingresar", origin, `{"name":"lector","password":"incorrecta"}`, nil, 401)
	login := func(role string) *http.Cookie {
		t.Helper()
		body, err := json.Marshal(map[string]string{"name": role, "password": password})
		if err != nil {
			t.Fatal(err)
		}
		response := call("POST", "/api/acceso/ingresar", origin, string(body), nil, 204)
		cookies := response.Result().Cookies()
		if len(cookies) != 1 {
			t.Fatal("el acceso requiere una cookie")
		}
		cookie := cookies[0]
		if !strings.HasPrefix(cookie.Name, "__Host-pavarotti-") || !cookie.Secure || !cookie.HttpOnly ||
			cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" || cookie.Domain != "" || time.Until(cookie.Expires) < 7*time.Hour {
			t.Fatal("atributos de la cookie incorrectos")
		}
		return cookie
	}
	reader := login(caso.SharedReader)
	state := call("GET", "/api/app", "", "", reader, 200)
	var config Settings
	if err := json.Unmarshal(state.Body.Bytes(), &config); err != nil || config.Case != name ||
		config.Account == nil || config.Account.Role != caso.SharedReader {
		t.Fatalf("perfil del lector: %+v, %v", config, err)
	}
	call("GET", "/credits.json", "", "", reader, 200)
	const note = `{"title":"Fuente aprobada","source":"https://evidence.invalid","details":"Informe del analista"}`
	call("POST", "/api/nota", origin, note, reader, 403)
	analyst := login(caso.SharedAnalyst)
	call("POST", "/api/nota", origin, note, analyst, 200)
	listing := call("GET", "/api/registro/pagina", "", "", reader, 200)
	if !strings.Contains(listing.Body.String(), "Fuente aprobada") {
		t.Fatal("la cuenta lectora no recibió la nota")
	}
	var records caso.Page
	if err := json.Unmarshal(listing.Body.Bytes(), &records); err != nil || len(records.Rows) != 1 {
		t.Fatalf("registros: %+v, %v", records, err)
	}
	const edit = `{"title":"Fuente revisada","details":"Actualización privada","revision":1}`
	call("PATCH", "/api/nota/"+records.Rows[0].ID, origin, edit, analyst, 200)
	call("PATCH", "/api/nota/"+records.Rows[0].ID, origin, edit, analyst, 409)
	call("GET", "/api/actividad?limite=0", "", "", reader, 400)
	activity := call("GET", "/api/actividad?limite=1", "", "", reader, 200)
	var history caso.AuditPage
	if err := json.Unmarshal(activity.Body.Bytes(), &history); err != nil || len(history.Events) != 1 || history.Next != 2 {
		t.Fatalf("página de actividad: %+v, %v", history, err)
	}
	updated := history.Events[0]
	if updated.Action != caso.AuditEdit || updated.Actor != caso.SharedAnalyst || updated.Source != "sesion" ||
		updated.Target != records.Rows[0].ID || updated.Details.Revision != 2 || strings.Contains(activity.Body.String(), "Actualización privada") {
		t.Fatalf("evento web: %+v", updated)
	}
	earlier := call("GET", "/api/actividad?antes=2&limite=1", "", "", reader, 200)
	if err := json.Unmarshal(earlier.Body.Bytes(), &history); err != nil || len(history.Events) != 1 || history.Events[0].Action != caso.AuditNote {
		t.Fatalf("actividad anterior: %+v, %v", history, err)
	}
	call("POST", "/api/acceso/salir", origin, "", analyst, 204)
	call("GET", "/api/app", "", "", analyst, 401)
}
