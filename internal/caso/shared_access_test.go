package caso

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"
)

func TestOpenPostgresDuringSharedSessionWrite(t *testing.T) {
	active := openAuditTest(t)
	ctx := t.Context()
	tx, err := active.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `LOCK TABLE pavarotti_case_sessions IN ROW EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	available, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	other, err := OpenPostgres(available, os.Getenv("PAVAROTTI_TEST_POSTGRES"), active.expediente+"-otro")
	if err != nil {
		t.Fatalf("abrir otro expediente durante una escritura de sesión: %v", err)
	}
	defer other.Close()
	if accounts, err := other.SharedAccounts(available); err != nil || len(accounts) != 0 {
		t.Fatalf("consultar las cuentas del otro expediente: %+v, %v", accounts, err)
	}
}

func TestSharedAccessKeepsSessionsInsideTheCase(t *testing.T) {
	dsn := os.Getenv("PAVAROTTI_TEST_POSTGRES")
	if dsn == "" {
		t.Skip("PAVAROTTI_TEST_POSTGRES no configurado")
	}
	ctx := t.Context()
	base := "test-acceso-" + hex.EncodeToString(randBytes(t))
	start := func(name string) *Store {
		t.Helper()
		store, err := OpenPostgres(ctx, dsn, name)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			defer store.Close()
			if _, err := store.db.ExecContext(context.Background(), "DELETE FROM pavarotti_case_members WHERE expediente = $1", name); err != nil {
				t.Error(err)
			}
		})
		return store
	}
	first, second := start(base+"-a"), start(base+"-b")
	const password = "Contraseña sintética para esta prueba"
	for _, provision := range []struct {
		store *Store
		role  string
	}{{first, SharedAnalyst}, {second, SharedReader}} {
		account, err := provision.store.SaveSharedAccount(ctx, " Revisor ", provision.role, password)
		if err != nil || account.Name != "revisor" || account.Role != provision.role {
			t.Fatalf("cuenta: %+v, %v", account, err)
		}
	}
	if _, _, err := first.OpenSharedSession(ctx, "revisor", "Contraseña sintética equivocada"); !errors.Is(err, ErrSharedCredentials) {
		t.Fatalf("contraseña inválida: %v", err)
	}
	token, expires, err := first.OpenSharedSession(ctx, "REVISOR", password)
	if err != nil || token == "" || time.Until(expires) < 7*time.Hour {
		t.Fatalf("sesión: %v, %v", expires, err)
	}
	if account, err := first.SharedSession(ctx, token); err != nil || account.Role != SharedAnalyst {
		t.Fatalf("identidad: %+v, %v", account, err)
	}
	if _, err := second.SharedSession(ctx, token); !errors.Is(err, ErrSharedSession) {
		t.Fatalf("sesión cruzada: %v", err)
	}
	var digest string
	if err := first.db.QueryRowContext(ctx, `SELECT token_hash FROM pavarotti_case_sessions WHERE expediente = $1`, base+"-a").Scan(&digest); err != nil || digest == token || digest != Hash([]byte(token)) {
		t.Fatalf("persistencia del token: %v", err)
	}
	if _, err := first.db.ExecContext(ctx, `UPDATE pavarotti_case_sessions SET expires_at = clock_timestamp()
		WHERE expediente = $1 AND token_hash = $2`, base+"-a", digest); err != nil {
		t.Fatal(err)
	}
	if _, err := first.SharedSession(ctx, token); !errors.Is(err, ErrSharedSession) {
		t.Fatalf("vencimiento: %v", err)
	}
	token, _, err = first.OpenSharedSession(ctx, "revisor", password)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := first.ChangeSharedRole(ctx, "revisor", SharedReader); err != nil {
		t.Fatal(err)
	}
	if _, err := first.SharedSession(ctx, token); !errors.Is(err, ErrSharedSession) {
		t.Fatalf("revocación al cambiar permisos: %v", err)
	}
	token, _, err = first.OpenSharedSession(ctx, "revisor", password)
	if err != nil {
		t.Fatal(err)
	}
	if err := first.CloseSharedSession(ctx, token); err != nil {
		t.Fatal(err)
	}
	if _, err := first.SharedSession(ctx, token); !errors.Is(err, ErrSharedSession) {
		t.Fatalf("cierre de sesión: %v", err)
	}
	if err := first.RevokeSharedAccount(ctx, "revisor"); err != nil {
		t.Fatal(err)
	}
	if accounts, err := second.SharedAccounts(ctx); err != nil || len(accounts) != 1 || accounts[0].Role != SharedReader {
		t.Fatalf("cuentas del otro expediente: %+v, %v", accounts, err)
	}
}
