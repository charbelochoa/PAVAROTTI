package terminal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"pavarotti/internal/caso"
	"pavarotti/internal/config"
)

func terminalSharedAccounts(args []string, stdout, stderr io.Writer, open openExpediente) error {
	usage := "usuarios [listar|guardar|rol|revocar]"
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		_, err := fmt.Fprintln(stdout, "Uso: pavarotti "+usage)
		return err
	}
	command := args[0]
	flags := terminalFlags("usuarios "+command, usage, stderr)
	var name, role, secret string
	switch command {
	case "guardar":
		flags.StringVar(&secret, "clave-archivo", "", "archivo con la contraseña, o - para leer la entrada estándar")
		fallthrough
	case "rol":
		flags.StringVar(&role, "rol", "", "lector o analista")
		fallthrough
	case "revocar":
		flags.StringVar(&name, "nombre", "", "nombre de la cuenta")
	case "listar":
	default:
		return errors.New("usa pavarotti usuarios --help")
	}
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || (command != "listar" && name == "") ||
		((command == "guardar" || command == "rol") && role == "") || (command == "guardar" && secret == "") {
		return errors.New("usa pavarotti usuarios " + command + " --help")
	}
	store, err := open()
	if err != nil {
		return err
	}
	defer store.Close()
	ctx := context.Background()
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	switch command {
	case "listar":
		accounts, err := store.SharedAccounts(ctx)
		if err != nil {
			return err
		}
		return encoder.Encode(accounts)
	case "guardar":
		password, err := config.ReadSecret(secret, os.Stdin, caso.MaxPasswordBytes)
		if err != nil {
			return err
		}
		account, err := store.SaveSharedAccount(ctx, name, role, password)
		if err != nil {
			return err
		}
		return encoder.Encode(account)
	case "rol":
		account, err := store.ChangeSharedRole(ctx, name, role)
		if err != nil {
			return err
		}
		return encoder.Encode(account)
	default:
		if err := store.RevokeSharedAccount(ctx, name); err != nil {
			return err
		}
		_, err := fmt.Fprintln(stdout, "Acceso revocado")
		return err
	}
}
