package config

import (
	"errors"
	"io"
	"os"
	"strings"
)

func ReadSecret(path string, stdin io.Reader, limit int) (string, error) {
	reader := stdin
	if path != "-" {
		file, err := os.Open(path)
		if err != nil {
			return "", err
		}
		defer file.Close()
		reader = file
	}
	data, err := io.ReadAll(io.LimitReader(reader, int64(limit)+3))
	if err != nil {
		return "", err
	}
	value := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	if value == "" || len(value) > limit {
		return "", errors.New("el secreto está vacío o supera el tamaño admitido")
	}
	return value, nil
}
