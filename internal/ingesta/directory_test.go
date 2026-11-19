package ingesta

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pavarotti/internal/caso"
)

func TestDirectoryReviewPreservesFileIdentityAndReportsRejections(t *testing.T) {
	root := t.TempDir()
	for name, data := range map[string]string{
		"a/app.go": "package fixture\n", "b/app.go": "package fixture\n", "bad.go": "package ",
		"go.mod": "module fixture.invalid/project\n", "vendor/ignored.go": "package automatic\n",
		"node_modules/ignored.go": "package automatic\n", ".git/ignored.go": "package automatic\n",
	} {
		path := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	_ = os.Symlink(filepath.Join(root, "a", "app.go"), filepath.Join(root, "link.go"))
	store, err := caso.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	review, err := LoadDirectory(t.Context(), root)
	if err != nil {
		t.Fatal(err)
	}
	result, err := review.Save(t.Context(), store)
	if err != nil || result.Imported != 3 || result.Rejected != 1 || len(result.Files) != 4 ||
		result.Files[0].Path != "a/app.go" || result.Files[2].Status != "rechazado" {
		t.Fatalf("resultado: %+v, %v", result, err)
	}
	result, err = review.Save(t.Context(), store)
	if err != nil || result.Duplicates != 3 || result.Imported != 0 {
		t.Fatalf("repetición: %+v, %v", result, err)
	}
	rows, err := store.Records()
	if err != nil || len(rows) != 3 {
		t.Fatalf("persistencia: %v, %v", rows, err)
	}
	byPath := make(map[string]caso.Record)
	for _, row := range rows {
		byPath[row.SourceID] = row
	}
	a, b := byPath["a/app.go"], byPath["b/app.go"]
	if !a.Directory || !b.Directory || a.ID == b.ID || a.SHA256 != b.SHA256 {
		t.Fatalf("identidades: %s %s", a.ID, b.ID)
	}
}

func TestDirectoryPathsRejectAbsoluteAndTraversal(t *testing.T) {
	var review DirectoryReview
	for _, name := range []string{"../app.go", "C:/app.go", `/etc/app.go`, `a\app.go`, "a/../app.go", "vendor/app.go"} {
		if err := review.Add(name, strings.NewReader("package fixture")); !errors.Is(err, ErrDirectoryPath) {
			t.Fatalf("%q: %v", name, err)
		}
	}
}
