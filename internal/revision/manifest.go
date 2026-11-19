package revision

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
	"pavarotti/internal/caso"
)

const (
	MaxManifest     = 4 << 20
	MaxDependencies = 5000
)

var npmName = regexp.MustCompile(`^(?:@[A-Za-z0-9._-]+/)?[A-Za-z0-9._-]+$`)
var jsonPointer = strings.NewReplacer("~", "~0", "/", "~1")

func Inventory(kind string, data []byte) (caso.DependencyInventory, error) {
	if len(data) > MaxManifest {
		return caso.DependencyInventory{}, errors.New("el manifiesto admite hasta 4 MiB")
	}
	data = bytes.TrimPrefix(data, []byte{0xef, 0xbb, 0xbf})
	if !utf8.Valid(data) {
		return caso.DependencyInventory{}, errors.New("el manifiesto debe usar UTF-8")
	}
	switch kind {
	case "gomod":
		return readGoMod(data)
	case "npmlock":
		return readNPMLock(data)
	}
	return caso.DependencyInventory{}, errors.New("manifiesto desconocido")
}

func readGoMod(data []byte) (caso.DependencyInventory, error) {
	parsed, err := modfile.Parse("go.mod", data, nil)
	if err != nil {
		return caso.DependencyInventory{}, fmt.Errorf("go.mod inválido: %w", err)
	}
	if parsed.Module == nil || !validGoPath(parsed.Module.Mod.Path) {
		return caso.DependencyInventory{}, errors.New("falta un módulo válido en go.mod")
	}
	if len(parsed.Require) > MaxDependencies {
		return caso.DependencyInventory{}, errors.New("el manifiesto supera 5000 dependencias")
	}
	project := caso.DependencyInventory{Ecosystem: "go", Manifest: "go.mod", Project: parsed.Module.Mod.Path,
		Entries: make([]caso.Dependency, 0, len(parsed.Require))}
	replacements := make(map[module.Version]caso.Replacement, len(parsed.Replace))
	for _, item := range parsed.Replace {
		row := caso.Replacement{Local: item.New.Version == "", Line: item.Syntax.Start.Line}
		if !row.Local {
			if !validGoPath(item.New.Path) || !manifestText(item.New.Version, 128) {
				return caso.DependencyInventory{}, errors.New("reemplazo de módulo fuera de rango")
			}
			row.Name, row.Version = item.New.Path, item.New.Version
		}
		replacements[item.Old] = row
	}
	for _, item := range parsed.Require {
		if !validGoPath(item.Mod.Path) || !manifestText(item.Mod.Version, 128) {
			return caso.DependencyInventory{}, errors.New("dependencia de Go fuera de rango")
		}
		row := caso.Dependency{Name: item.Mod.Path, Version: item.Mod.Version, Line: item.Syntax.Start.Line, Scope: "directa"}
		if item.Indirect {
			row.Scope = "indirecta"
		}
		replacement, found := replacements[item.Mod]
		if !found {
			replacement, found = replacements[module.Version{Path: item.Mod.Path}]
		}
		if found {
			row.Replacement = &replacement
		}
		project.Entries = append(project.Entries, row)
	}
	return project, nil
}

func validGoPath(value string) bool {
	return manifestText(value, 255) && module.CheckImportPath(value) == nil
}

type lockPackage struct {
	Name      string            `json:"name"`
	Version   string            `json:"version"`
	Integrity string            `json:"integrity"`
	Link      bool              `json:"link"`
	Requires  map[string]string `json:"dependencies"`
	Dev       map[string]string `json:"devDependencies"`
	Optional  map[string]string `json:"optionalDependencies"`
	Peers     map[string]string `json:"peerDependencies"`
}

func readNPMLock(data []byte) (caso.DependencyInventory, error) {
	var lock struct {
		Name     string                 `json:"name"`
		Version  int                    `json:"lockfileVersion"`
		Packages map[string]lockPackage `json:"packages"`
	}
	if err := json.Unmarshal(data, &lock); err != nil {
		return caso.DependencyInventory{}, fmt.Errorf("package-lock.json inválido: %w", err)
	}
	if (lock.Version != 2 && lock.Version != 3) || lock.Packages == nil {
		return caso.DependencyInventory{}, errors.New("se requiere package-lock.json v2 o v3 con el mapa packages")
	}
	if len(lock.Packages) > MaxDependencies+1 {
		return caso.DependencyInventory{}, errors.New("el manifiesto supera 5000 dependencias")
	}
	root := lock.Packages[""]
	if root.Name != "" {
		lock.Name = root.Name
	}
	project := caso.DependencyInventory{Ecosystem: "npm", Manifest: "package-lock.json", Entries: make([]caso.Dependency, 0, len(lock.Packages))}
	if validNPMName(lock.Name) {
		project.Project = lock.Name
	}
	direct := make(map[string]string)
	for _, group := range []struct {
		scope string
		names map[string]string
	}{{"par", root.Peers}, {"desarrollo", root.Dev}, {"directa", root.Requires}, {"opcional", root.Optional}} {
		for name := range group.names {
			direct[name] = group.scope
		}
	}
	for _, location := range slices.Sorted(maps.Keys(lock.Packages)) {
		if location == "" {
			continue
		}
		node := lock.Packages[location]
		name, installed := npmPackageName(location, node.Name)
		if !validNPMName(name) || !validLockPath(location) || (!node.Link && !validNPMVersion(node.Version)) {
			project.Skipped++
			continue
		}
		row := caso.Dependency{Name: name, Scope: "transitiva", Location: "#/packages/" + jsonPointer.Replace(location)}
		if installed != "" && installed != name {
			row.InstalledAs = installed
		}
		if location == "node_modules/"+installed && direct[installed] != "" {
			row.Scope = direct[installed]
		}
		switch {
		case node.Link:
			row.Replacement = &caso.Replacement{Local: true}
		case installed == "":
			row.Scope = "workspace"
			row.Version = node.Version
		default:
			row.Version, row.Integrity = node.Version, npmIntegrity(node.Integrity)
		}
		project.Entries = append(project.Entries, row)
	}
	if len(project.Entries) > MaxDependencies {
		return caso.DependencyInventory{}, errors.New("el manifiesto supera 5000 dependencias")
	}
	return project, nil
}

func npmPackageName(path, declared string) (string, string) {
	path = "/" + path
	start := strings.LastIndex(path, "/node_modules/")
	if start < 0 {
		return declared, ""
	}
	installed := path[start+len("/node_modules/"):]
	if !validNPMName(installed) {
		return "", ""
	}
	if declared != "" {
		return declared, installed
	}
	return installed, installed
}

func validNPMName(value string) bool { return len(value) <= 214 && npmName.MatchString(value) }

func validLockPath(value string) bool {
	return manifestText(value, 1024) && path.Clean(value) == value && !path.IsAbs(value) &&
		value != "." && value != ".." && !strings.HasPrefix(value, "../") && !strings.ContainsAny(value, `:\`)
}

func validNPMVersion(value string) bool {
	return len(value) <= 128 && (semver.IsValid("v"+value) || semver.IsValid(value))
}

func manifestText(value string, maximum int) bool {
	return len(value) > 0 && len(value) <= maximum && !strings.ContainsFunc(value, func(char rune) bool {
		return unicode.IsControl(char) || unicode.In(char, unicode.Cf)
	})
}

func npmIntegrity(value string) string {
	if len(value) > 512 {
		return ""
	}
	for _, token := range strings.Fields(value) {
		algorithm, digest, _ := strings.Cut(token, "-")
		length := map[string]int{"sha1": 20, "sha256": 32, "sha384": 48, "sha512": 64}[algorithm]
		if decoded, err := base64.StdEncoding.Strict().DecodeString(digest); length > 0 && err == nil && len(decoded) == length {
			return token
		}
	}
	return ""
}
