package revision

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGoModuleInventoryKeepsDeclaredVersionsAndReplacementLocations(t *testing.T) {
	data := []byte("\ufeffmodule example.invalid/workspace\n\ngo 1.25.0\n\nrequire (\n" +
		"  example.invalid/core v1.2.3\n  example.invalid/support v0.8.0 // indirect\n)\n" +
		"replace example.invalid/support => ../private-directory\n" +
		"replace example.invalid/core => example.invalid/fork v1.3.0\n")
	inventory, err := Inventory("gomod", data)
	if err != nil || inventory.Project != "example.invalid/workspace" || len(inventory.Entries) != 2 {
		t.Fatalf("inventario: %+v, %v", inventory, err)
	}
	first, second := inventory.Entries[0], inventory.Entries[1]
	if first.Line != 6 || first.Scope != "directa" || first.Replacement == nil || first.Replacement.Line != 10 ||
		first.Replacement.Name != "example.invalid/fork" || first.Replacement.Version != "v1.3.0" {
		t.Fatalf("dependencia directa: %+v", first)
	}
	if second.Line != 7 || second.Scope != "indirecta" || second.Replacement == nil || !second.Replacement.Local || second.Replacement.Line != 9 {
		t.Fatalf("dependencia indirecta: %+v", second)
	}
	data, err = json.Marshal(inventory)
	if err != nil || strings.Contains(string(data), "private-directory") {
		t.Fatalf("se conservó la ruta local: %s, %v", data, err)
	}
}

func TestNPMLockKeepsNestedPackageLocations(t *testing.T) {
	const input = `{"name":"fixture","lockfileVersion":3,"packages":{
		"":{"dependencies":{"alias":"npm:@scope/real@1.2.3"},"devDependencies":{"tool":"2.0.0"}},
		"node_modules/alias":{"name":"@scope/real","version":"1.2.3","resolved":"https://private.invalid/secret-token","integrity":"sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="},
		"node_modules/alias/node_modules/@scope/child":{"version":"1.0.0"},
		"node_modules/tool":{"version":"2.0.0"},
		"node_modules/workspace":{"link":true,"resolved":"../private"},
		"../outside":{"name":"outside","version":"2.0.0"}
	}}`
	inventory, err := Inventory("npmlock", []byte(input))
	if err != nil || inventory.Project != "fixture" || len(inventory.Entries) != 4 || inventory.Skipped != 1 {
		t.Fatalf("inventario: %+v, %v", inventory, err)
	}
	alias, child, tool, link := inventory.Entries[0], inventory.Entries[1], inventory.Entries[2], inventory.Entries[3]
	if alias.Name != "@scope/real" || alias.InstalledAs != "alias" || alias.Scope != "directa" || alias.Integrity == "" ||
		child.Location != "#/packages/node_modules~1alias~1node_modules~1@scope~1child" || child.Scope != "transitiva" ||
		tool.Scope != "desarrollo" || link.Replacement == nil || !link.Replacement.Local {
		t.Fatal(inventory.Entries)
	}
	data, err := json.Marshal(inventory)
	if err != nil || strings.Contains(string(data), "private") {
		t.Fatalf("se conservó información ajena al inventario: %s, %v", data, err)
	}
	if _, err := Inventory("npmlock", []byte(`{"lockfileVersion":1,"dependencies":{}}`)); err == nil {
		t.Fatal("se aceptó un formato ajeno al esquema de inventario")
	}
}
